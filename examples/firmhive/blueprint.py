import os
import sys
import json
import time
import argparse
import threading
import subprocess
import uuid
from typing import Dict, List, Any, Optional, Type, Union
from concurrent.futures import ThreadPoolExecutor, as_completed
from agenthive.base import BaseAgent
from agenthive.core.assitants import BaseAssistant, ParallelBaseAssistant
from agenthive.core.builder import build_agent, AgentConfig, AssistantToolConfig

from binhive.binagent import create_binary_analysis_config,\
     DEFAULT_BINARY_ANALYSIS_SYSTEM_PROMPT,DEFAULT_BINARY_VALIDATION_SYSTEM_PROMPT

from firmhive.utils.finder import find_firmware_root
from firmhive.utils.convert2md import load_knowledge_base
from firmhive.tools import FlexibleContext, ExecutableTool, GetContextInfoTool, ShellExecutorTool, Radare2Tool
    #  VulnerabilitySearchTool
from firmhive.knowagent import KnowledgeBaseAgent,QueryFindingsTool,ListUniqueValuesTool,StoreFindingsTool,DEFAULT_KB_SYSTEM_PROMPT
from firmhive.assitants import ParallelDeepFileAnalysisDelegator,ParallelDeepDirectoryAnalysisDelegator,\
                            DeepFileAnalysisAssistant,DeepDirectoryAnalysisAssistant
                            
DEFAULT_VERIFICATION_TASK_TEMPLATE = (
    "您的唯一任务是严格且客观地验证以下安全警报。您的分析必须完全基于的证据。\n\n"
    "**核心原则**:\n"
    "1.  **证据驱动**: 警报中的所有声明必须通过对的证据进行分析来验证。严禁猜测或分析不相关的信息和文件。\n"
    "2.  **逻辑审查**: 不要仅仅确认代码的存在：你必须理解其执行逻辑。仔细检查条件语句、数据净化和其他决定代码路径是否可达的因素。\n"
    "3.  **评估**: 在固件操作的上下文中评估警报，结合所有相关信息，以确定它是否构成真实的、可利用的漏洞。\n\n"
    "**注意**: 警报中的函数名可能来自反编译。仔细搜索；不要因为它们不在符号表或字符串中就轻易得出它们不存在的结论。\n\n"
    "{verification_finding_details}\n"
)
DEFAULT_VERIFICATION_INSTRUCTION_TEMPLATE = (
    "{verification_task}\n"
    "**提供结论**: 在分析结束时，`final_response`必须是一个包含以下字段的JSON对象:\n"
    "    - `accuracy`: (字符串) 对警报描述准确性的评估。必须是'accurate'、'inaccurate'或'partially'。\n"
    "    - `vulnerability`: (布尔值) 确定描述是否足以构成真实漏洞。必须是True或False。前提是攻击者是已连接到设备并拥有有效登录凭据的用户。\n"
    "    - `risk_level`: (字符串) 如果`vulnerability`为`true`，则为漏洞的利用复杂度。必须是'Low'、'Medium'或'High'。\n"
    "    - `reason`: (字符串) 您判断的详细解释，必须支持所有上述结论。对于被确认为真实漏洞的发现，该字段还必须提供可重现的攻击载荷或概念验证(PoC)步骤，清楚地描述如何利用该漏洞。\n"
)
SHARED_RESPONSE_FORMAT_BLOCK = """
每个发现必须包含以下**核心字段**:
- **`description`**: 发现的详细描述，必须包括:
* 问题的具体表现和触发条件。
* 详细的污点传播路径、相关约束和边界检查的详细信息。
* 潜在的攻击向量和利用方法。
- **`link_identifiers`**: 具体的NVRAM或ENV变量名、文件路径、IPC套接字路径和自定义共享函数符号。
- **`location`**: 代码汇点或关键逻辑的精确位置。
- **`code_snippet`**: 返回完整的相关代码片段。
- **`risk_score`**: 风险评分(0.0-10.0)。
- **`confidence`**: 对发现的准确性和可利用性分析的置信度。(0.0-10.0)。
- **`notes`**: 供人类分析师参考。包括:需要进一步验证的假设、相关文件或函数、建议的后续分析方向。
#### 注意
- 严禁编造任何信息；必须基于工具获得的实际证据。如果工具无法获得证据，如实报告并解释信息缺失。严禁做出任何未经证实的猜测。
"""
DEFAULT_WORKER_EXECUTOR_SYSTEM_PROMPT = f"""
您是一个固件文件系统静态分析代理。您的任务是基于当前分析焦点(特定目录)进行探索和分析。请专注于当前焦点，当您认为对其分析完成或无法取得进一步进展时，继续下一个任务或结束任务。
工作方法:
1.  **理解需求**
    *   始终关注具体任务，同时参考用户的整体或初始需求。注意，如果任务与当前分析焦点不匹配，您需要停止分析并及时向用户反馈。不要进行跨目录分析。
    *   仔细理解用户当前想要分析的固件内容和目标。除非您非常确定它们不符合用户要求，否则不要遗漏符合用户要求的目录和文件。如果用户需求不明确，根据固件特征选择最佳分析路径，分解复杂任务，合理调用分析助手。
    *   如果用户需求不明确，根据固件特征选择最佳分析路径，适当分解复杂任务，合理调用分析助手。
2.  **制定分析计划**
    *   根据固件特征选择最佳分析路径。
    *   对于复杂任务，将其分解为多个具有明确子对象和目标的子任务，并合理调用分析助手和工具。当需要深入分析时，调用适当的分析助手:
    *   **探索目录**: 使用子目录分析助手或其并行版本切换到指定目录进行分析。
    *   **分析文件**: 使用文件分析助手或其并行版本分析指定文件。
    *   根据助手反馈合理调整分析计划，以确保计划准确完整。如果助手无法完成任务，重新制定分析计划。如果助手在两次尝试后仍无法完成任务，继续分析下一个任务。
3.  **分析过程中的问题处理**
    *   记录分析过程中遇到的技术困难和独特挑战。
    *   评估问题在实际固件环境中的影响。
    *   谨慎使用某些工具以避免结果过长导致分析失败，例如`strings`工具。
4.  **分析结果提交**
    *   总结所有分析结果并回答与当前任务相对应的问题。
    *   如实报告证据不足或不确定的情况(缺少什么证据，缺少什么信息)。
"""

DEFAULT_TOOL_CLASSES: List[Union[Type[ExecutableTool], ExecutableTool]] = [
    GetContextInfoTool, ShellExecutorTool, Radare2Tool
]
DEFAULT_FILE_SYSTEM_PROMPT = f"""
您是一个专门的文件分析代理。您的任务是深入分析当前指定的文件并提供详细的、有证据支持的分析结果。请专注于当前焦点文件或当前具体任务。当您认为分析完成或无法取得进一步进展时，继续下一个任务或结束任务。
**工作原则:**
-   **基于证据**: 所有分析必须基于从工具获得的实际证据；禁止无根据的推测。
-   **结果验证**: 批判性评估委派子任务(如函数分析)返回的结果，始终验证其真实性和可靠性，以防止虚假结果污染最终结论。
**工作流程:**
1.  **理解任务**: 专注于当前分析文件的具体任务，充分参考用户的整体需求。注意，如果任务与当前分析焦点不匹配，您需要停止分析并及时向用户反馈。不要进行跨目录分析。
2.  **执行分析**: 确保您的分析具有足够的深度。对于复杂任务，将其分解为多个具有明确目标和步骤的子任务，并合理地顺序或并行调用分析助手或工具。选择最合适的工具或助手来获取证据。谨慎使用某些工具以避免结果过长导致分析失败，例如`strings`工具。
3.  **完成和报告**: 完成分析后，使用`finish`操作并严格按照以下格式提交您的最终报告。
**最终响应要求**:
*   回答与当前任务相关的所有问题，您的响应必须有完整的证据。不要遗漏任何有效信息。
*   用具体证据支持所有发现，并如实报告任何证据不足或困难。
{SHARED_RESPONSE_FORMAT_BLOCK}
*   在'action'字段中选择工具或'finish'，并在'action_input'中提供参数或最终响应。
"""

class ExecutorAgent(BaseAgent):
    """系统分析代理(接收外部上下文，依赖项外部注入，包括工具执行环境和对象)"""
    def __init__(
        self,
        tools: Optional[List[Union[Type[ExecutableTool], ExecutableTool]]] = None,
        system_prompt: str = DEFAULT_WORKER_EXECUTOR_SYSTEM_PROMPT,
        output_schema: Optional[Dict[str, Any]] = None,
        max_iterations: int = 50,
        history_strategy = None,
        context: Optional[FlexibleContext] = None,
        messages_filters: List[Dict[str, str]] = None,
        **extra_params: Any
    ):
        self.file_path = context.get("file_path")
        self.file_name = os.path.basename(self.file_path) if self.file_path else None
        self.current_dir = context.get("current_dir")
        tools_to_pass = tools if tools is not None else DEFAULT_TOOL_CLASSES
        self.messages_filters = messages_filters if messages_filters else [{'from': context.get('base_path')+os.path.sep, 'to': ''}] if context and context.get('base_path') else []
        
        super().__init__(
            tools=tools_to_pass, 
            system_prompt=system_prompt, 
            output_schema=output_schema, 
            max_iterations=max_iterations, 
            history_strategy=history_strategy, 
            context=context,
            messages_filters=self.messages_filters,
            **extra_params
        )

class PlannerAgent(BaseAgent):
    """文件分析代理(接收外部上下文，依赖项外部注入，包括工具执行环境和对象)，并在分析后存储结果。"""
    def __init__(
        self,
        tools: Optional[List[Union[Type[ExecutableTool], ExecutableTool]]] = None,
        system_prompt: str = None,
        output_schema: Optional[Dict[str, Any]] = None,
        max_iterations: int = 50,
        history_strategy = None,
        context: Optional[FlexibleContext] = None,
        messages_filters: List[Dict[str, str]] = None,
        **extra_params: Any
    ):
        self.file_path = context.get("file_path") if context else None
        self.file_name = os.path.basename(self.file_path) if self.file_path else None
        self.current_dir = context.get("current_dir")
        tools_to_pass = tools if tools is not None else DEFAULT_TOOL_CLASSES
        self.messages_filters = messages_filters if messages_filters else [{'from': context.get('base_path')+os.path.sep, 'to': ''}] if context and context.get('base_path') else []
        
        super().__init__(
            tools=tools_to_pass, 
            system_prompt=system_prompt, 
            output_schema=output_schema, 
            max_iterations=max_iterations, 
            history_strategy=history_strategy, 
            context=context,
            messages_filters=self.messages_filters,
            **extra_params
        )
        kb_context = self.context.copy()
        self.kb_storage_agent = KnowledgeBaseAgent(context=kb_context)
   
    def run(self, user_input: str = None) -> Any:
        findings = str(super().run(user_input=user_input))
        
        store_prompt = (
            f"新的分析结果如下:\n"
            f"{findings}\n\n"
            f"基于上述分析结果，您当前的任务是确定它们是否存在风险。"
            f"如果存在，您需要存储和组织分析结果。"
            f"用户的核心需求是: {self.context.get('user_input', '未提供')}\n"
        )
        self.kb_storage_agent.run(user_input=store_prompt)
        return findings
    

def create_kb_agent_config(
    max_iterations: int = 30,
) -> AgentConfig:
    kb_agent_cfg = AgentConfig(
        agent_class=KnowledgeBaseAgent,
        tool_configs=[QueryFindingsTool, ListUniqueValuesTool, StoreFindingsTool],
        system_prompt=DEFAULT_KB_SYSTEM_PROMPT,
        max_iterations=max_iterations
    )
    return kb_agent_cfg

def create_file_analysis_config(
    include_kb: bool,
    max_iterations: int = 50,
    main_system_prompt: Optional[str] = None,
    worker_system_prompt: Optional[str] = None,
    verification: bool = False,
) -> AgentConfig:
    """
    创建一个两层的代理配置，用于文件分析。
    L0: PlannerAgent - 负责规划和委派任务。
    L1: ExecutorAgent (worker) / BinaryAnalysisAgent - 负责执行具体任务。
    """
    effective_main_prompt = main_system_prompt or DEFAULT_FILE_SYSTEM_PROMPT
    effective_worker_prompt = worker_system_prompt or DEFAULT_FILE_SYSTEM_PROMPT

    worker_agent_cfg = AgentConfig(
        agent_class=ExecutorAgent,
        tool_configs=DEFAULT_TOOL_CLASSES.copy(),
        system_prompt=effective_worker_prompt,
        max_iterations=max_iterations,
    )

    # 专业二进制分析团队代理配置
    binary_analysis_cfg = create_binary_analysis_config(
        max_iterations=max_iterations,
        verification=verification,
    )

    l0_tool_configs: List[Union[Type[ExecutableTool], AssistantToolConfig]] = [
        *DEFAULT_TOOL_CLASSES.copy(),
        GetContextInfoTool,
    ]

    binary_analysis_team_tool = AssistantToolConfig(
        assistant_class=BaseAssistant,
        sub_agent_config=binary_analysis_cfg,
        name="BinaryAnalysisTeam",
        description="一个专业的二进制分析团队，使用radare2等工具深入分析二进制文件。当需要反汇编、分析函数、检查二进制文件所有潜在的污点传播路径时，应使用此工具。",
    )
    l0_tool_configs.append(binary_analysis_team_tool)

    basic_assistant_tool = AssistantToolConfig(
        assistant_class=BaseAssistant,
        sub_agent_config=worker_agent_cfg,
        name="SingleTaskWorker",
    )
    l0_tool_configs.append(basic_assistant_tool)

    parallel_assistant_tool = AssistantToolConfig(
        assistant_class=ParallelBaseAssistant,
        sub_agent_config=worker_agent_cfg,
        name="ParallelTaskWorker",
    )
    l0_tool_configs.append(parallel_assistant_tool)

    if include_kb:
        kb_config = create_kb_agent_config(max_iterations=max_iterations)
        kb_manager_tool = AssistantToolConfig(
            assistant_class=BaseAssistant,
            sub_agent_config=kb_config,
            name="KnowledgeBaseManager",
            description="用于查询有关此固件文件系统的所有已知信息。在开始新任务前，可以先用它来查询是否已有相关发现，以避免重复工作。",
        )
        l0_tool_configs.append(kb_manager_tool)

    planner_config = AgentConfig(
        agent_class=PlannerAgent,
        tool_configs=l0_tool_configs,
        system_prompt=effective_main_prompt,
        max_iterations=max_iterations,
    )

    return planner_config

def create_firmware_analysis_blueprint(
    include_kb: bool = True,
    max_levels: int = 5,
    max_iterations_per_agent: int = 50,
    verification: bool = False,
) -> AgentConfig:
    """
    创建多层、规划器-执行器嵌套的固件分析代理配置。
    每个规划级别(Lx_Planner)指导一个Lx_Executor。
    Lx_Executor探索其分配的目录并使用助手来:
    - 委派文件分析(深度文件分析助手 -> 通用文件分析器配置)
    - 委派子目录分析(递归目录分析助手 -> 更深层级规划器配置)
    最深层级规划器的执行器将子目录委派给终端执行器。
    """
    if max_levels < 1:
        raise ValueError("max_levels必须至少为1。")

    file_analyzer_config = create_file_analysis_config(
        include_kb=include_kb,
        max_iterations=max_iterations_per_agent,
        verification=verification,
    )
    kb_query_tool_cfg = create_kb_agent_config(
        max_iterations=max_iterations_per_agent,
    )

    def _create_level(level: int) -> AgentConfig:
        """
        递归地创建代理配置的单个层级。

        Args:
            level (int): 当前要创建的层级。

        Returns:
            AgentConfig: 为当前层级生成的代理配置。
        """
        if level < 1:
            return AgentConfig(
                agent_class=ExecutorAgent,
                tool_configs=[
                    GetContextInfoTool,
                    ShellExecutorTool,
                    AssistantToolConfig(
                        assistant_class=DeepFileAnalysisAssistant,
                        sub_agent_config=file_analyzer_config,
                    ),
                    AssistantToolConfig(
                        assistant_class=ParallelDeepFileAnalysisDelegator,
                        sub_agent_config=file_analyzer_config,
                    ),
                ],
                system_prompt=DEFAULT_WORKER_EXECUTOR_SYSTEM_PROMPT,
                max_iterations=max_iterations_per_agent,
            )

        deeper_level_config = _create_level(level - 1)

        # 为当前层级配置工具
        worker_tools = [
            GetContextInfoTool,
            ShellExecutorTool,
            AssistantToolConfig(
                assistant_class=DeepFileAnalysisAssistant,
                sub_agent_config=file_analyzer_config,
            ),
            AssistantToolConfig(
                assistant_class=DeepDirectoryAnalysisAssistant,
                sub_agent_config=deeper_level_config,
            ),
            AssistantToolConfig(
                assistant_class=ParallelDeepFileAnalysisDelegator,
                sub_agent_config=file_analyzer_config,
            ),
            AssistantToolConfig(
                assistant_class=ParallelDeepDirectoryAnalysisDelegator,
                sub_agent_config=deeper_level_config,
            ),
        ]
        if include_kb:
            worker_tools.append(
                AssistantToolConfig(
                    assistant_class=BaseAssistant,
                    sub_agent_config=kb_query_tool_cfg,
                )
            )

        return AgentConfig(
            agent_class=ExecutorAgent,
            tool_configs=worker_tools,
            system_prompt=DEFAULT_WORKER_EXECUTOR_SYSTEM_PROMPT,
            max_iterations=max_iterations_per_agent,
        )

    return _create_level(max_levels) 


class FirmwareMasterAgent: 
    def __init__(
        self,
        firmware_root_path: str,
        output_dir: str,
        user_input: str,
        max_levels_for_blueprint: int = 5,
        max_iterations_per_agent: int = 50,
        agent_instance_name: Optional[str] = "FirmwareMasterAgent"
    ):
        if not os.path.isdir(firmware_root_path):
            raise ValueError(f"Firmware root path '{firmware_root_path}' does not exist or is not a directory.")
        
        self.firmware_root_path = os.path.abspath(firmware_root_path)
        self.output_dir = os.path.abspath(output_dir)
        self.user_input = user_input
        self.max_levels = max_levels_for_blueprint
        self.max_iterations = max_iterations_per_agent
        self.agent_instance_name = agent_instance_name
        self.analysis_duration = 0.0
        self.verification_duration = 0.0
        self._verification_lock = threading.Lock()
        self.container_id = None
        self._start_container()

        self.context = FlexibleContext(
            base_path=self.firmware_root_path,
            current_dir=self.firmware_root_path,
            output=self.output_dir,
            agent_log_dir=os.path.join(self.output_dir, f"{agent_instance_name}_logs"),
            user_input=self.user_input,
            container_id=self.container_id
        )

    def _start_container(self):
        """Starts a docker container and mounts the firmware root."""
        container_name = f"firmhive-radare2-{uuid.uuid4().hex[:12]}"
        docker_command = [
            "docker", "run", "-d", "--rm",
            "--name", container_name,
            "-v", f"{self.firmware_root_path}:/firmware:ro",
            "radare/radare2",
            "sleep", "infinity"
        ]
        try:
            print(f"Starting Docker container: {' '.join(docker_command)}")
            container_id = subprocess.check_output(docker_command, text=True, stderr=subprocess.STDOUT).strip()
            self.container_id = container_id
            print(f"Started Docker container {container_name} with ID: {self.container_id}")
        except subprocess.CalledProcessError as e:
            print(f"Failed to start Docker container: {e.output}")
            raise
        except FileNotFoundError:
            print("Error: 'docker' command not found. Please ensure Docker is installed and in your PATH.")
            raise

    def _stop_container(self):
        """Stops the docker container."""
        if self.container_id:
            print(f"Stopping Docker container {self.container_id}...")
            try:
                subprocess.run(["docker", "stop", self.container_id], check=True, capture_output=True, text=True)
                print(f"Container {self.container_id} stopped.")
            except subprocess.CalledProcessError as e:
                # It might already be stopped or removed, so just log it.
                print(f"Could not stop container {self.container_id}: {e.stderr}")
            finally:
                self.container_id = None

    def run(self, mode: str = 'all', max_workers: int = 5):
        try:
            if mode in ['analyze', 'all']:
                self._run_analysis()
            
            if mode in ['verify', 'all']:
                self.verify(max_workers=max_workers)
            
            self.summary()
            print(f"\n--- Execution complete (Mode: {mode}) ---")
        finally:
            self._stop_container()

    def _run_analysis(self):
        print("\n--- Running in Analysis Mode ---")
        initial_task = (
            f"Please analyze the firmware comprehensively, combining it with the user's core requirements. "
            f"Currently located in firmware directory: {os.path.basename(self.firmware_root_path)}, "
            f"user's core requirement is: {self.user_input} "
            f"Please start from this directory and analyze files and subdirectories layer by layer."
        )
        
        master_agent_config = create_firmware_analysis_blueprint(
            include_kb=True, 
            verification=False,
            max_levels=self.max_levels,
            max_iterations_per_agent=self.max_iterations
        )
        
        master_agent = build_agent(master_agent_config, self.context)
        
        start_time = time.time()
        master_agent.run(user_input=initial_task)
        end_time = time.time()
        self.analysis_duration = end_time - start_time
        print(f"\n--- Analysis complete in {self.analysis_duration:.2f} seconds ---")

    def _load_findings_from_kb(self) -> List[Dict[str, Any]]:
        """Loads all findings from the knowledge base."""
        print("\n--- Loading all findings from knowledge base for verification ---")
        kb_file_path = os.path.join(self.output_dir, "knowledge_base.jsonl")
        if not os.path.exists(kb_file_path):
            print(f"Knowledge base file '{kb_file_path}' does not exist, skipping verification.")
            return []
        
        all_findings = load_knowledge_base(kb_file_path)
        if not all_findings:
            print("Knowledge base is empty, no verification needed.")
            return []

        print(f"Loaded {len(all_findings)} findings from knowledge base for verification.")
        return all_findings

    def _verify_one_finding(self, finding: Dict[str, Any], agent_config: AgentConfig) -> Dict[str, Any]:
        """
        Core logic for verifying a single finding.
        """
        finding_name_for_log = finding.get('name') or finding.get('description', 'untitled_finding')[:50].replace('/', '_')
        print(f"\n>> Starting verification: {finding_name_for_log}")
        
        finding_details = {k: v for k, v in finding.items() if k in ['location','description', 'file_path', 'code_snippet', 'risk_score']}
        verification_finding_details = (
            f"Verify the following finding:\n"
            f"```json\n"
            f"{json.dumps(finding_details, indent=2, ensure_ascii=False)}\n"
            f"```\n"
            f"**Requirements**:\n"
            f"1.  **Focused Verification**: All your operations must revolve around verifying this finding.\n"
            f"2.  **Evidence Support**: Your conclusions must be based on actual evidence returned by tools.\n"
            f"3.  **No Unrelated Analysis**: Do not explore any other potential issues outside of this finding.\n"
        )

        verification_task = DEFAULT_VERIFICATION_TASK_TEMPLATE.format(verification_finding_details=verification_finding_details)
        verification_prompt = DEFAULT_VERIFICATION_INSTRUCTION_TEMPLATE.format(verification_task=verification_task)
        
        task_context = self.context.copy()
        task_context.set("stage", f"verify_{finding_name_for_log}")
        task_context.set("user_input", verification_task)
        task_context.set("agent_log_dir", os.path.join(self.output_dir, "verify_tasks", f"verify_{finding_name_for_log}_logs"))
        
        task_start_time = time.time()
        tokens_before = self.calculate_token_usage()

        verification_analyzer_agent = build_agent(verification_analyzer_config, context=task_context)
        verification_result = verification_analyzer_agent.run(user_input=verification_prompt)
        
        task_end_time = time.time()
        tokens_after = self.calculate_token_usage()

        task_duration = task_end_time - task_start_time
        task_tokens = tokens_after - tokens_before

        print(f"<< Verification completed: {finding_name_for_log} (Time taken: {task_duration:.2f}s, Tokens: {task_tokens})")
        print(f"   Verification result: {verification_result}")

        verification_record = {
            'verification_task': finding_details,
            'verification_result': verification_result,
            'verification_duration_seconds': task_duration,
            'verification_token_usage': task_tokens
        }
        
        results_file_path = os.path.join(self.output_dir, "verification_results.jsonl")

        try:
            with self._verification_lock:
                with open(results_file_path, 'a', encoding='utf-8') as f:
                    f.write(json.dumps(verification_record, ensure_ascii=False) + '\n')
            print(f"   Verification results written to: {results_file_path}")
        except IOError as e:
            print(f"   Failed to write verification results file: {e}")

    def verify(self, max_workers: int = 5):
        """
        [Concurrent] Verifies all findings from the knowledge base.
        """
        print("\n--- Running in Concurrent Verification Mode ---")
        start_time = time.time()
        
        findings_to_process = self._load_findings_from_kb()

        if not findings_to_process:
            print("No findings selected for verification.")
            return

        print(f"Total of {len(findings_to_process)} findings will be verified [concurrently], using {max_workers} worker threads.")

        verification_analyzer_config = create_firmware_analysis_blueprint(
            include_kb=False,
            verification=True,
        )

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = [
                executor.submit(self._verify_one_finding, finding, verification_analyzer_config)
                for finding in findings_to_process
            ]
            for future in as_completed(futures):
                try:
                    future.result() 
                except Exception as exc:
                    print(f'A verification task generated an exception: {exc}')

        end_time = time.time()
        self.verification_duration += (end_time - start_time)
        print(f"\nThis concurrent verification took {end_time - start_time:.2f} seconds. Total verification time accumulated: {self.verification_duration:.2f} seconds.")

    def generate_report(self):
        """Generates a Markdown analysis report."""
        print("\nStarting analysis report generation")
        kb_path = os.path.join(self.output_dir, 'knowledge_base.jsonl')
        if not os.path.exists(kb_path):
            print(f"Knowledge base file '{kb_path}' does not exist, cannot generate report.")
            return None, "Knowledge base file does not exist"

        try:
            from firmhive.utils.convert2md import convert_kb_to_markdown
            success, msg_or_path = convert_kb_to_markdown(kb_path)
            if success:
                print(f"Successfully generated Markdown report: {msg_or_path}")
                return msg_or_path, None
            else:
                print(f"Failed to generate report: {msg_or_path}")
                return None, msg_or_path
        except ImportError:
            error_msg = "Could not import report generation tools, skipping Markdown report generation."
            print(error_msg)
            return None, error_msg
        except Exception as e:
            error_msg = f"An unknown error occurred during report generation: {e}"
            print(error_msg)
            return None, error_msg

    def generate_verification_report(self):
        """Generates a Markdown verification report."""
        print("\nStarting verification report generation")
        
        try:
            from firmhive.utils.convert2md import generate_verification_report_md
            
            success, msg_or_path = generate_verification_report_md(self.output_dir)
            
            if success:
                print(f"Successfully generated Markdown verification report: {msg_or_path}")
                return [msg_or_path], None 
            else:
                if "No verification results file found" in msg_or_path:
                    print(f"No 'verification_results.jsonl' file found in '{self.output_dir}', skipping verification report generation.")
                else:
                    print(f"Failed to generate verification report: {msg_or_path}")
                return None, msg_or_path
                    
        except ImportError:
            error_msg = "Could not import report generation tools, skipping Markdown verification report generation."
            print(error_msg)
            return None, error_msg
        except Exception as e:
            error_msg = f"An unknown error occurred during report generation: {e}"
            print(error_msg)
            return None, error_msg

    def calculate_token_usage(self):
        """Calculates and returns the total token usage."""
        token_usage_file = os.path.join(self.output_dir, "token_usage.jsonl")
        if not os.path.exists(token_usage_file):
            return 0

        total_tokens = 0
        try:
            with open(token_usage_file, 'r') as f:
                for line in f:
                    try:
                        data = json.loads(line)
                        total_tokens += data.get('total_tokens', 0)
                    except json.JSONDecodeError:
                        continue
        except Exception as e:
            print(f"Error calculating token usage: {e}")
        return total_tokens

    def summary(self):
        """Creates and writes a summary.txt file. Regenerates and overwrites the summary on each call."""
        self.generate_report()
        self.generate_verification_report()
        
        total_tokens = self.calculate_token_usage()
        
        summary_path = os.path.join(self.output_dir, "summary.txt")
        summary_content = (
            f"Analysis and Verification Summary\n"
            f"Analysis Phase Duration: {self.analysis_duration:.2f} seconds\n"
            f"Verification Phase Duration: {self.verification_duration:.2f} seconds\n"
            f"Total Duration: {self.analysis_duration + self.verification_duration:.2f} seconds\n"
            f"Total Model Token Usage: {total_tokens}\n"
        )
        try:
            with open(summary_path, 'w', encoding='utf-8') as f:
                f.write(summary_content)
            print(f"\nSummary information updated: {summary_path}")
            print(summary_content)
        except IOError as e:
            print(f"Could not write summary file {summary_path}: {e}")
    
if __name__ == "__main__":
    default_user_input = ("Perform a comprehensive security analysis of the firmware. The core objective is to identify and report complete, viable attack chains.")
    
    parser = argparse.ArgumentParser(description="Firmware Analysis Master Agent")
    parser.add_argument("--search_dir", type=str, required=True, help="Path to the directory to search for firmware root.")
    parser.add_argument("--output", type=str, default="output", help="Base directory for analysis output.")
    parser.add_argument("--mode", type=str, choices=['analyze', 'verify', 'all'], default='all', 
                        help="Execution mode: 'analyze' only, 'verify' only, or 'all' (analyze then verify).")
    parser.add_argument("--user_input", type=str, default=default_user_input, help="User input/prompt for the analysis. Uses a default prompt if not provided in 'analyze' or 'all' mode.")
    parser.add_argument("--concurrent", action="store_true", help="Run verification concurrently.")
    parser.add_argument("--max_workers", type=int, default=5, help="Max workers for concurrent verification.")
    
    args = parser.parse_args()

    firmware_root = find_firmware_root(args.search_dir)
    if not firmware_root:
        print(f"Error: Could not find a valid firmware root in '{args.search_dir}'.")
        sys.exit(1)
    
    print(f"Found firmware root at: {firmware_root}")

    output_dir = args.output
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    print(f"Output will be saved to: {output_dir}")

    master_agent = FirmwareMasterAgent(
        max_levels_for_blueprint=5,
        firmware_root_path=firmware_root,
        output_dir=output_dir,
        user_input=args.user_input,
    )
    
    if args.mode == 'analyze':
        print("\n--- Running in Analysis-Only Mode ---")
        master_agent.run()
        print("\n--- Analysis complete ---")

    elif args.mode == 'verify':
        print("\n--- Running in Verification-Only Mode ---")
        if args.concurrent:
            master_agent.verify(
                max_workers=args.max_workers
            )
        else:
            master_agent.verify()
        print("\n--- Verification complete ---")

    elif args.mode == 'all':
        print("\n--- Running in Analysis and Verification Mode ---")
        summary = master_agent.run()
        print("\n--- Analysis and Verification complete ---")