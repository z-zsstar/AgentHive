import os
from typing import Dict, List, Any, Optional, Type, Union

from agenthive.base import BaseAgent
from agenthive.core.builder import AgentConfig, AssistantToolConfig

from binhive.recorder import RecorderAgent,StoreFindingsTool,DEFAULT_KB_SYSTEM_PROMPT
from binhive.tools import FlexibleContext, ExecutableTool, Radare2Tool
from binhive.assitants import ParallelFunctionDelegator,ParallelTaskDelegator


SHARED_RESPONSE_FORMAT_BLOCK = """
每个发现必须包含以下**核心内容**：
- **`type`**: 漏洞对应的CWE条目 (例如: 'CWE-78')。
- **`identifier`**: **仅当**污点通过具名媒介（如NVRAM变量、环境变量、IPC套接字）进行跨组件传递时，才使用此字段记录该媒介的符号名称或者外部函数名称（例如 'lan_ipaddr', 'PATH', '/var/run/ubus.sock'），不要脱敏。
- **`propagation`**: 描述污点从来源到汇聚点的完整传播路径。**此路径必须包含足够详细的关键代码片段（汇编或高质量伪代码），以证明污点的流动和缺乏净化**。路径的终点是一个危险函数(sink)，中间的每个步骤都应遵循'Step: 三到五行汇编或伪代码片段 --> [步骤解释]'的格式。例如：["Source: Input from client socket received in function main", "Step: mov r0, r4 --> User input is moved to r0 at 0x401a10", "Sink: bl system --> Tainted data in r0 is passed to system() at 0x401b20"]
- **`reason`**: 详细解释你的判断理由，支撑所有结论。
- **`risk_score`**: 风险评分（0.0-10.0），变量是否真的外界可控，是否真的能被攻击者利用？风险模型为假设攻击者可以连接设备且正常登录界面。
- **`confidence`**: 确信度评分，证据是否充分？（0.0-10.0）。

#### 注意
- 严禁伪造任何信息，必须基于工具获取的实际证据。
"""

DEFAULT_BINARY_ANALYSIS_SYSTEM_PROMPT = f"""
你是专业的固件二进制文件安全分析智能体。你的任务是针对当前具体任务且结合总体需求，全面深入分析当前指定的二进制文件，找出其中外界真实可利用的污点，委托助手追踪，最终完整报告所有可利用路径。

**工作原则:**
- **证据为本**: 所有分析都必须基于从 `r2` 工具获得的实际证据，禁止无根据猜测。
- **污点识别**: 你需要自主规划和分解任务，调用工具和助手来完成多个子任务，尤其是寻找多个入口的地址的任务。你需要准确且无遗漏的找到所有外界真实可控变量，这包括但不限于：网络接口（如HTTP参数、API端点、原始套接字输入）、进程间通信（IPC）、NVRAM/环境变量等。判断污点是否真实可利用，否则不追踪。威胁模型是攻击者是一个已经连接到设备并且拥有合法登录凭据的用户。
- **污点追踪**: 你自身不进行任何深入的污点追踪，而是委托给助手进行定位和污点追踪，最后完整给出从入口到sink的完整污点传播路径。
- **专注分析**: 专注于当前任务，一旦你认为完成当前具体任务即可结束，**严禁** 提供任何形式的修复建议或任何主观评论。你的最终输出是所有基于证据的可能被攻击者成功利用的路径，不要遗漏。

**最终回复要求**:
*   你的回应必须有完整证据，不要遗漏任何有效信息和路径。
*   用具体证据支持所有路径发现，并如实报告任何证据不足或困难。
{SHARED_RESPONSE_FORMAT_BLOCK}
"""

DEFAULT_FUNCTION_ANALYSIS_SYSTEM_PROMPT = """
你是一个高度专业化的固件二进制函数调用链分析助手。你的任务是且仅是：从当前指定的函数开始，严格地、单向地、前向地追踪指定的污点数据，直到它到达一个sink（危险函数）。

**严格的行为准则（必须遵守）：**
1.  **绝对专注**: 你的分析范围 **仅限于** 当前任务指定的函数及其调用的子函数。**严禁** 分析任何与当前调用链无关的其他函数或代码路径。
2.  **单向追踪**: 你的任务是 **前向（forward）追踪**。一旦污点传入子函数，你必须跟随它进入，**严禁** 返回或进行反向分析。
3.  **禁止评估**: **严禁** 提供任何形式的安全评估、修复建议或任何主观评论。你的唯一输出是基于证据的、格式化的污点路径。
4.  **完整路径**: 你必须提供从污点源头到sink的 **完整、可复现的** 传播路径。如果因为某种原因路径中断，必须明确说明中断的位置和原因。

**分析流程:**
1.  **分析当前函数**: 使用 `r2` 工具分析当前函数的代码，理解污点数据（通常在特定寄存器或内存地址中）如何被处理和传递。
2.  **决策：深入或记录**:
    *   **深入**: 如果污点数据被明确传递给一个子函数，简单预览子函数逻辑，且对子函数创建一个新的委托任务。任务描述必须包含：1) **目标函数（尽可能根据反汇编提供具体的函数地址）**，2) **污点入口**（污点在子函数中的哪个寄存器/内存），3) **污点来源**（污点在父函数中如何产生），以及 4) **分析目标**（对新污点入口的追踪要求）。
    *   **记录**: 如果污点数据被传递给一个 **sink** (如 `system`, `sprintf`) ，且确认为危险操作（最好构造一个PoC），记录这条完整的传播路径，这是你需要详细报告的内容。
3.  **路径中断**: 如果污点在当前函数内被安全处理（如净化、验证）或未被传递给任何子函数、sink，则终止当前路径的分析并明确报告。

**最终报告格式:**
*   在分析的最后，你需要将所有发现的完整污点传播路径，用一个清晰的树状图呈现。
*   每个步骤 **必须** 遵循 `'Step: 地址：汇编代码或伪代码片段 --> 步骤解释'` 的格式。**代码片段必须是真实、可验证的，并且是理解数据流的关键。严禁只提供解释或者结论而不提供地址和代码。
"""

DEFAULT_BINARY_VALIDATION_SYSTEM_PROMPT = f"""
你是固件二进制文件调用链验证智能体。你的唯一任务是根据给定的线索的调用链（有的地址信息可能存在偏差，需要主动探索并获取真实地址），在指定二进制文件中进行严格验证。

**验证要求:**
- 仅基于 r2 获取的真实证据进行判断，禁止任何猜测。
- 按线索指示的位置优先检查（函数地址/名称、sink、输入变量），判断污点是否真实可利用，否则不追踪。确认是否存在从线索所述来源到危险操作的可复现传播路径。
- 如果验证成功：完整输出基于证据的传播路径(使用radare2工具得到的地址)。
- 如果验证失败：明确说明失败原因（例如：函数/地址不存在、数据未到达 sink、在中途被净化、缺少足够证据等）。
- 不进行主观风险评估，仅描述可证伪的证据链和结论。

**工作原则:**
- **证据为本**: 所有分析都必须基于从 `r2` 工具获得的实际证据，禁止无根据猜测。
- **污点识别**: 你需要自主规划和分解任务，调用工具和助手来完成多个子任务。判断污点是否真实可利用，否则不追踪。
- **污点追踪**: 你自身不进行任何深入的污点追踪，而是委托给函数助手进行污点追踪，最后完整给出从入口到sink的完整污点传播路径。
- **专注分析**: 专注于当前任务，一旦你认为完成当前具体任务即可结束，**严禁** 提供任何形式的修复建议或任何主观评论。

"""

class ExecutorAgent(BaseAgent):
    def __init__(
        self,
        tools: Optional[List[Union[Type[ExecutableTool], ExecutableTool]]] = None,
        system_prompt: str = DEFAULT_BINARY_ANALYSIS_SYSTEM_PROMPT,
        output_schema: Optional[Dict[str, Any]] = None,
        max_iterations: int = 25,
        history_strategy = None,
        context: Optional[FlexibleContext] = None,
        messages_filters: List[Dict[str, str]] = None,
        **extra_params: Any
    ):
        self.file_path = context.get("file_path") if context else None
        self.file_name = os.path.basename(self.file_path) if self.file_path else None
        
        tools_to_pass = tools if tools is not None else [Radare2Tool]
        self.messages_filters = messages_filters if messages_filters else [{'from': context.get('base_path') + os.path.sep, 'to': ''}] if context and context.get('base_path') else []
        
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
    """文件分析Agent，并在分析后存储结果。"""

    def __init__(
        self,
        tools: Optional[List[Union[Type[ExecutableTool], ExecutableTool]]] = None,
        system_prompt: str = None,
        output_schema: Optional[Dict[str, Any]] = None,
        max_iterations: int = 25,
        history_strategy = None,
        context: Optional[FlexibleContext] = None,
        messages_filters: List[Dict[str, str]] = None,
        **extra_params: Any
    ):
        self.file_path = context.get("file_path") if context else None
        tools_to_pass = tools if tools is not None else [Radare2Tool]
        self.messages_filters = messages_filters if messages_filters else [{'from': context.get('base_path') + os.path.sep, 'to': ''}, {'from': 'zxr', 'to': 'root'}] if context and context.get('base_path') else []
        
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
        self.kb_storage_agent = RecorderAgent(system_prompt=DEFAULT_KB_SYSTEM_PROMPT, context=kb_context, tools=[StoreFindingsTool])
   
    def run(self, user_input: str = None) -> Any:
        findings = str(super().run(user_input=user_input))
        
        store_prompt = (
            f"新的分析结果如下：\n"
            f"{findings}\n\n"
            f"请基于以上分析结果，判断是否存储。"
        )
        self.kb_storage_agent.run(user_input=store_prompt)
        return findings
    

def _create_nested_function_analysis_config(max_iterations: int, level: int = 4, verification: bool = False) -> AgentConfig:
    default_system_prompt = DEFAULT_FUNCTION_ANALYSIS_SYSTEM_PROMPT
    if verification:
        default_system_prompt = DEFAULT_BINARY_VALIDATION_SYSTEM_PROMPT
    if level <= 0:
        return AgentConfig(
            agent_class=ExecutorAgent,
            tool_configs=[Radare2Tool],
            system_prompt=default_system_prompt,
            max_iterations=max_iterations,
        )

    sub_agent_config = _create_nested_function_analysis_config(max_iterations, level - 1)

    delegator_tool = AssistantToolConfig(
        assistant_class=ParallelFunctionDelegator,
        sub_agent_config=sub_agent_config,
    )
    
    current_level_tools = [Radare2Tool, delegator_tool]

    return AgentConfig(
        agent_class=ExecutorAgent,
        tool_configs=current_level_tools,
        system_prompt=default_system_prompt,
        max_iterations=max_iterations,
    )


def create_binary_analysis_config(
    max_iterations: int = 70,
    system_prompt: Optional[str] = None,
    max_nesting_level: int = 4,
    verification: bool = True
) -> AgentConfig:
    effective_system_prompt = system_prompt or DEFAULT_BINARY_ANALYSIS_SYSTEM_PROMPT

    function_agent_config = _create_nested_function_analysis_config(max_iterations, level=max_nesting_level - 1, verification=verification)
    function_delegator_tool = AssistantToolConfig(
        assistant_class=ParallelFunctionDelegator,
        sub_agent_config=function_agent_config,
    )
    task_agent_config = AgentConfig(
            agent_class=ExecutorAgent,
            tool_configs=[Radare2Tool,function_delegator_tool],
            system_prompt=DEFAULT_BINARY_ANALYSIS_SYSTEM_PROMPT,
            max_iterations=max_iterations,
        )
    l0_task_delegator_tool = AssistantToolConfig(
        assistant_class=ParallelTaskDelegator,
        sub_agent_config=task_agent_config,
    )

    planner_config = AgentConfig(
        agent_class=PlannerAgent,
        tool_configs=[l0_task_delegator_tool, Radare2Tool],
        system_prompt=effective_system_prompt,
        max_iterations=max_iterations,
    )
    
    return planner_config
