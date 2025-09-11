import json 
import os
import fcntl
from typing import Dict, List, Any, Optional, Type, Union

from agenthive.base import BaseAgent
from agenthive.historystrategy import HistoryStrategy
from agenthive.tools.basetool import ExecutableTool, FlexibleContext

DEFAULT_KB_FILE = "propagation_paths.jsonl"

FINDING_SCHEMA: Dict[str, Dict[str, Any]] = {
    "type": {
        "type": "string",
        "description": "漏洞对应的CWE条目，多个用逗号分隔。例如：'CWE-120' (经典缓冲区溢出), 'CWE-78' (OS命令注入)。"
    },
    "identifier": {
        "type": "array", 
        "items": {"type": "string"},
        "description": "**仅当**污点通过具名媒介，包括source的具体变量名（如污点参数有语义的变量名、NVRAM变量、环境变量、IPC套接字）进行跨组件传递时，才使用此字段记录该媒介的符号名称（例如 'lan_ipaddr', 'PATH', '/var/run/ubus.sock'）。对于组件内部的直接数据（例如，命令行参数 `argv` 、地址），**此字段必须省略**。严禁使用地址或`argv`等宽泛的变量名无法作为跨组件标识符的名称。"
    },
    "propagation": {
        "type": "array",
        "items": {"type": "string"},
        "description": "描述污点从来源(source)到汇聚点(sink)的完整传播路径。路径的终点可以是一个危险函数(sink)，也可以是一个将污点传递到其他组件的操作(handoff)。中间的每个步骤都应遵循'Step: [Relevant Code Snippet] --> [Explanation of the step]'的格式。例如：[\"Source: Input from client socket received in function main\", \"Step: mov r0, r4 --> User input is moved to r0 at 0x401a10\", \"Sink: bl system --> Tainted data in r0 is passed to system() at 0x401b20\"]"
    },
    "reason": {
        "type": "string",
        "description": "详细解释你的判断理由，支撑结论。"
    },
    "risk_score": {
        "type": "number",
        "description": "风险评分（0.0-10.0），评估该路径成为真实漏洞的概率多大。"
    },
    "confidence": {
        "type": "number",
        "description": "确信度评分（0.0-10.0），评估该路径的证据是否充分。"
    }
}
FINDING_SCHEMA_REQUIRED_FIELDS: List[str] = ["type", "propagation", "risk_score", "confidence"]

class KnowledgeBaseMixin:
    """
    Mixin 类，用于管理 KB 文件路径和锁。现在也被设计为可用于直接存储（虽然目前是通过工具实现）。
    Mixin 提供了一种将通用功能（如 KB 文件处理）添加到多个类（如工具类）的方法，而无需继承。
    """
    def _initialize_kb(self, context: FlexibleContext):
        """
        初始化知识库设置。
        - 从上下文（context）获取 'output'，如果未提供则使用 DEFAULT_output_NAME。
        - 检查并创建知识库文件所在的目录（如果路径包含目录）。
        - 处理目录创建失败的情况，并回退到当前目录的文件名。
        - 打印最终确定的知识库文件绝对路径。
        """
        output_from_context = context.get("output")
        
        if output_from_context and isinstance(output_from_context, str):
            self.output = output_from_context
        else:
            raise ValueError("'output' not found in context or invalid.")

        if not os.path.exists(self.output):
            try:
                os.makedirs(self.output, exist_ok=True)
                print(f"Created output directory: {os.path.abspath(self.output)}")
            except OSError as e:
                print(f"警告: 无法创建输出目录 '{self.output}': {e}. 将尝试在当前目录创建知识库文件。")
                self.output = "."

        self.kb_file_path = os.path.join(self.output, DEFAULT_KB_FILE)
        
        kb_specific_dir = os.path.dirname(self.kb_file_path)
        if kb_specific_dir and not os.path.exists(kb_specific_dir):
            try:
                os.makedirs(kb_specific_dir, exist_ok=True)
            except OSError as e:
                 print(f"警告: 无法为 KB 文件创建特定目录 '{kb_specific_dir}': {e}")
        
        print(f"知识库文件路径设置为: {os.path.abspath(self.kb_file_path)}")

    def _load_kb_data(self, lock_file) -> List[Dict[str, Any]]:
        """
        使用文件锁从 JSONL 文件加载知识库。
        lock_file: 已经打开并准备好加锁的文件对象。
        返回: 加载的发现列表，如果文件为空或出错则返回空列表。
        """
        findings = []
        try:
            fcntl.flock(lock_file, fcntl.LOCK_SH)
            lock_file.seek(0)
            for line_bytes in lock_file:
                if not line_bytes.strip():
                    continue
                try:
                    findings.append(json.loads(line_bytes.decode('utf-8-sig')))
                except json.JSONDecodeError as e:
                    print(f"警告: 解析知识库中的一行时出错，已跳过。错误: {e}. 行: {line_bytes[:100]}...")
            return findings
        except Exception as e:
            print(f"加载 KB '{self.kb_file_path}' 时出错: {e}。返回空列表。")
            return []
        finally:
            try:
                fcntl.flock(lock_file, fcntl.LOCK_UN)
            except (ValueError, OSError):
                pass

class StoreFindingsTool(ExecutableTool, KnowledgeBaseMixin):
    name: str = "StoreStructuredFindings"
    description: str = """
    将结构化的固件分析发现以追加方式存储到知识库中。每个发现必须包含详细的路径约束和条件约束信息，以确保发现的可追溯性和可验证性。
    """
    parameters: Dict = {
        "type": "object",
        "properties": {
            "findings": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": FINDING_SCHEMA,
                    "required": FINDING_SCHEMA_REQUIRED_FIELDS
                },
                "description": "要存储的问题列表。列表中每个对象的结构应遵循。上下文信息 (如 'file_path') 将由工具自动添加。"
            }
        },
        "required": ["findings"]
    }

    def __init__(self, context: FlexibleContext):
        ExecutableTool.__init__(self, context)
        KnowledgeBaseMixin._initialize_kb(self, context)

    def execute(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        context_file_path = self.context.get("file_path")
        
        if not findings: 
            return {"status": "info", "message": "信息: 没有提供问题以供存储。"}

        enriched_findings = []
        for finding_dict in findings:
            if isinstance(finding_dict, dict):
                finding_copy = finding_dict.copy()
                
                if context_file_path:
                    finding_copy['file_path'] = context_file_path
                
                enriched_findings.append(finding_copy)
            else:
                print(f"警告: 在 findings 列表中发现非字典项，已忽略: {finding_dict}")
        
        if not enriched_findings: 
            return {"status": "info", "message": "信息: 没有有效的问题被处理以供存储。"}

        try:
            with open(self.kb_file_path, 'ab') as f:
                fcntl.flock(f, fcntl.LOCK_EX)
                try:
                    for finding in enriched_findings:
                        try:
                            json_string = json.dumps(finding, ensure_ascii=False)
                            f.write(json_string.encode('utf-8'))
                            f.write(b'\n')
                        except TypeError as te:
                            print(f"CRITICAL: 无法序列化发现项，已跳过。错误: {te}. 内容: {str(finding)[:200]}...")
                            continue
                finally:
                    fcntl.flock(f, fcntl.LOCK_UN)

            num_stored = len(enriched_findings)
            message = f"成功将 {num_stored} 个发现追加到知识库."
            print(f"{message}")
            return {"status": "success", "message": message, "stored_count": num_stored}

        except Exception as e:
            error_message = f"存储问题时出错: {str(e)}"
            print(f"{error_message} (详细: {e})")
            return {"status": "error", "message": error_message}

DEFAULT_KB_SYSTEM_PROMPT = f"""
你是固件分析库智能体，负责高效、准确地记录有效的，可能被利用的风险路径，否则无需执行任何存储，直接返回。

### 存储发现 (StoreStructuredFindings)
- **用途**: 结构化的存储所有风险路径。
- **关键要求**: 
  - `propagation` 字段必须清晰地描述污点从源到汇聚点的完整路径。

## **绝对禁止事项**
1. **禁止编造任何信息**：所有发现必须基于真实的代码分析结果。
2. **禁止猜测和推断**：只记录有明确证据支持的发现。

记住：你的工作直接影响固件安全分析的质量和效率。保持专业、准确和系统化的方法，注意最终把内容转为英文记录，避免使用中文。
"""

class RecorderAgent(BaseAgent):
    def __init__(
        self,
        context: FlexibleContext, 
        max_iterations: int = 25, 
        history_strategy: Optional[HistoryStrategy] = None,
        tools: Optional[List[Union[Type[ExecutableTool], ExecutableTool]]] = [StoreFindingsTool],
        system_prompt: Optional[str] = DEFAULT_KB_SYSTEM_PROMPT,
        output_schema: Optional[Dict[str, Any]] = None, 
        **extra_params: Any
    ):
        tools_to_pass = tools
        
        final_system_prompt = system_prompt
        
        self.messages_filters = [{'from': context.get('base_path'), 'to': '/'}]
        
        super().__init__(
            tools=tools_to_pass, 
            context=context, 
            system_prompt=final_system_prompt, 
            output_schema=output_schema, 
            max_iterations=max_iterations, 
            history_strategy=history_strategy,
            **extra_params
        )
