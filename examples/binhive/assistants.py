import os
from typing import Any, Dict, Optional, List, Union, Type

from hivemind.base import BaseAgent
from hivemind.tools.basetool import FlexibleContext, ExecutableTool
from hivemind.core.assistants import BaseAssistant, ParallelBaseAssistant

class ParallelTaskDelegator(ParallelBaseAssistant):
    name = "TaskDelegator"
    description = """
    任务委托器 - 用于将多个子任务分发给并行执行的子代理进行处理。
    
    适用场景：
    1. 需要将一个任务分解为多个独立子任务进行处理。
    2. 子任务之间没有严格的执行顺序依赖，比如寻找多个可控变量地址的任务。
    3. 推荐在全面分析和复杂任务中使用，可以并行执行多个子任务，提高分析效率。
    
    """
    parameters = {
        "type": "object",
        "properties": {
            "tasks": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "task": {
                            "type": "string",
                            "description": "要执行的子任务的具体描述，注意每个子任务的描述都是独立的，需要说明分析对象。"
                        }
                    },
                    "required": ["task"],
                    "description": "包含单个任务描述的任务项。"
                },
                "description": "需要分发给子代理执行的独立子任务列表。"
            }
        },
        "required": ["tasks"]
    }
    timeout = 9600

    def _build_sub_agent_prompt(self, **kwargs: Any) -> str:
        """
        为子代理构建完整的任务提示。
        """
        task_description = kwargs.get("task")
        usr_init_msg = self.context.get("user_input")

        usr_init_msg_content = usr_init_msg if usr_init_msg else "未提供用户初始请求"
        task_description_content = task_description if task_description else "未提供任务描述"

        prompt_parts = [
            f"用户核心请求是:\n{usr_init_msg_content}",
            f"当前具体任务:\n{task_description_content}"
        ]

        return "\n\n".join(prompt_parts)


class ParallelFunctionDelegator(ParallelBaseAssistant):
    name = "FunctionDelegator"
    description = """
    函数分析委托器 - 一个专门用于二进制文件的函数调用链分析智能体。职责是前向追踪污点数据在函数调用间的流动路径。你可以将潜在的外界入口点委托该智能体来深入追踪。
    """

    parameters = {
        "type": "object",
        "properties": {
            "tasks": { 
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "task_description": {
                            "type": "string", 
                            "description": "为子函数创建分析任务时，你的描述必须清晰地包含以下四点：\n1. **目标函数**: 要分析的子函数名和地址。\n2. **污点入口**: 在子函数中，污点位于哪个具体的寄存器或栈地址（例如：'污点位于第一个参数寄存器 r0'）。\n3. **污点来源**: 这个污点数据在父函数中是如何产生的（例如：'该值是父函数 main 通过调用 nvram_get(\"lan_ipaddr\") 获得的'）。\n4. **分析目标**: 明确指示新任务要追踪这个新的污点入口（例如：'追踪 r0 在子函数内部的流动路径'）。"
                        },
                        "task_context": {
                            "type": "string", 
                            "description": "(可选) 提供影响分析的补充性上下文。这部分信息不是污点流本身，但可能影响子函数的执行路径。例如：\n- 'r2 寄存器此时的值是 0x100，它代表了缓冲区的最大长度'\n- '全局变量 `is_admin` 在此调用前被设置为 1'\n- '分析时需假设文件已被成功打开'"
                        }
                    },
                    "required": ["task_description"]
                },
                "description": "需要分析的函数任务列表。"
            }
        },
        "required": ["tasks"]
    }

    def __init__(self, 
                 context: FlexibleContext,
                 agent_class_to_create: Type[BaseAgent] = BaseAgent,
                 default_sub_agent_tool_classes: Optional[List[Union[Type[ExecutableTool], ExecutableTool]]] = None,
                 default_sub_agent_max_iterations: int = 10,
                 sub_agent_system_prompt: Optional[str] = None,
                 name: Optional[str] = None,
                 description: Optional[str] = None,
                 timeout: Optional[int] = None
                ):
        final_name = name or ParallelFunctionDelegator.name
        final_description = description or ParallelFunctionDelegator.description
        
        super().__init__(
            context=context,
            agent_class_to_create=agent_class_to_create,
            default_sub_agent_tool_classes=default_sub_agent_tool_classes,
            default_sub_agent_max_iterations=default_sub_agent_max_iterations,
            sub_agent_system_prompt=sub_agent_system_prompt,
            name=final_name,
            description=final_description,
            timeout=timeout
        )
    def _build_sub_agent_prompt(self, **kwargs: Any) -> str:
        """
        为子代理构建完整的任务提示，并包含可选的 task_context。
        """
        task_description = kwargs.get("task_description")
        task_context = kwargs.get("task_context")
        usr_init_msg = self.context.get("user_input")

        usr_init_msg_content = usr_init_msg if usr_init_msg else "未提供用户初始请求"
        task_description_content = task_description if task_description else "未提供任务描述"

        prompt_parts = [
            f"用户核心请求是:\n{usr_init_msg_content}",
            f"当前具体任务:\n{task_description_content}"
        ]

        if task_context:
            prompt_parts.append(f"补充性上下文:\n{task_context}")

        return "\n\n".join(prompt_parts)

