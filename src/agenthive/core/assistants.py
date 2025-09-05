import json
import traceback
import threading
from typing import Optional, List, Type, Union, Any, Dict

from ..base import BaseAgent
from ..tools.basetool import FlexibleContext, ExecutableTool

class BaseAssistant(ExecutableTool):
    name = "TaskDelegator"
    description = """
    任务委托器 - 用于将一个子任务委托给子代理进行处理。
    
    适用场景：
    需要在得到单步任务的分析结果后，才决定下一步分析任务。

    """
    parameters = {
        "type": "object",
        "properties": {
            "task": {
                "type": "object",
                "properties": {
                    "task": {
                        "type": "string",
                        "description": "要执行的子任务的具体描述，需要注意说明分析对象。"
                    }
                },
                "required": ["task"],
                "description": "包含单个任务描述的任务项。"
            }
        },
        "required": ["task"]
    }

    timeout = 9600

    def __init__(
        self,
        context: FlexibleContext,
        agent_class_to_create: Type[BaseAgent] = BaseAgent,
        default_sub_agent_tool_classes: Optional[List[Union[Type[ExecutableTool], ExecutableTool]]] = None,
        default_sub_agent_max_iterations: int = 25,
        sub_agent_system_prompt: Optional[str] = None,
        name: Optional[str] = None,
        description: Optional[str] = None,
        timeout: Optional[int] = None,
    ):
        super().__init__(context)
        self.agent_class_to_create = agent_class_to_create
        self.default_sub_agent_tool_classes = default_sub_agent_tool_classes if default_sub_agent_tool_classes is not None else []
        self.default_sub_agent_max_iterations = default_sub_agent_max_iterations
        self.sub_agent_system_prompt = sub_agent_system_prompt

        if name is not None:
            self.name = name
        if description is not None:
            self.description = description

        if timeout is not None:
            self.timeout = timeout

    def _extract_task(self, **kwargs: Any) -> List[Dict[str, Any]]:
        """
        从 execute 方法的 **kwargs 中提取要并行处理的任务项列表。
        子类可以重写此方法以处理不同的输入参数格式 (例如 'file_paths' 而不是 'tasks')。
        """
        return kwargs.get("tasks", [])

    def _prepare_sub_agent_context(self, **kwargs: Any) -> FlexibleContext:
        """
        在创建子代理之前准备其上下文。
        默认实现是创建当前上下文的副本。
        **kwargs 包含从 execute 方法传入的所有参数。
        子类可以重写此方法以从 kwargs 中选择需要的参数并向上下文添加特定于任务的信息。
        """
        sub_agent_context = self.context.copy()
        return sub_agent_context

    def _build_sub_agent_prompt(self, **kwargs: Any) -> str:
        """
        为子代理构建完整的任务提示。
        **kwargs 包含从 execute 方法传入的所有参数。
        子类可以重写此方法以从 kwargs 中选择需要的参数构建提示。
        """
        # 默认实现从 task 参数中获取 task
        task_list = kwargs.get("task_list", {})
        task = task_list.get("task") if isinstance(task_list, dict) else None

        usr_init_msg_content = self.context.get("user_input") if self.context.get("user_input") else "未提供用户初始请求"
        task_content = task if task else "未提供任务描述" # 确保非空

        return (
            f"用户初始请求是:\n{usr_init_msg_content}\n"
            f"当前具体任务:\n{task_content}"
        )

    def execute(self, **kwargs: Any) -> str:
        from .builder import AgentConfig, build_agent
        task_for_error_log: Optional[str] = "未知任务描述"

        try:
            # Phase 1: Build prompt (can be overridden)
            task_prompt = self._build_sub_agent_prompt(**kwargs)
            
            # Phase 2: Prepare context (can be overridden)
            try:
                sub_agent_prepared_context = self._prepare_sub_agent_context(**kwargs)
            except Exception as e:
                return f"错误: {str(e)}"
            
            # Phase 4: Create and run sub-agent
            sub_agent_instance_name = f"{self.name}_sub_agent"
            
            sub_agent_config = AgentConfig(
                agent_class=self.agent_class_to_create,
                tool_configs=self.default_sub_agent_tool_classes,
                system_prompt=self.sub_agent_system_prompt,
                max_iterations=self.default_sub_agent_max_iterations,
                agent_instance_name=sub_agent_instance_name,
            )
            
            sub_agent = build_agent(
                agent_config=sub_agent_config,
                context=sub_agent_prepared_context,
            )
            
            result_from_sub_agent = sub_agent.run(task_prompt)
            return result_from_sub_agent

        except Exception as e:
            # Generic catch-all for any error during the above phases
            error_desc_snippet = task_for_error_log[:70]
            # More descriptive error message for the user/LLM
            error_message_for_return = f"错误: {self.name} 在执行子任务时失败 (任务描述片段: '{error_desc_snippet}'): {type(e).__name__} - {str(e)}"
            
            # Detailed message for logging
            log_error_message = f"Error in {self.name} during sub-task preparation or delegation (task description snippet: '{error_desc_snippet}...'): {type(e).__name__} - {str(e)}"
            logger = getattr(self, 'logger', None)
            if logger:
                logger.error(log_error_message, exc_info=True)
            else:
                print(f"ERROR in {self.name}: {log_error_message}")
                print(traceback.format_exc())
            return f"执行子任务时发生错误: {error_message_for_return}" # Return the detailed error message


class ParallelBaseAssistant(ExecutableTool):
    name = "ParallelTaskDelegator"
    description = """
    任务委托器 - 用于将多个子任务分发给并行执行的子代理进行处理。
    
    适用场景：
    1. 需要将一个复杂任务分解为多个独立子任务进行处理。
    2. 子任务之间没有严格的执行顺序依赖。
    3. 推荐在大规模和复杂任务中使用，可以并行执行多个子任务，提高分析效率。
    
    """
    parameters = {
        "type": "object",
        "properties": {
            "tasks": { # General 'tasks' parameter, a list of task objects
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

    def __init__(
        self,
        context: FlexibleContext,
        agent_class_to_create: Type[BaseAgent] = BaseAgent,
        default_sub_agent_tool_classes: Optional[List[Union[Type[ExecutableTool], ExecutableTool]]] = None,
        default_sub_agent_max_iterations: int = 25,
        sub_agent_system_prompt: Optional[str] = None,
        name: Optional[str] = None,
        description: Optional[str] = None,
        timeout: Optional[int] = None,
    ):
        super().__init__(context)
        self.agent_class_to_create = agent_class_to_create
        self.default_sub_agent_tool_classes = default_sub_agent_tool_classes if default_sub_agent_tool_classes is not None else []
        self.default_sub_agent_max_iterations = default_sub_agent_max_iterations
        self.sub_agent_system_prompt = sub_agent_system_prompt

        if name is not None:
            self.name = name
        if description is not None:
            self.description = description

        if timeout is not None:
            self.timeout = timeout

    def _extract_task_list(self, **kwargs: Any) -> List[Dict[str, Any]]:
        """
        从 execute 方法的 **kwargs 中提取要并行处理的任务项列表。
        子类可以重写此方法以处理不同的输入参数格式 (例如 'file_paths' 而不是 'tasks')。
        """
        return kwargs.get("tasks", [])

    def _prepare_sub_agent_context(self, **kwargs: Any) -> FlexibleContext:
        """
        在创建子代理之前为其准备上下文 (并行版本)。
        默认实现是创建当前上下文的副本。
        **kwargs 包含从 execute 方法传入的用于单个任务的所有参数。
        子类可以重写此方法以从 kwargs 中选择需要的参数并向上下文添加特定于任务的信息。
        """
        sub_agent_context = self.context.copy()
        return sub_agent_context

    def _build_sub_agent_prompt(self, **kwargs: Any) -> str:
        """
        为并行执行的子代理构建完整的任务提示。
        **kwargs 包含从 execute 方法传入的用于单个任务的所有参数。
        """
        task = kwargs.get("task")

        usr_init_msg_content = self.context.get("user_input") if self.context.get("user_input") else "未提供用户初始请求"
        task_content = task if task else "未提供任务描述"

        return (
            f"用户初始请求是:\n{usr_init_msg_content}\n\n"
            f"当前具体任务:\n{task_content}"
        )

    def _execute_single_task_in_thread(self, task_item: Dict[str, Any], task_index: int, results_list: list):
        from .builder import AgentConfig, build_agent
        task_for_error_log: Optional[str] = f"任务 #{task_index + 1}"

        try:
            task_details_with_index = task_item.copy()
            task_details_with_index['task_index'] = task_index
            
            full_task_prompt = self._build_sub_agent_prompt(
                **task_details_with_index
            )
            
            try:
                sub_agent_prepared_context = self._prepare_sub_agent_context(
                    **task_details_with_index
                )
            except Exception as e:
                results_list[task_index] = f"错误: {str(e)}"
                return
            
            sub_agent_instance_name = f"{self.name}_task{task_index+1}"

            sub_agent_config = AgentConfig(
                agent_class=self.agent_class_to_create,
                tool_configs=self.default_sub_agent_tool_classes,
                max_iterations=self.default_sub_agent_max_iterations,
                system_prompt=self.sub_agent_system_prompt,
                agent_instance_name=sub_agent_instance_name
            )

            sub_agent = build_agent(
                agent_config=sub_agent_config,
                context=sub_agent_prepared_context
            )
            
            result = sub_agent.run(full_task_prompt)
            results_list[task_index] = result

        except Exception as e:
            error_desc_snippet = str(task_for_error_log)[:50]
            error_string_for_result = f"错误: {self.name} 的并行子任务 #{task_index + 1} 执行失败 ({type(e).__name__}): {str(e)}"
            results_list[task_index] = error_string_for_result
            
            log_error_message = f"Error in {self.name} during parallel sub-task #{task_index + 1} (desc snippet: '{error_desc_snippet}...'): {type(e).__name__} - {str(e)}"
            logger = getattr(self, 'logger', None)
            if logger:
                logger.error(log_error_message, exc_info=True)
            else:
                print(f"ERROR in {self.name} (task #{task_index+1}): {log_error_message}")

    def execute(self, **kwargs: Any) -> str:
        tasks = self._extract_task_list(**kwargs)
        
        if not tasks:
            return json.dumps([], ensure_ascii=False)

        threads = []
        results_list = [None] * len(tasks)

        for i, task_item in enumerate(tasks):
            thread = threading.Thread(
                target=self._execute_single_task_in_thread,
                args=(task_item, i, results_list),
                name=f"SubAgent-{self.name}-{i+1}"
            )
            threads.append(thread)
            thread.start()

        for thread in threads:
            thread.join()
            
        final_results_for_json = []
        for i, task_item in enumerate(tasks):
            task_result_or_error = results_list[i]

            task_entry = {
                "task_item": task_item,
                "task_index": i + 1
            }

            if task_result_or_error is None:
                task_entry["error_details"] = "未能获取任务结果 (线程可能未正确返回值)"
            elif isinstance(task_result_or_error, str) and task_result_or_error.startswith("错误:"):
                task_entry["error_message"] = task_result_or_error
            else:
                task_entry["result"] = task_result_or_error
            
            final_results_for_json.append(task_entry)
        
        return json.dumps(final_results_for_json, ensure_ascii=False, indent=2)
