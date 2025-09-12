import re
import json
import traceback
from typing import Optional, List, Any, Dict

from agenthive.tools.basetool import FlexibleContext
from deepresearch.models import ReportNode,ReferenceManager
from agenthive.core.builder import AgentConfig, build_agent
from agenthive.core.assistants import BaseAssistant, ParallelBaseAssistant

class FocusedChapterEditor(BaseAssistant):
    """
    一个专注于单个章节的助手。它会自动创建不存在的章节，
    然后将一个具体的、深入的写作或编辑任务委托给子代理。
    这是处理单个报告部分的标准工具。
    """
    name = "FocusedChapterEditor"
    description = (
        "专注于单个章节进行详细编辑。**如果章节不存在，将自动创建。** "
        "使用此工具为一个章节委托具体的写作任务（例如，起草、重写、扩展）。"
    )
    
    parameters = {
        "type": "object", 
        "properties": {
            "chapter_path": {
                "type": "string", 
                "description": "目标章节的确切数字路径。如果不存在，将被创建。"
            }, 
            "task_description": {
                "type": "string", 
                "description": "为子代理准备的详细写作或编辑任务描述。"
            }
        }, 
        "required": ["chapter_path", "task_description"]
    }

    def _prepare_sub_agent_context(self, **task_details: Any) -> FlexibleContext:
        sub_agent_context = FlexibleContext()

        report_tree: Optional[ReportNode] = self.context.get("report_tree")
        ref_manager: Optional[ReferenceManager] = self.context.get("reference_manager")
        user_input: str = self.context.get("user_input", "")
        output_dir: str = self.context.get("output", "research/output")

        sub_agent_context.set("report_tree", report_tree)
        sub_agent_context.set("reference_manager", ref_manager)
        sub_agent_context.set("user_input", user_input)
        sub_agent_context.set("output", output_dir)

        chapter_path = task_details.get("chapter_path")
        self_path = self.context.get("workspace_node_path", "")

        if not chapter_path:
             raise ValueError("错误：'chapter_path' 不能为空。")
        if not re.match(r'^\d+(-\d+)*$', chapter_path):
            raise ValueError(f"错误：'chapter_path' 格式无效 '{chapter_path}'。必须是 '1' 或 '2-1' 这样的格式。")
        if chapter_path == self_path:
             raise ValueError(f"错误：检测到逻辑循环。不能将任务委托给你自己所在的章节 '{self_path}'。")
        if self_path and not chapter_path.startswith(f"{self_path}-"):
             raise ValueError(f"错误：权限被拒绝。你的工作区是 '{self_path}'，只能委托给其直接的子章节。")
        if not isinstance(report_tree, ReportNode):
            raise ValueError("错误：上下文中未找到 'report_tree'。")

        target_node = report_tree.get_node_by_path(chapter_path)
        if target_node is None:
            print(f"信息：章节 '{chapter_path}' 不存在，正在尝试创建...")
            path_parts = chapter_path.split('-')
            parent_path = "-".join(path_parts[:-1]) if len(path_parts) > 1 else ""
            parent_node = report_tree.get_node_by_path(parent_path)

            if not parent_node:
                raise ValueError(f"错误：无法创建章节 '{chapter_path}'，因为其父章节 '{parent_path}' 也不存在。")
            
            new_chapter_node = ReportNode(parent=parent_node)
            parent_node.add_item(new_chapter_node)
            
            if new_chapter_node.path != chapter_path:
                 print(f"警告：创建的节点路径 '{new_chapter_node.path}' 与目标路径 '{chapter_path}' 不符。这可能在非顺序创建时发生，通常是正常的。")
            
            print(f"信息：已成功创建新章节，其路径为：'{new_chapter_node.path}'。")

        sub_agent_context.set("workspace_node_path", chapter_path)
        
        return sub_agent_context

    def _build_sub_agent_prompt(self, **task_details: Any) -> str:
        chapter_path = task_details.get("chapter_path", "未知")
        task_description = task_details.get("task_description", "未提供")
        overall_goal = self.context.get("user_input", "未提供")
        return (
            f"用户的总体请求是：{overall_goal}\n\n"
            f"你的具体职责是管理章节 **{chapter_path}** 内的内容。\n\n"
            f"你当前的任务是：**{task_description}**\n\n"
            "请先分析你章节的当前状态，然后执行任务。"
        )

    def execute(self, **kwargs: Any) -> str:
        task_for_error_log: Optional[str] = f"Chapter: {kwargs.get('chapter_path')}"
        try:
            sub_agent_prepared_context = self._prepare_sub_agent_context(**kwargs)
            task_prompt = self._build_sub_agent_prompt(**kwargs)
            sub_agent_instance_name = f"{self.name}_sub_{kwargs.get('chapter_path', 'agent')}"
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
            return sub_agent.run(task_prompt)
        except Exception as e:
            traceback.print_exc()
            error_message = f"错误: {self.name} 在执行子任务时失败 ({task_for_error_log}): {type(e).__name__} - {e}"
            return error_message

    async def aexecute(self, **kwargs: Any) -> str:
        task_for_error_log: Optional[str] = f"Chapter: {kwargs.get('chapter_path')}"
        try:
            sub_agent_prepared_context = self._prepare_sub_agent_context(**kwargs)
            task_prompt = self._build_sub_agent_prompt(**kwargs)
            sub_agent_instance_name = f"{self.name}_sub_{kwargs.get('chapter_path', 'agent')}"
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
            return await sub_agent.arun(task_prompt)
        except Exception as e:
            traceback.print_exc()
            error_message = f"错误: {self.name} 在执行子任务时失败 ({task_for_error_log}): {type(e).__name__} - {e}"
            return error_message

class ParallelChapterEditor(ParallelBaseAssistant):
    name = "ParallelChapterEditor"
    description = (
        "将多个写作任务委托给不同章节并行执行。"
        "**如果章节不存在，将自动创建。** "
        "用于高效地搭建报告的主体结构。"
    )
    
    parameters = {
        "type": "object", 
        "properties": {
            "chapters": {
                "type": "array", 
                "items": {
                    "type": "object", 
                    "properties": {
                        "chapter_path": {
                            "type": "string",
                            "description": "目标章节的确切数字路径。如果不存在将被创建。"
                        },
                        "task_description": {
                            "type": "string",
                            "description": "分配给该章节子代理的具体写作或编辑任务。"
                        }
                    }, 
                    "required": ["chapter_path", "task_description"]
                }
            }
        }, 
        "required": ["chapters"]
    }

    def _extract_task_list(self, **kwargs: Any) -> List[Dict[str, Any]]:
        return kwargs.get("chapters", [])

    _prepare_sub_agent_context = FocusedChapterEditor._prepare_sub_agent_context
    _build_sub_agent_prompt = FocusedChapterEditor._build_sub_agent_prompt

    def execute(self, **kwargs: Any) -> str:
        tasks = self._extract_task_list(**kwargs)
        if not tasks: 
            return json.dumps([], ensure_ascii=False)
        paths = [task.get("chapter_path") for task in tasks if task.get("chapter_path")]
        if len(paths) != len(set(paths)):
            return "错误：在并行任务列表中检测到重复的 'chapter_path'。每个并行章节任务必须针对一个唯一的路径。"
        return super().execute(**kwargs)

    async def aexecute(self, **kwargs: Any) -> str:
        tasks = self._extract_task_list(**kwargs)
        if not tasks: 
            return json.dumps([], ensure_ascii=False)
        paths = [task.get("chapter_path") for task in tasks if task.get("chapter_path")]
        if len(paths) != len(set(paths)):
            return "错误：在并行任务列表中检测到重复的 'chapter_path'。每个并行章节任务必须针对一个唯一的路径。"
        return await super().aexecute(**kwargs)
