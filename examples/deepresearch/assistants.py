import re
import json
import asyncio
import traceback
from typing import Optional, List, Any, Dict

from agenthive.base import BaseAgent
from agenthive.tools.basetool import FlexibleContext
from agenthive.core.assistants import BaseAssistant, ParallelBaseAssistant
from agenthive.core.builder import AgentConfig, AssistantToolConfig, build_agent


from models import ReportNode, ReferenceManager


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
                "description": "目标章节的确切数字路径 (例如 '1', '2-1')。使用 '.' 来代表整个报告的根目录。"
            }, 
            "task_description": {
                "type": "string", 
                "description": "为子代理准备的详细写作或编辑任务描述。"
            }
        }, 
        "required": ["chapter_path", "task_description"]
    }

    def _prepare_sub_agent_context(self, **task_details: Any) -> FlexibleContext:
        sub_agent_context = self.context.copy()

        report_tree: Optional[ReportNode] = sub_agent_context.get("report_tree")

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


class ResearchAssistant(BaseAssistant):
    """
    一个专门的研究助手（思想层，L2）。
    它接收一个研究任务，使用内部的搜索代理来获取和提炼信息，
    然后返回结构化的观点或数据。它本身不负责写入报告。
    """
    name = "ResearchAssistant"
    description = (
        "一个专门的研究助手，当你需要编撰需要创新或者深度的内容时，请使用此工具。"
        "它会进行网络搜索和分析，更重要的是从多元思维角度和第一性原理出发，和你进行讨论。请提供一个清晰、具体的观点和想法。"
        "不要进行任何与任务无关的对话或评论。"
    )
    
    parameters = {
        "type": "object", 
        "properties": {
            "research_task": {
                "type": "string", 
                "description": "需要研究的具体观点和想法。"
            }
        }, 
        "required": ["research_task"]
    }

    def _prepare_sub_agent_context(self, **kwargs: Any) -> FlexibleContext:
        """为研究代理准备上下文。"""
        return self.context.copy()

    def _build_sub_agent_prompt(self, **kwargs: Any) -> str:
        """为研究代理构建提示 (用户输入)。"""
        research_task = kwargs.get("research_task", "未提供观点和想法")
        overall_goal = self.context.get("user_input", "未提供")
        return (
            f"我们的总体研究目标是：'{overall_goal}'。\n\n"
            f"针对这个目标，我正在撰写一个章节，现在需要和你深入探讨以下具体内容：\n"
            f"**'{research_task}'**\n\n"
            "请开始你的分析。"
        )
    
    @staticmethod
    def _get_system_prompt() -> str:
        """为研究子代理构建系统提示词。"""
        return (
            "你的身份是一位研究伙伴和思想上的辩论者。你的核心方法论是从第一性原理出发进行思考。\n\n"
            "你的职责是：\n"
            "1. **专注讨论**: 你的所有分析和讨论都必须严格围绕当前作家（你的上级）提出的具体内容展开。\n"
            "2. **深度思考**: 不要仅仅罗列信息。你需要对观点进行解构，从根本原则出发，提供深刻的见解、创新的角度或潜在的挑战。\n"
            "3. **善用工具**: 你可以随时使用网络搜索工具来获取外部信息，也可以使用获取章节内容工具来理解上下文、参考其他章节或避免重复工作。\n"
            "4. **输出**: 你的输出应该是结构清晰、逻辑严密的分析和观点，作为高质量写作的核心素材。"
        )

    def execute(self, **kwargs: Any) -> str:
        """执行研究任务。"""
        from tools import WebSearchToolWrapper, GetNodeContentTool
        try:
            context = self._prepare_sub_agent_context(**kwargs)
            prompt = self._build_sub_agent_prompt(**kwargs)
            system_prompt = self._get_system_prompt()
            
            researcher_config = AgentConfig(
                agent_class=BaseAgent,
                tool_configs=[WebSearchToolWrapper, GetNodeContentTool],
                system_prompt=system_prompt,
                max_iterations=25, 
            )
            researcher_agent = build_agent(researcher_config, context)
            
            result = researcher_agent.run(prompt)
            return f"研究结果：\n{result}"

        except Exception as e:
            traceback.print_exc()
            error_message = f"错误: {self.name} 在执行研究任务时失败: {type(e).__name__} - {e}"
            return error_message

    async def aexecute(self, **kwargs: Any) -> str:
        """异步执行研究任务。"""
        from tools import WebSearchToolWrapper, GetNodeContentTool
        try:
            context = self._prepare_sub_agent_context(**kwargs)
            prompt = self._build_sub_agent_prompt(**kwargs)
            system_prompt = self._get_system_prompt()
            
            researcher_config = AgentConfig(
                agent_class=BaseAgent,
                tool_configs=[WebSearchToolWrapper, GetNodeContentTool],
                system_prompt=system_prompt,
                max_iterations=25,
            )
            researcher_agent = build_agent(researcher_config, context)
            
            result = await researcher_agent.arun(prompt)
            return f"研究结果：\n{result}"

        except Exception as e:
            traceback.print_exc()
            error_message = f"错误: {self.name} 在执行研究任务时失败: {type(e).__name__} - {e}"
            return error_message


class ChapterProducerAssistant(BaseAssistant):
    """
    一个完整的章节生产单元。它接收一个高层级的写作任务，
    并编排内部的“写作-格式审核”流水线来完成该任务。
    """
    name = "ChapterProducer"
    description = "启动一个完整的生产流程来撰写或重写一个章节。请提供章节路径和详细的写作任务。"

    parameters = {
        "type": "object",
        "properties": {
            "chapter_path": {
                "type": "string",
                "description": "目标章节的确切数字路径。如果不存在，将被创建。"
            },
            "task_description": {
                "type": "string",
                "description": "对要完成的写作任务的详细、清晰的描述。"
            }
        },
        "required": ["chapter_path", "task_description"]
    }

    _prepare_sub_agent_context = FocusedChapterEditor._prepare_sub_agent_context

    def execute(self, **kwargs: Any) -> str:
        from tools import AddItemTool, UpdateBlockTextTool, DeleteItemTool, GetNodeContentTool, WebSearchToolWrapper
        from blueprint import CREATOR_SYSTEM_PROMPT, REVIEWER_SYSTEM_PROMPT

        chapter_path = kwargs.get("chapter_path")
        task_description = kwargs.get("task_description")
        overall_goal = self.context.get("user_input", "未提供")
        print(f"\n--- [ChapterProducer] 开始制作章节 '{chapter_path}' ---")

        try:
            # --- 阶段一：内容创作 (L1作家 + L2研究员) ---
            print(f"--- [ChapterProducer] 阶段 1/2: 内容创作 ---")
            writing_context = self._prepare_sub_agent_context(**kwargs)

            researcher_sub_agent_config = AgentConfig(
                agent_class=BaseAgent,
                tool_configs=[WebSearchToolWrapper, GetNodeContentTool],
                system_prompt=ResearchAssistant._get_system_prompt(),
                max_iterations=25,
            )
            
            writing_agent_config = AgentConfig(
                agent_class=BaseAgent,
                tool_configs=[
                    AddItemTool, UpdateBlockTextTool, DeleteItemTool, GetNodeContentTool,
                    AssistantToolConfig(
                        assistant_class=ResearchAssistant,
                        sub_agent_config=researcher_sub_agent_config
                    )
                ],
                system_prompt=CREATOR_SYSTEM_PROMPT,
                max_iterations=self.default_sub_agent_max_iterations or 40,
            )
            writing_agent = build_agent(writing_agent_config, writing_context)
            
            writing_prompt = (
                f"用户的总体请求是：{overall_goal}\n\n"
                f"你的任务是撰写章节 **{chapter_path}** 的内容。\n"
                f"具体要求：**{task_description}**\n"
                "请使用你的写作工具完成初稿。如果需要深度思考或外部信息，请调用你的研究助手。"
            )
            draft_result = writing_agent.run(writing_prompt)
            print(f"--- [ChapterProducer] 创作完成。产出: {draft_result}...")

            # --- 阶段二：格式审核 ---
            print(f"--- [ChapterProducer] 阶段 2/2: 格式审核 ---")
            formatting_context = self._prepare_sub_agent_context(**kwargs)
            
            formatting_agent_config = AgentConfig(
                agent_class=BaseAgent,
                tool_configs=[UpdateBlockTextTool, GetNodeContentTool],
                system_prompt=REVIEWER_SYSTEM_PROMPT,
                max_iterations=15,
            )
            formatting_agent = build_agent(formatting_agent_config, formatting_context)

            formatting_prompt = (
                f"你的上级（作家Agent）刚刚完成了关于 '{overall_goal}' 报告中章节 **{chapter_path}** 的初稿。\n"
                f"现在，你需要检查并修正该章节的Markdown格式。完成后，请说'格式修正完毕'。"
            )
            formatting_agent.run(formatting_prompt)
            
            print(f"--- [ChapterProducer] 章节 '{chapter_path}' 制作完成 ---")
            return f"章节 '{chapter_path}' 已成功生成并通过格式审核。最终内容节选: {draft_result}..."

        except Exception as e:
            traceback.print_exc()
            return f"错误: ChapterProducer 在制作章节 '{chapter_path}' 时失败: {e}"

    async def aexecute(self, **kwargs: Any) -> str:
        from tools import AddItemTool, UpdateBlockTextTool, DeleteItemTool, GetNodeContentTool, WebSearchToolWrapper
        from blueprint import CREATOR_SYSTEM_PROMPT, REVIEWER_SYSTEM_PROMPT

        chapter_path = kwargs.get("chapter_path")
        task_description = kwargs.get("task_description")
        overall_goal = self.context.get("user_input", "未提供")
        print(f"\n--- [ChapterProducer] 开始异步制作章节 '{chapter_path}' ---")

        try:
            # --- 阶段一：内容创作 (L1作家 + L2研究员) ---
            print(f"--- [ChapterProducer] 阶段 1/2: 内容创作 (异步) ---")
            writing_context = self._prepare_sub_agent_context(**kwargs)

            researcher_sub_agent_config = AgentConfig(
                agent_class=BaseAgent,
                tool_configs=[WebSearchToolWrapper, GetNodeContentTool],
                system_prompt=ResearchAssistant._get_system_prompt(),
                max_iterations=25,
            )
            
            writing_agent_config = AgentConfig(
                agent_class=BaseAgent,
                tool_configs=[
                    AddItemTool, UpdateBlockTextTool, DeleteItemTool, GetNodeContentTool,
                    AssistantToolConfig(
                        assistant_class=ResearchAssistant,
                        sub_agent_config=researcher_sub_agent_config
                    )
                ],
                system_prompt=CREATOR_SYSTEM_PROMPT,
                max_iterations=self.default_sub_agent_max_iterations or 40,
            )
            writing_agent = build_agent(writing_agent_config, writing_context)
            
            writing_prompt = (
                f"用户的总体请求是：{overall_goal}\n\n"
                f"你的任务是撰写章节 **{chapter_path}** 的内容。\n"
                f"具体要求：**{task_description}**\n"
                "请使用你的写作工具完成初稿。如果需要深度思考或外部信息，请调用你的研究助手。"
            )
            draft_result = await writing_agent.arun(writing_prompt)
            print(f"--- [ChapterProducer] 创作完成。产出: {draft_result}...")

            # --- 阶段二：格式审核 ---
            print(f"--- [ChapterProducer] 阶段 2/2: 格式审核 (异步) ---")
            formatting_context = self._prepare_sub_agent_context(**kwargs)
            
            formatting_agent_config = AgentConfig(
                agent_class=BaseAgent,
                tool_configs=[UpdateBlockTextTool, GetNodeContentTool],
                system_prompt=REVIEWER_SYSTEM_PROMPT,
                max_iterations=15,
            )
            formatting_agent = build_agent(formatting_agent_config, formatting_context)

            formatting_prompt = (
                f"你的上级（作家Agent）刚刚完成了关于 '{overall_goal}' 报告中章节 **{chapter_path}** 的初稿。\n"
                f"现在，你需要检查并修正该章节的Markdown格式。完成后，请说'格式修正完毕'。"
            )
            await formatting_agent.arun(formatting_prompt)
            
            print(f"--- [ChapterProducer] 章节 '{chapter_path}' 制作完成 ---")
            return f"章节 '{chapter_path}' 已成功生成并通过格式审核。最终内容节选: {draft_result}..."

        except Exception as e:
            traceback.print_exc()
            return f"错误: ChapterProducer 在制作章节 '{chapter_path}' 时失败: {e}"


class ParallelChapterProducerAssistant(ParallelBaseAssistant):
    name = "ParallelChapterProducer"
    description = "并行启动多个完整的生产流程，同时撰写或重写多个章节。用于高效搭建报告主体。"

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

    def __init__(self, context: FlexibleContext, **kwargs):
        # 关键：将内部的执行单元定义为 ChapterProducerAssistant
        # 但我们不能直接实例化它，而是通过构建一个临时的Agent来运行它
        # 这里我们将通过重写 _execute_single_task_in_thread 来实现
        super().__init__(context=context, **kwargs)

    def _extract_task_list(self, **kwargs: Any) -> List[Dict[str, Any]]:
        return kwargs.get("chapters", [])

    def _execute_single_task_in_thread(self, task_item: Dict[str, Any], task_index: int, results_list: list):
        # 这是并行执行的核心。我们为每个任务实例化一个ChapterProducerAssistant并执行它。
        try:
            producer = ChapterProducerAssistant(context=self.context)
            result = producer.execute(**task_item)
            results_list[task_index] = result
        except Exception as e:
            error_message = f"并行任务 #{task_index + 1} (章节 {task_item.get('chapter_path')}) 失败: {e}"
            traceback.print_exc()
            results_list[task_index] = error_message
    
    async def _aexecute_single_task(self, task_item: Dict[str, Any], task_index: int):
        # 异步版本的实现
        try:
            producer = ChapterProducerAssistant(context=self.context)
            # ChapterProducerAssistant 现在有了一个合适的 aexecute 方法，我们可以直接调用它。
            result = await producer.aexecute(**task_item)
            return result
        except Exception as e:
            error_message = f"并行任务 #{task_index + 1} (章节 {task_item.get('chapter_path')}) 失败: {e}"
            traceback.print_exc()
            return error_message
    
    @staticmethod
    def _get_system_prompt() -> str:
        """为研究子代理构建系统提示词。"""
        return (
            "你的身份是一位研究伙伴和思想上的辩论者。你的核心方法论是从第一性原理出发进行思考。\n\n"
            "你的职责是：\n"
            "1. **专注讨论**: 你的所有分析和讨论都必须严格围绕当前作家（你的上级）提出的具体内容展开。\n"
            "2. **深度思考**: 不要仅仅罗列信息。你需要对观点进行解构，从根本原则出发，提供深刻的见解、创新的角度或潜在的挑战。\n"
            "3. **善用工具**: 你可以随时使用网络搜索工具来获取外部信息，也可以使用获取章节内容工具来理解上下文、参考其他章节或避免重复工作。\n"
            "4. **输出**: 你的输出应该是结构清晰、逻辑严密的分析和观点，作为高质量写作的核心素材。"
        )