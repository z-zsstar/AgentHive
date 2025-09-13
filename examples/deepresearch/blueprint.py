import os
import traceback
import time
from typing import Optional, Dict, Any

from agenthive.base import BaseAgent
from agenthive.tools.basetool import FlexibleContext, ExecutableTool
from agenthive.core.builder import AgentConfig, build_agent, AssistantToolConfig

from websearch.blueprint import WebSearchManager
from deepresearch.models import ReportNode, ReferenceManager
from deepresearch.assistants import FocusedChapterEditor, ParallelChapterEditor
from deepresearch.tools import (
    AddItemTool,
    DeleteItemTool,
    GetNodeContentTool,
    UpdateBlockTextTool,
    SearchReportContentTool,
    WebSearchToolWrapper
)
from .util.utils import time_it

CREATOR_SYSTEM_PROMPT = """
你的核心身份：自主研究专家 (创作者Agent)
你是一位专业的、自主的深度研究报告专家。你的使命是模拟顶尖学者或行业分析师，产出一份高质量的研究报告。你必须专注于分配给你的任务范围，并对产出质量全权负责。
你的思维与哲学
批判性自我反思: 每一步行动后，反思：“我的论证严密吗？逻辑完整吗？内容是否回应了任务要求？” **更重要的是，我是否提供了超越简单信息整合的深度分析和独特见解？**
主动规划与结构化思维: 动手前，先形成清晰大纲。每次工具调用都服务于明确意图。先建结构，再填内容。
深度与洞察力: 你的价值在于深度分析，而非信息罗列。**你需要从多元视角审视问题，综合、提炼信息，并提出独到观点，挖掘深层关联和潜在影响。**
内容与格式黄金准则
块是完整的语义单元: 每个内容块应为一个完整的“思想单元”，如一整个段落。绝不为每句话创建单独的块。
专业排版: 使用标准Markdown，确保逻辑清晰、重点突出。格式要美观，避免过度添加子标题，比如某些段落不用添加二级标题。
**内容形式多样化: 在合适的时候，例如比较、总结或展示结构化数据时，请适当使用表格、列表、图等多种表现形式，以更清晰、直观地传达信息或已有知识。**
"""

REVIEWER_SYSTEM_PROMPT = """
你的核心身份：首席审阅编辑 (审阅Agent)
你是一位严谨、细致的首席审阅编辑。你的使命是你必须专注于分配给你的任务范围，并对产出质量全权负责。你的核心任务是发现问题、修正错误、并确保你所负责范围内的报告部分达到出版质量。
请从头到尾检查以下几点：
1. 宏观结构：确保摘要（如果有）在最前面，章节顺序逻辑通顺。
2. 内容连贯性：阅读内容，确保章节之间过渡自然，没有明显的逻辑断层。
3. 格式规范：检查所有章节是否都有正确的Markdown标题（例如 ## 2 章节标题），确保没有遗漏。系统会自动生成文末的参考文献列表。
4. 专业排版: 使用标准Markdown，确保逻辑清晰、重点突出。格式要美观，避免过度添加子标题，比如某些段落不用添加二级标题。
请使用你的工具进行必要的修改，直到报告完美无瑕。完成后，总结你的修改工作并结束任务。
"""

class SelfReviewingAgent(BaseAgent):
    """
    一个特殊的Agent，其工作流内置了“创作-审阅”两阶段循环。
    它会先扮演创作者完成任务，然后立即扮演审阅者来检查和修正自己的工作。
    """
    def run(self, user_input: str) -> Any:
        print(f"\n{'='*20} [SelfReviewingAgent: {self.name}] 启动 {'='*20}")
        print(f"负责范围 (workspace): '{self.context.get('workspace_node_path', 'ROOT')}'")
        print(f"初始任务: {user_input[:200]}...")

        print(f"\n--- [{self.name}] 阶段一：内容创作 ---")
        creator_agent = BaseAgent(
            llm_client=self.llm_client,
            tools=self.tool_configs,
            system_prompt=CREATOR_SYSTEM_PROMPT,
            max_iterations=self.max_iterations,
            context=self.context,
            agent_instance_name=f"{self.name}_Creator"
        )
        creator_result = creator_agent.run(user_input)
        print(f"\n--- [{self.name}] 创作阶段完成 ---")
        print(f"创作者的最终思考: {creator_result}")

        print(f"\n--- [{self.name}] 阶段二：自我审阅 ---")
        reviewer_agent = BaseAgent(
            llm_client=self.llm_client,
            tools=self.tool_configs, 
            system_prompt=REVIEWER_SYSTEM_PROMPT,
            max_iterations=self.max_iterations,
            context=self.context,
            agent_instance_name=f"{self.name}_Reviewer"
        )
        
        review_prompt = (
            "你的创作伙伴刚刚完成了以下任务的初稿：\n"
            f"--- 初始任务 ---\n{user_input}\n--- 结束 ---\n\n"
            "现在，你的任务是对**你当前工作空间内的**这部分产出进行一次彻底的审阅和修正。"
            "请检查：\n"
            "1. **格式规范**：确保章节有正确的Markdown标题。\n"
            "2. **内容完整性**：确保内容没有明显遗漏。\n"
            "3. **整体检查**：确保markdown格式正确，内容连贯，没有明显的逻辑断层。\n"
            "请使用工具进行必要的修改，直到你负责的部分完美无瑕。完成后，总结你的修改工作并结束任务。"
        )
        
        reviewer_result = reviewer_agent.run(review_prompt)
        print(f"\n--- [{self.name}] 审阅阶段完成 ---")
        print(f"审阅者的最终思考: {reviewer_result}")

        return reviewer_result

    async def arun(self, user_input: str) -> Any:
        print(f"\n{'='*20} [SelfReviewingAgent: {self.name}] 启动 (Async) {'='*20}")
        print(f"负责范围 (workspace): '{self.context.get('workspace_node_path', 'ROOT')}'")
        print(f"初始任务: {user_input[:200]}...")

        print(f"\n--- [{self.name}] 阶段一：内容创作 (Async) ---")
        creator_agent = BaseAgent(
            llm_client=self.llm_client,
            tools=self.tool_configs,
            system_prompt=CREATOR_SYSTEM_PROMPT,
            max_iterations=self.max_iterations,
            context=self.context,
            agent_instance_name=f"{self.name}_Creator"
        )
        creator_result = await creator_agent.arun(user_input)
        print(f"\n--- [{self.name}] 创作阶段完成 (Async) ---")
        print(f"创作者的最终思考: {creator_result}")

        print(f"\n--- [{self.name}] 阶段二：自我审阅 (Async) ---")
        reviewer_agent = BaseAgent(
            llm_client=self.llm_client,
            tools=self.tool_configs, 
            system_prompt=REVIEWER_SYSTEM_PROMPT,
            max_iterations=self.max_iterations,
            context=self.context,
            agent_instance_name=f"{self.name}_Reviewer"
        )
        
        review_prompt = (
            "你的创作伙伴刚刚完成了以下任务的初稿：\n"
            f"--- 初始任务 ---\n{user_input}\n--- 结束 ---\n\n"
            "现在，你的任务是对**你当前工作空间内的**这部分产出进行一次彻底的审阅和修正。"
            "请检查：\n"
            "1. **格式规范**：确保章节有正确的Markdown标题。\n"
            "2. **内容完整性**：确保内容没有明显遗漏。\n"
            "3. **整体检查**：确保markdown格式正确，内容连贯，没有明显的逻辑断层。\n"
            "请使用工具进行必要的修改，直到你负责的部分完美无瑕。完成后，总结你的修改工作并结束任务。"
        )
        
        reviewer_result = await reviewer_agent.arun(review_prompt)
        print(f"\n--- [{self.name}] 审阅阶段完成 (Async) ---")
        print(f"审阅者的最终思考: {reviewer_result}")

        return reviewer_result

class DeepResearchManager:
    """
    编排整个深度研究流程。
    它构建一个由 SelfReviewingAgent 组成的多层级、并行体系。
    """
    def __init__(self, context: Optional[FlexibleContext] = None, max_iterations: int = 50, output: str = "research/output", depth: int = 3):
        self.context = context if context is not None else FlexibleContext()
        self.max_iterations = max_iterations
        self.output = output
        self.depth = max(0, depth)

    def build_agent_config(self) -> AgentConfig:
        """
        构建嵌套的 SelfReviewingAgent 配置链（由内而外）。
        """
        print(f"--- 正在构建Agent配置链，深度为: {self.depth} ---")
        
        base_tools = [
            AddItemTool, UpdateBlockTextTool, DeleteItemTool,
            GetNodeContentTool, SearchReportContentTool, WebSearchToolWrapper,
        ]

        worker_config = AgentConfig(
            agent_class=SelfReviewingAgent,
            tool_configs=base_tools,
            max_iterations=self.max_iterations
        )

        if self.depth == 0:
            return worker_config

        current_sub_agent_config = worker_config
        for i in range(self.depth):
            print(f"正在构建第 {i+1} 层管理Agent...")
            delegation_tools = [
                AssistantToolConfig(assistant_class=ParallelChapterEditor, sub_agent_config=current_sub_agent_config),
                AssistantToolConfig(assistant_class=FocusedChapterEditor, sub_agent_config=current_sub_agent_config),
            ]
            manager_tools = base_tools + delegation_tools
            new_manager_config = AgentConfig(
                agent_class=SelfReviewingAgent,
                tool_configs=manager_tools,
                max_iterations=self.max_iterations
            )
            current_sub_agent_config = new_manager_config
            
        return current_sub_agent_config

    @time_it
    def run(self, user_input: str):
        """
        启动深度研究流程，自动保存最终报告。
        """

        self.context.set("user_input", user_input)
        self.context.set("output", self.output)
        os.makedirs(self.output, exist_ok=True)
        if self.context.get("report_tree") is None:
            self.context.set("report_tree", ReportNode(), shallow_copy=True)
        if self.context.get("reference_manager") is None:
            self.context.set("reference_manager", ReferenceManager(), shallow_copy=True)
        self.context.set("workspace_node_path", "")
        
        try:
            agent_config = self.build_agent_config()
            top_level_agent = build_agent(agent_config, self.context)
            print(f"\n--- 正在启动顶层 SelfReviewingAgent (最大深度: {self.depth}) ---")
            final_result = top_level_agent.run(user_input)
            print("\n\n" + "="*30 + " Agent运行结束 " + "="*30)
            print("\n--- 顶层Agent的最终结果 ---")
            print(final_result)
        
        except Exception as e:
            print(f"在深度研究运行过程中发生错误: {e}")
            traceback.print_exc()
        
        finally:
            report_tree = self.context.get("report_tree")
            ref_manager = self.context.get("reference_manager")
            if report_tree and ref_manager:
                print("\n--- 正在生成最终报告 ---")
                main_content_md = report_tree.to_markdown()
                references_md = ref_manager.generate_references_section()
                final_report_md = main_content_md + references_md
                report_path = os.path.join(self.output, "final_report.md")
                try:
                    with open(report_path, "w", encoding="utf-8") as f:
                        f.write(final_report_md)
                    print(f"报告已成功生成并保存至: {report_path}")
                except IOError as e:
                    print(f"错误：无法将最终报告写入 '{report_path}'. 原因: {e}")
            else:
                print("警告：无法生成最终报告，因为上下文中缺少'report_tree'或'ref_manager'。")

    @time_it
    async def arun(self, user_input: str):
        """
        Asynchronously starts the deep research process and saves the final report.
        """

        self.context.set("user_input", user_input)
        self.context.set("output", self.output)
        os.makedirs(self.output, exist_ok=True)
        if self.context.get("report_tree") is None:
            self.context.set("report_tree", ReportNode(), shallow_copy=True)
        if self.context.get("reference_manager") is None:
            self.context.set("reference_manager", ReferenceManager(), shallow_copy=True)
        self.context.set("workspace_node_path", "")
        
        try:
            agent_config = self.build_agent_config()
            top_level_agent = build_agent(agent_config, self.context)
            print(f"\n--- 正在启动顶层 SelfReviewingAgent (最大深度: {self.depth}) ---")
            final_result = await top_level_agent.arun(user_input)
            print("\n\n" + "="*30 + " Agent运行结束 " + "="*30)
            print("\n--- 顶层Agent的最终结果 ---")
            print(final_result)
        
        except Exception as e:
            print(f"在深度研究运行过程中发生错误: {e}")
            traceback.print_exc()
        
        finally:
            report_tree = self.context.get("report_tree")
            ref_manager = self.context.get("reference_manager")
            if report_tree and ref_manager:
                print("\n--- 正在生成最终报告 ---")
                main_content_md = report_tree.to_markdown()
                references_md = ref_manager.generate_references_section()
                final_report_md = main_content_md + references_md
                report_path = os.path.join(self.output, "final_report.md")
                try:
                    with open(report_path, "w", encoding="utf-8") as f:
                        f.write(final_report_md)
                    print(f"报告已成功生成并保存至: {report_path}")
                except IOError as e:
                    print(f"错误：无法将最终报告写入 '{report_path}'. 原因: {e}")
            else:
                print("警告：无法生成最终报告，因为上下文中缺少'report_tree'或'ref_manager'。")
