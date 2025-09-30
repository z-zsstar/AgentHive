import os
import traceback
from typing import Optional, Any

from hivemind.base import BaseAgent
from hivemind.tools.basetool import FlexibleContext
from hivemind.core.builder import AgentConfig, build_agent, AssistantToolConfig

from util.utils import time_it
from models import ReportNode, ReferenceManager
from assistants import ChapterProducerAssistant, ParallelChapterProducerAssistant, FocusedChapterEditor
from tools import AddItemTool, DeleteItemTool, GetNodeContentTool, UpdateBlockTextTool, SearchReportContentTool

CREATOR_SYSTEM_PROMPT = """
你的核心身份：自主研究专家 (创作者Agent)
你是一位专业的、自主的深度研究报告专家。你的使命是模拟顶尖学者或行业分析师，产出一份高质量的研究报告或论文。你必须专注于分配给你的任务范围，并对产出质量全权负责。
你的思维与哲学
批判性自我反思: 每一步行动后，反思：“我的论证严密吗？逻辑完整吗？内容是否回应了任务要求？” **更重要的是，我是否提供了超越简单信息整合的深度分析和独特见解？**
主动规划与结构化思维: 动手前，先形成清晰大纲。每次工具调用都服务于明确意图。先建结构，再填内容。
深度与洞察力: 你的价值在于深度分析，而非信息罗列。**你需要从审视问题，综合、提炼信息，并提出独到观点，挖掘深层关联和潜在影响。**
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

TOP_LEVEL_SYSTEM_PROMPT = """
你的核心身份：研究报告总编辑
你是一位顶尖的研究报告总编辑。你的使命是根据用户的需求，规划、组织并最终产出一份高质量的深度研究报告。

你的工作流程：
1.  **规划 (Planning)**: 首先，深刻理解用户的核心需求。然后，构思报告的整体结构，决定需要包含哪些章节和核心论点。
2.  **委派 (Delegation)**: 使用你的 `ChapterProducer` 助手工具，将每个章节的写作任务分配出去。为每个任务提供清晰、具体的写作指引。你可以一次性分配多个任务并行处理。
3.  **整合与微调 (Integration & Refinement)**: 在所有章节初稿完成后，通读全文。使用你的编辑工具（add, update, delete）进行必要的微调，确保章节间的逻辑流畅、内容衔接自然。这个阶段只做小幅修改，不动大结构。
4.  **最终审核 (Final Review)**: 在你认为内容已经完善后，调用你的格式审核助手，对整份报告进行最后的格式检查和统一。
5.  **完成 (Finish)**: 报告完成，输出最终成果。
"""

class DeepResearchManager:
    """
    根据新的“流水线+总编”模型，编排整个深度研究流程。
    """
    def __init__(self, context: Optional[FlexibleContext] = None, max_iterations: int = 50, output: str = "output"):
        self.context = context if context is not None else FlexibleContext()
        self.max_iterations = max_iterations
        self.output = output

    def build_agent_config(self) -> AgentConfig:
        """
        构建顶层规划Agent的配置。
        """
        print("--- 正在构建总编辑 (Top-Level) Agent 配置 ---")
        creator_config = AgentConfig(
            agent_class=BaseAgent,
            tool_configs=[AddItemTool, UpdateBlockTextTool, DeleteItemTool, GetNodeContentTool],
            system_prompt=CREATOR_SYSTEM_PROMPT,
            max_iterations=30,
        )
        
        formatting_review_config = AgentConfig(
            agent_class=BaseAgent,
            tool_configs=[UpdateBlockTextTool, GetNodeContentTool],
            system_prompt=REVIEWER_SYSTEM_PROMPT,
            max_iterations=30,
        )

        top_level_tools = [
            AddItemTool,
            UpdateBlockTextTool,
            DeleteItemTool,
            GetNodeContentTool,
            AssistantToolConfig(
                assistant_class=ChapterProducerAssistant,
                sub_agent_config=creator_config,
            ),
            AssistantToolConfig(
                assistant_class=ParallelChapterProducerAssistant,
                sub_agent_config=creator_config,
            ),
            AssistantToolConfig(
                assistant_class=FocusedChapterEditor,
                sub_agent_config=formatting_review_config,
                name="Reviewer",
                description="在所有内容都撰写和微调完毕后，调用此工具对整份报告进行最终的、全局的格式检查和统一。"
            )
        ]

        top_level_config = AgentConfig(
            agent_class=BaseAgent,
            tool_configs=top_level_tools,
            system_prompt=TOP_LEVEL_SYSTEM_PROMPT,
            max_iterations=self.max_iterations
        )
        
        return top_level_config

    @time_it
    def run(self, user_input: str):
        """
        启动深度研究流程。
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
            print("\n--- 正在启动总编辑 Agent ---")
            final_result = top_level_agent.run(user_input)
            print("\n\n" + "="*30 + " Agent运行结束 " + "="*30)
            print("\n--- 总编辑Agent的结果 ---")
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
        异步启动深度研究流程。
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
            print("\n--- 正在启动总编辑 Agent (Async) ---")
            final_result = await top_level_agent.arun(user_input)
            print("\n\n" + "="*30 + " Agent运行结束 " + "="*30)
            print("\n--- 总编辑Agent的结果 ---")
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
