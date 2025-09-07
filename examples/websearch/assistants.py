import os
import traceback
from typing import List, Dict, Any
from agenthive.base import Message
from agenthive.core.builder import build_agent, AgentConfig
from agenthive.tools.basetool import ExecutableTool, FlexibleContext


class WebParallelAssistant(ExecutableTool):
    """An assistant that can process multiple web-based tasks in parallel.
    Each task is handled by a separate WebSearchAgent instance in its own browser context.
    """
    name: str = "ParallelWebExtractor"
    description: str = """
    一个可以并行处理多个网络任务的助手。它特别适用于从指定网页中提取相关信息，或从给定的PDF链接中提取内容。
    每个任务由一个独立的WebSearchAgent实例在自己的浏览器上下文中处理。
    """
    parameters: Dict[str, Any] = {
        "type": "object",
        "properties": {
            "tasks": {
                "type": "array",
                "items": {"type": "string"},
                "description": "一个描述性任务列表，用于并行执行。每个任务字符串必须明确包含要访问的URL（网页或PDF链接），并指明需要提取的具体信息。"
            }
        },
        "required": ["tasks"]
    }

    def __init__(self, sub_agent_config: AgentConfig, context: FlexibleContext, **kwargs: Any):
        super().__init__(context=context)
        self.sub_agent_config = sub_agent_config

    def execute(self, **kwargs: Any) -> List[Dict[str, Any]]:
        """Executes a list of tasks in parallel, each with its own agent and browser context."""
        results = []
        browser = self.context.get("playwright_browser")
        output_dir = self.context.get("output")
        if not browser:
            raise ValueError("Browser object not found in context. The assistant requires a running Playwright browser.")

        for task in kwargs.get("tasks", []):
            browser_context = None
            try:

                browser_context = browser.new_context()
                sub_agent_context = FlexibleContext()
                sub_agent_context.set("output", os.path.join(output_dir, 'webassistant'))
                sub_agent_context.set('playwright_browser_context', browser_context)
                sub_agent_context.set('playwright_browser', browser)

                sub_agent = build_agent(self.sub_agent_config, sub_agent_context)

                initial_message = Message(role="user", content=task)
                response = sub_agent.run(initial_message)
                results.append({"task": task, "result": response})

            except Exception as e:
                error_message = f"Error processing task '{task}': {traceback.format_exc()}"
                print(error_message)
                results.append({"task": task, "error": str(e)})
            finally:
                if browser_context:
                    browser_context.close()
        
        return results
