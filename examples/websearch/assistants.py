import os
import traceback
from typing import List, Dict, Any

from agenthive.tools.basetool import ExecutableTool, FlexibleContext
from agenthive.core.builder import build_agent, AgentConfig
from agenthive.base import Message


class WebParallelAssistant(ExecutableTool):
    """An assistant that can process multiple web-based tasks in parallel.
    Each task is handled by a separate WebSearchAgent instance in its own browser context.
    """
    name: str = "ParallelTaskProcessor"
    description: str = "Use this tool to process a list of web-based tasks in parallel. This is useful when you need to gather information from multiple sources or perform multiple related tasks simultaneously."
    parameters: Dict[str, Any] = {
        "type": "object",
        "properties": {
            "tasks": {
                "type": "array",
                "items": {"type": "string"},
                "description": "A list of descriptive tasks to execute in parallel."
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
