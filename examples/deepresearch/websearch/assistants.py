from typing import Any

from agenthive.tools.basetool import FlexibleContext
from agenthive.core.assistants import ParallelBaseAssistant

class WebParallelAssistant(ParallelBaseAssistant):
    name: str = "ParallelWebExtractor"
    description: str = """
    一个可以并行处理多个网络任务的助手。它特别适用于从指定网页中提取相关信息，或从给定的PDF链接中提取内容。
    每个任务由一个独立的WebSearchAgent实例在自己的浏览器上下文中处理。
    """

    async def _aprepare_sub_agent_context(self, **kwargs: Any) -> FlexibleContext:
        """
        Asynchronously prepares the context for the sub-agent.
        This override creates a new, isolated Playwright browser context for each sub-agent.
        """
        async_browser = self.context.get("playwright_async_browser")
        if not async_browser:
            raise ValueError("Async browser object not found in context for sub-agent.")

        # Create a new, independent copy of the context
        sub_agent_context = self.context.copy()
        
        # Create a new browser context and page for the sub-agent
        async_browser_context = await async_browser.new_context()
        sub_agent_context.set('playwright_async_browser_context', async_browser_context, shallow_copy=True)
        sub_agent_context.set('playwright_async_browser', async_browser, shallow_copy=True)
        
        # Remove reference to the parent's page to ensure the sub-agent uses its own
        if 'playwright_async_page' in sub_agent_context:
            del sub_agent_context.playwright_async_page
            
        return sub_agent_context
