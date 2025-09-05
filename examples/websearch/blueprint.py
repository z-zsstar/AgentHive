import json
import base64
import traceback
from typing import List, Dict, Any, Optional, Union

from playwright.sync_api import Error as PlaywrightError
from playwright.sync_api import sync_playwright

from agenthive.base import BaseAgent, Message
from agenthive.tools.basetool import FlexibleContext, ExecutableTool
from agenthive.core.builder import build_agent, AgentConfig, AssistantToolConfig

from .scripts import MARK_PAGE_SCRIPT_CONTENT
from websearch.assistants import WebParallelAssistant
from websearch.interact import (
    SearchOnlineTool,
    NavigateTool, 
    ClickTool, 
    TypeTextTool, 
    ScrollTool, 
    GoBackTool, 
    ReadPDFContentFromURLTool
)

class WebSearchAgent(BaseAgent):
    """
    An agent that can browse the web, managing its own browser page.
    This class includes robust error handling for Playwright's race conditions
    and ensures thread-safe tool execution when used with a multi-threaded BaseAgent.
    """
    def __init__(
            self,
            context: FlexibleContext,
            max_iterations: int = 25,
            tools: Optional[List[ExecutableTool]] = None,
            system_prompt: Optional[str] = None,
            output_schema: Optional[Dict[str, Any]] = None,
            **extra_kwargs: Any
        ):
            browser_context = context.get('playwright_browser_context')
            if not browser_context:
                raise ValueError("Context must contain 'playwright_browser_context'")
            self.page = browser_context.new_page()
            context.set('playwright_page', self.page)
            tools_list = tools
            if tools_list is None:
                tools_list = [
                    SearchOnlineTool(context=context),
                    # TavilySearchTool(context=context),
                    NavigateTool(context=context),
                    ClickTool(context=context), TypeTextTool(context=context),
                    ScrollTool(context=context), GoBackTool(context=context),
                    ReadPDFContentFromURLTool(context=context)
                ]
            system_prompt = system_prompt if system_prompt else """你是一个专业的网页浏览代理。你的任务是根据用户的请求，在网页上进行浏览、搜索、点击和阅读，以全面地获取所有相关信息。在完成任务时，你必须：

1.  **全面性**: 确保你收集了所有与用户请求相关的信息，不要遗漏关键细节。
2.  **准确性**: 仔细阅读和理解网页内容，提取准确的信息。
3.  **溯源性**: 记录并返回你获取信息的具体来源URL。
4.  **总结性**: 将收集到的所有信息整合成一个完整、连贯的答案。

你的最终目标是为用户提供一个包含完整信息和来源的综合性答复。"""
            super().__init__(
                context=context, max_iterations=max_iterations, tools=tools_list,
                system_prompt=system_prompt, output_schema=output_schema, **extra_kwargs
            )

    def _format_bboxes_for_prompt(self, bboxes: List[Dict[str, Any]]) -> str:
        if not bboxes:
            return "No interactive elements were automatically identified on the page."
        descriptions = []
        for i, bbox in enumerate(bboxes):
            text = bbox.get("text", "").strip()
            el_type = bbox.get("type", "unknown")
            aria_label = bbox.get("ariaLabel", "").strip()
            description = f"[{i}] <{el_type}>"
            if text:
                description += f" Text: \"{text[:100]}{'...' if len(text) > 100 else ''}\""
            if aria_label and aria_label != text:
                description += f" AriaLabel: \"{aria_label[:100]}{'...' if len(aria_label) > 100 else ''}\""
            descriptions.append(description)
        return "Interactive elements identified on the page (with numerical labels for actions):\n" + "\n".join(descriptions)

    def _capture_visual_context(self) -> Dict[str, Any]:
        page = self.context.get('playwright_page')
        if not page or page.is_closed():
            print("Warning: Page is not available or closed...")
            return {"screenshot_base64": None, "bboxes": [], "page_text": "Page is not available or has been closed."}
        try:
            page.wait_for_load_state('networkidle', timeout=7000)
            page.evaluate(MARK_PAGE_SCRIPT_CONTENT)
            bboxes = page.evaluate("markPage()") 
            screenshot_bytes = page.screenshot(timeout=15000)
            screenshot_base64 = base64.b64encode(screenshot_bytes).decode('utf-8')
            page_text = page.inner_text('body', timeout=7000)
        except PlaywrightError as e:
            error_message = str(e)
            if "Execution context was destroyed" in error_message:
                print(f"Warning: Page was navigating during context capture. Error: {error_message}")
                return {"screenshot_base64": None, "bboxes": [], "page_text": "Could not see the page because it was navigating..."}
            else:
                print(f"Error capturing visual context (PlaywrightError): {error_message}")
                return {"screenshot_base64": None, "bboxes": [], "page_text": f"An error occurred while analyzing the page: {error_message}"}
        except Exception as e:
            print(f"An unexpected error in _capture_visual_context: {e}")
            return {"screenshot_base64": None, "bboxes": [], "page_text": f"An unexpected error occurred while analyzing the page: {e}"}
        finally:
            try:
                if not page.is_closed(): page.evaluate("unmarkPage()")
            except Exception: pass
        return {"screenshot_base64": screenshot_base64, "bboxes": bboxes or [], "page_text": page_text}



    def _prepare_llm_request_messages(self) -> List[Message]:
        if not self.messages or self.messages[0].role != 'system':
            return self.messages[:]

        system_message = self.messages[0]
        history_to_manage = self.messages[1:]
        
        managed_history = self.history_strategy.apply(history_to_manage) if self.history_strategy else history_to_manage[:]
            
        messages_for_llm: List[Dict[str, Any]] = [system_message.copy()] 
        messages_for_llm.extend([msg.copy() for msg in managed_history])

        visual_context = self._capture_visual_context()
        
        page_text = visual_context.get("page_text", "")
        bboxes = visual_context.get("bboxes", [])
        formatted_bboxes_text = self._format_bboxes_for_prompt(bboxes)
        self.context.set('current_bboxes', bboxes)


        if messages_for_llm and messages_for_llm[-1]['role'] == "user":
            last_user_message = messages_for_llm[-1]
            

            original_user_text = last_user_message['content']
            if not isinstance(original_user_text, str):
                return [Message(**msg) for msg in messages_for_llm]

            contextual_text = f"{original_user_text}"
            if page_text:
                contextual_text += f"\n\n--- Page Content ---\n{page_text}"
            contextual_text += f"\n\n--- Interactive Elements ---\n{formatted_bboxes_text}"
            

            last_user_message['content'] = contextual_text
        
        return [Message(**msg) for msg in messages_for_llm]
        
    def _execute_tool(self, tool_name: str, tool_input: Dict[str, Any]) -> str:
        """
        [OVERRIDDEN] Executes the tool directly in the current thread.
        This is crucial for compatibility with Playwright's sync API, which is not thread-safe.
        This version intentionally bypasses the multi-threaded, timeout-handling logic
        of the BaseAgent.
        """
        if tool_name not in self.tools:
            error_msg = f"Error: Tool '{tool_name}' does not exist. Available tools: {list(self.tools.keys())}"
            print(error_msg)
            return error_msg

        tool = self.tools[tool_name]
        print(f"--- Executing tool (synchronously): {tool_name} with input: {json.dumps(tool_input, ensure_ascii=False, default=str)} ---")
        
        try:
            result = tool.function(**tool_input) 
            

            tool_input_str_for_log = json.dumps(tool_input, ensure_ascii=False, default=str)
            if result is None:
                return f"Tool: {tool_name}\nParameters: {tool_input_str_for_log}\nResult:\n <No return value>"
            return f"Tool: {tool_name}\nParameters: {tool_input_str_for_log}\nResult:\n {str(result)}"
        
        except Exception as e:
            error_details = traceback.format_exc()
            print(f"Error executing tool {tool_name} synchronously:\n{error_details}")
            tool_input_str_for_log = json.dumps(tool_input, ensure_ascii=False, default=str)
            return f"Tool: {tool_name}\nParameters: {tool_input_str_for_log}\nResult:\n <Execution failed, error: {type(e).__name__}: {str(e)}>"

    def close(self):
        if hasattr(self, 'page') and self.page and not self.page.is_closed():
            self.page.close()

    def run(self, user_input: Union[str, Message]) -> Any:
        if isinstance(user_input, Message):
            initial_message_content = user_input.content
        else:
            initial_message_content = user_input
        try:
            response = super().run(user_input=initial_message_content)
            return response
        finally:
            self.close()



class WebSearchManager:
    def __init__(self, context: FlexibleContext = None, depth: int = 2):
        self.depth = depth
        self.context = context if context is not None else FlexibleContext()
        
    def _build_agent_config(self, depth: int) -> AgentConfig:

        basic_tools = [SearchOnlineTool, NavigateTool, ClickTool, TypeTextTool, ScrollTool, GoBackTool, ReadPDFContentFromURLTool
        ]

        if depth <= 0: return AgentConfig(agent_class=WebSearchAgent, tool_configs=basic_tools)
        
        sub_agent_config = self._build_agent_config(depth - 1)
        assistant_config = AssistantToolConfig(
            assistant_class=WebParallelAssistant, sub_agent_config=sub_agent_config,
            name=f"ParallelTaskProcessor_Depth_{depth}", description=f"Delegate web tasks to a level-{depth-1} assistant."
        )
        manager_tools = [assistant_config] + basic_tools
        return AgentConfig(agent_class=WebSearchAgent, tool_configs=manager_tools)
    
    def build_agent(self) -> BaseAgent:
        agent_config = self._build_agent_config(self.depth)
        return build_agent(agent_config, self.context)
    
    def run(self, initial_task: str, headless: bool = True):
        response = ""
        with sync_playwright() as p:
            try:
                browser = p.chromium.launch(
                    headless=headless,
                    args=['--no-sandbox', '--disable-setuid-sandbox', '--disable-dev-shm-usage',
                          '--disable-accelerated-2d-canvas', '--no-first-run', '--no-zygote', '--disable-gpu']
                )
            except Exception as e:
                print(f"Failed to launch browser: {e}")
                return f"Error: Could not launch the browser. Details: {e}"
            try:
                self.context.set('playwright_browser', browser)
                browser_context = browser.new_context(
                    user_agent='Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
                    viewport={'width': 1920, 'height': 1080}, ignore_https_errors=True
                )
                self.context.set('playwright_browser_context', browser_context)
                print(f"--- Building Agent Hierarchy (Depth: {self.depth}) ---")
                agent = self.build_agent()
                print(f"--- Starting Master Agent (Level {self.depth}) ---")
                initial_message = Message(role="user", content=initial_task)
                response = agent.run(initial_message)
                print("--- Agent Finished ---")
                print(f"Final Response:\n{response}")
            except Exception as e:
                print(f"An error occurred during agent execution: {e}")
                traceback.print_exc()
                response = f"An error occurred: {e}"
            finally:
                print("--- Closing Browser ---")
                if 'browser' in locals() and browser.is_connected():
                    browser.close()
        return response

if __name__ == '__main__':
    def build_agent_mock(config: AgentConfig, context: FlexibleContext) -> BaseAgent:
        tool_instances = []
        for tool_config in config.tool_configs:
            if isinstance(tool_config, AssistantToolConfig):
                tool_instance = tool_config.assistant_class(
                    sub_agent_config=tool_config.sub_agent_config, context=context,
                    name=tool_config.name, description=tool_config.description
                )
            else:
                tool_instance = tool_config(context=context)
            tool_instances.append(tool_instance)
        agent_instance = config.agent_class(context=context, tools=tool_instances)
        return agent_instance
    
    build_agent = build_agent_mock
    manager = WebSearchManager(depth=1)
    task = "Find the official websites for Playwright and Puppeteer and list their main features."
    manager.run(initial_task=task, headless=True)