import json
import base64
import traceback
import asyncio
from typing import List, Dict, Any, Optional, Union

from playwright.sync_api import sync_playwright
from playwright.async_api import async_playwright
from playwright.sync_api import Error as PlaywrightError
from playwright.async_api import Error as AsyncPlaywrightError

from agenthive.base import BaseAgent, Message
from agenthive.tools.basetool import FlexibleContext, ExecutableTool
from agenthive.core.builder import build_agent, AgentConfig, AssistantToolConfig


from .assistants import WebParallelAssistant
from .scripts import MARK_PAGE_SCRIPT_CONTENT
from .tools import NavigateTool, ClickTool, TypeTextTool, ScrollTool, GoBackTool, ReadPDFContentFromURLTool, TavilySearchTool


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
            async_browser_context = context.get('playwright_async_browser_context')
            
            if browser_context:
                # 同步模式
                self.page = browser_context.new_page()
                context.set('playwright_page', self.page)
            elif async_browser_context:
                # 异步模式 - 页面将在异步方法中创建
                self.async_browser_context = async_browser_context
                self.async_page = None
            else:
                raise ValueError("Context must contain either 'playwright_browser_context' or 'playwright_async_browser_context'")
            tools_list = tools
            if tools_list is None:
                tools_list = [
                    TavilySearchTool(context=context),
                    NavigateTool(context=context),
                    ClickTool(context=context), TypeTextTool(context=context),
                    ScrollTool(context=context), GoBackTool(context=context),
                    ReadPDFContentFromURLTool(context=context)
                ]
            system_prompt = system_prompt if system_prompt else """
你是一个专业的网络搜索代理。你的核心任务是**全面、详尽地搜集所有与用户请求相关的信息和文献**，不遗漏任何潜在有用的数据。在搜集和分析信息时，你必须做到以下几点：

**核心原则：**
1.  **信息全面性**：务必深入挖掘，从多个来源获取信息，确保覆盖所有相关方面。**搜索范围不限于中文和英文，应尽可能获取多种语言的相关信息。**
2.  **来源追溯性与可靠性**：在你的最终响应中，**必须清晰地标注所有信息的来源（URL或文献名称）**。同时，**你需要独立判断信息的权威性和可信度，优先获取并整合来自高可信度来源的信息。**
3.  **智能委托**：
    *   当你识别出PDF文档的URL时，应**优先委托助手（如果有）**来提取其内容。
    *   当需要访问特定网页以获取详细信息或与网页进行交互时，应**优先委托助手**。

**工作流程：**
1.  **理解任务**：仔细分析用户的搜索需求，明确信息搜集的目标和范围。
2.  **策略规划**：制定一个高效的搜索策略，包括关键词选择、**考虑多语言搜索**、网站访问顺序以及如何利用工具进行深度信息提取。
3.  **执行搜索**：
    *   进行广泛的关键词搜索。
    *   根据搜索结果访问相关网页。
    *   在网页上，发现更多关联链接或文档。
    *   如果发现PDF链接，使用助手提取其内容。
4.  **信息整合与分析**：对搜集到的信息进行整理、去重和分析，**并根据其权威性和可信度进行评估和优先级排序**，提炼出与用户请求最相关的部分。
5.  **生成最终响应**：以清晰、简洁的方式呈现你的发现，**并尽可能完整地返回所有相关内容，确保每条关键信息都附带了明确的来源尤其是url**。如果你无法找到足够的信息，也要明确说明。

在完成所有相关信息的搜集和整理后，使用`finish`操作并提供带有来源的最终回答。
"""
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

    async def _acapture_visual_context(self) -> Dict[str, Any]:
        """异步版本的视觉上下文捕获方法"""
        page = self.context.get('playwright_async_page')
        if not page or page.is_closed():
            print("Warning: Async page is not available or closed...")
            return {"screenshot_base64": None, "bboxes": [], "page_text": "Page is not available or has been closed."}
        try:
            await page.wait_for_load_state('networkidle', timeout=7000)
            await page.evaluate(MARK_PAGE_SCRIPT_CONTENT)
            bboxes = await page.evaluate("markPage()") 
            screenshot_bytes = await page.screenshot(timeout=15000)
            screenshot_base64 = base64.b64encode(screenshot_bytes).decode('utf-8')
            page_text = await page.inner_text('body', timeout=7000)
        except AsyncPlaywrightError as e:
            error_message = str(e)
            if "Execution context was destroyed" in error_message:
                print(f"Warning: Async page was navigating during context capture. Error: {error_message}")
                return {"screenshot_base64": None, "bboxes": [], "page_text": "Could not see the page because it was navigating..."}
            else:
                print(f"Error capturing visual context (AsyncPlaywrightError): {error_message}")
                return {"screenshot_base64": None, "bboxes": [], "page_text": f"An error occurred while analyzing the page: {error_message}"}
        except Exception as e:
            print(f"An unexpected error in _acapture_visual_context: {e}")
            return {"screenshot_base64": None, "bboxes": [], "page_text": f"An unexpected error occurred while analyzing the page: {e}"}
        finally:
            try:
                if not page.is_closed(): 
                    await page.evaluate("unmarkPage()")
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

    async def _aprepare_llm_request_messages(self) -> List[Message]:
        """异步版本的LLM请求消息准备方法"""
        if not self.messages or self.messages[0].role != 'system':
            return self.messages[:]

        system_message = self.messages[0]
        history_to_manage = self.messages[1:]
        
        managed_history = self.history_strategy.apply(history_to_manage) if self.history_strategy else history_to_manage[:]
            
        messages_for_llm: List[Dict[str, Any]] = [system_message.copy()] 
        messages_for_llm.extend([msg.copy() for msg in managed_history])

        visual_context = await self._acapture_visual_context()
        
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
            result = tool.execute(**tool_input) 
            

            tool_input_str_for_log = json.dumps(tool_input, ensure_ascii=False, default=str)
            if result is None:
                return f"Tool: {tool_name}\nParameters: {tool_input_str_for_log}\nResult:\n <No return value>"
            return f"Tool: {tool_name}\nParameters: {tool_input_str_for_log}\nResult:\n {str(result)}"
        
        except Exception as e:
            error_details = traceback.format_exc()
            print(f"Error executing tool {tool_name} synchronously:\n{error_details}")
            tool_input_str_for_log = json.dumps(tool_input, ensure_ascii=False, default=str)
            return f"Tool: {tool_name}\nParameters: {tool_input_str_for_log}\nResult:\n <Execution failed, error: {type(e).__name__}: {str(e)}>"

    async def _aexecute_tool(self, tool_name: str, tool_input: Dict[str, Any]) -> str:
        """
        异步版本的工具执行方法，直接在当前协程中执行。
        对于需要异步页面对象的工具，这确保了线程亲和性。
        """
        if tool_name not in self.tools:
            error_msg = f"Error: Tool '{tool_name}' does not exist. Available tools: {list(self.tools.keys())}"
            print(error_msg)
            return error_msg

        tool = self.tools[tool_name]
        print(f"--- Executing tool (asynchronously): {tool_name} with input: {json.dumps(tool_input, ensure_ascii=False, default=str)} ---")
        
        try:
            # Check if the tool has a native async execution method
            if hasattr(tool, 'aexecute'):
                result = await tool.aexecute(**tool_input)
            else:
                # Safely run the synchronous execute method in a separate thread
                # to avoid blocking the asyncio event loop.
                result = await asyncio.to_thread(tool.execute, **tool_input)

            await asyncio.sleep(1)  # Wait for 1 second

            tool_input_str_for_log = json.dumps(tool_input, ensure_ascii=False, default=str)
            if result is None:
                return f"Tool: {tool_name}\nParameters: {tool_input_str_for_log}\nResult:\n <No return value>"
            return f"Tool: {tool_name}\nParameters: {tool_input_str_for_log}\nResult:\n {str(result)}"
        
        except Exception as e:
            error_details = traceback.format_exc()
            print(f"Error executing tool {tool_name} asynchronously:\n{error_details}")
            tool_input_str_for_log = json.dumps(tool_input, ensure_ascii=False, default=str)
            return f"Tool: {tool_name}\nParameters: {tool_input_str_for_log}\nResult:\n <Execution failed, error: {type(e).__name__}: {str(e)}>"

    async def _ainit_async_page(self):
        """异步初始化页面"""
        if not self.async_page and hasattr(self, 'async_browser_context'):
            self.async_page = await self.async_browser_context.new_page()
            # The page object is not serializable and should always be shallow-copied.
            self.context.set('playwright_async_page', self.async_page, shallow_copy=True)

    def close(self):
        if hasattr(self, 'page') and self.page and not self.page.is_closed():
            self.page.close()
    
    async def aclose(self):
        """异步关闭页面"""
        if hasattr(self, 'async_page') and self.async_page and not self.async_page.is_closed():
            await self.async_page.close()

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

    async def arun(self, user_input: Union[str, Message] = None) -> Any:
        """异步运行方法，重写基类的arun方法以支持Playwright异步API"""
        if isinstance(user_input, Message):
            initial_message_content = user_input.content
        else:
            initial_message_content = user_input
        
        # 确保异步页面已初始化
        await self._ainit_async_page()
        
        try:
            if initial_message_content:
                self.add_message('user', initial_message_content)

            final_answer = None
            for i in range(self.max_iterations):
                print(f"\n----- [Async Iteration {i + 1}/{self.max_iterations}] (WebSearchAgent) -----")

                prompt_messages = await self._aprepare_llm_request_messages()

                max_parse_retries = 3
                parsed_response = None
                raw_response = ""
                
                for retry_count in range(max_parse_retries):
                    try:
                        output_dir = self.context.get("output")
                        response_obj = await self.get_llm_response_async(prompt_messages, output_dir=output_dir)
                        raw_response = response_obj['content']
                        print(f"LLM Raw Response (WebSearchAgent Async Iteration {i+1}, Attempt {retry_count+1}):\n{raw_response}")
                        
                        if retry_count == 0:  
                            self.add_message('assistant', raw_response)    
                        parsed_response = self._parse_llm_response(raw_response)
                        print(f"Parsed LLM Response: {json.dumps(parsed_response, indent=2, ensure_ascii=False, default=str)}")
                        
                        if "error" in parsed_response:
                            raise ValueError(f"Parsing error: {parsed_response['error']}: {parsed_response.get('message', 'Unknown error')}")
                        
                        break
                        
                    except Exception as e:
                        print(f"Response parsing failed (WebSearchAgent Async Attempt {retry_count+1}/{max_parse_retries}): {e}")
                        if retry_count < max_parse_retries - 1:  
                            format_reminder_prompt = self._get_response_format_prompt()
                            error_feedback_to_llm = f"""
Your previous response could not be parsed or validated correctly due to: {str(e)}
The raw response started with: {raw_response[:200]}...

Please strictly follow the required JSON schema and formatting instructions.
Ensure all required fields are present and the JSON is well-formed.

Required schema:
{format_reminder_prompt}

Retry generating the response.
"""
                            self.add_message('user', error_feedback_to_llm, type='parse_error')
                        else:
                            print(f"Maximum retry attempts reached, failed to parse LLM response")
                            parsed_response = {
                                "error": "parse_error_max_retries",
                                "thought": f"After {max_parse_retries} attempts, still unable to generate a valid formatted response",
                                "action": "finish",
                                "action_input": {"final_response": f"Sorry, I encountered a technical issue and couldn't process your request correctly."},
                                "status": "complete"
                            }
                
                if parsed_response is None or "error" in parsed_response:
                    print("Failed to parse LLM response, using default error response")
                    parsed_response = {
                        "thought": "Failed to parse response",
                        "action": "finish",
                        "action_input": {"final_response": "Sorry, I encountered a technical issue and couldn't process your request correctly."},
                        "status": "complete"
                    }

                action = parsed_response.get("action")
                action_input = parsed_response.get("action_input")
                status = parsed_response.get("status")  

                if status == "complete" or (action == "finish" and status != "continue"):
                    if isinstance(action_input, dict) and "final_response" in action_input:
                        final_answer = action_input["final_response"]
                    else:
                        final_answer = parsed_response
                    break 

                elif action and action != "finish" and status == "continue": 
                    if not isinstance(action_input, dict):
                         tool_result = f"Error: 'action_input' for tool '{action}' is invalid or missing (requires a dictionary), received {type(action_input)}."
                         print(tool_result)
                         self.add_message('user', tool_result, type='tool_result_error')
                    else:
                        tool_result = await self._aexecute_tool(action, action_input)
                        print(f"Tool execution result:\n{tool_result}")
                        self.add_message('user', tool_result, type='tool_result')

                else: 
                     print("Warning: LLM response format inconsistency or status mismatch with action")
                     status_mismatch = f"Error: Your response is inconsistent. If action is '{action}', status should be 'complete' if action is 'finish' else 'continue', but received '{status}'."
                     self.add_message('user', status_mismatch, type='error')
                     continue 

            else: 
                print(f"Max iterations reached ({self.max_iterations})")
                final_answer = "Max iterations reached but no answer found."
                if self.messages and self.messages[-1].role == 'assistant':
                    final_answer = self.messages[-1].content

            print(f"WebSearchAgent finished")
            return final_answer if final_answer is not None else "Sorry, I was unable to complete the request."
            
        finally:
            await self.aclose()



class WebSearchManager:
    def __init__(self, context: FlexibleContext = None, depth: int = 2):
        self.depth = depth
        self.context = context if context is not None else FlexibleContext()
        
    def _build_agent_config(self, depth: int) -> AgentConfig:

        basic_tools = [TavilySearchTool, NavigateTool, ClickTool, TypeTextTool, ScrollTool, GoBackTool, ReadPDFContentFromURLTool
        ]

        if depth <= 0: return AgentConfig(agent_class=WebSearchAgent, tool_configs=basic_tools)
        
        sub_agent_config = self._build_agent_config(depth - 1)
        assistant_config = AssistantToolConfig(
            assistant_class=WebParallelAssistant, sub_agent_config=sub_agent_config,
        )
        manager_tools = [assistant_config, TavilySearchTool, NavigateTool, ClickTool, TypeTextTool, ScrollTool, GoBackTool, ReadPDFContentFromURLTool]
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
                self.context.set('playwright_browser', browser, shallow_copy=True)
                browser_context = browser.new_context(
                    user_agent='Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
                    viewport={'width': 1920, 'height': 1080}, ignore_https_errors=True
                )
                self.context.set('playwright_browser_context', browser_context, shallow_copy=True)
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

    async def arun(self, initial_task: str, headless: bool = True):
        """异步版本的运行方法，使用Playwright异步API"""
        response = ""
        async with async_playwright() as p:
            try:
                browser = await p.chromium.launch(
                    headless=headless,
                    args=['--no-sandbox', '--disable-setuid-sandbox', '--disable-dev-shm-usage',
                          '--disable-accelerated-2d-canvas', '--no-first-run', '--no-zygote', '--disable-gpu']
                )
            except Exception as e:
                print(f"Failed to launch async browser: {e}")
                return f"Error: Could not launch the async browser. Details: {e}"
            try:
                self.context.set('playwright_async_browser', browser, shallow_copy=True)
                browser_context = await browser.new_context(
                    user_agent='Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
                    viewport={'width': 1920, 'height': 1080}, ignore_https_errors=True
                )
                self.context.set('playwright_async_browser_context', browser_context, shallow_copy=True)
                print(f"--- Building Async Agent Hierarchy (Depth: {self.depth}) ---")
                agent = self.build_agent()
                print(f"--- Starting Async Master Agent (Level {self.depth}) ---")
                initial_message = Message(role="user", content=initial_task)
                response = await agent.arun(initial_message)
                print("--- Async Agent Finished ---")
                print(f"Final Response:\n{response}")
            except Exception as e:
                print(f"An error occurred during async agent execution: {e}")
                traceback.print_exc()
                response = f"An error occurred: {e}"
            finally:
                print("--- Closing Async Browser ---")
                if browser.is_connected():
                    await browser.close()
        return response



if __name__ == '__main__':
    # The 'build_agent_mock' has been removed to ensure the actual 'build_agent' 
    # from 'agenthive.core.builder' is used, which correctly handles assistant setup.

    async def main():
        """Asynchronously runs the WebSearchManager to test the full async agent flow."""
        manager = WebSearchManager(depth=1)
        # A more comprehensive task to better test the agent's capabilities
        task = "Find the official websites for Playwright and Puppeteer, then list their main features and provide a brief comparison."
        
        print("--- [STARTING ASYNC TEST] ---")
        response = await manager.arun(initial_task=task, headless=True)
        print("\n--- [ASYNC TEST FINISHED] ---")
        print("Final response from async run:")
        print(response)

    # To run the asynchronous test, which is now the default test for this script
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nTest interrupted by user.")
