import os
import fitz
import aiohttp
import requests
from typing import List, Dict, Any
from googlesearch import search
from playwright.sync_api import Page, TimeoutError, Optional
from playwright.async_api import Page as AsyncPage, TimeoutError as AsyncTimeoutError

from agenthive.tools.basetool import ExecutableTool, FlexibleContext


class SearchOnlineTool(ExecutableTool):
    name: str = "search_online"
    description: str = "Searches the web for a given query and returns the top results."
    parameters: List[Dict[str, Any]] = [
        {
            "name": "query",
            "type": "string",
            "description": "The search query.",
            "required": True
        }
    ]

    def __init__(self, context: FlexibleContext = None):
        super().__init__(context)
        self.function = self.execute

    def execute(self, query: str, **kwargs) -> str:
        """
        执行网络搜索并返回格式化后的结果字符串。
        """
        try:
            search_results = search(query, num_results=5, advanced=True)
            results = []
            for r in search_results:
                results.append({
                    'title': r.title,
                    'href': r.url,
                    'body': r.description
                })
        except Exception as e:
            return f"An error occurred during the search: {e}"

        if not results:
            return "No results found for your query."

        formatted_results = []
        for i, result in enumerate(results):
            formatted_results.append(
                f"[{i}] Title: {result.get('title')}\n"
                f"   Link: {result.get('href')}\n"
                f"   Snippet: {result.get('body')}"
            )
        return "\n\n".join(formatted_results)

class TavilySearchTool(ExecutableTool):
    name: str = "tavily_search"
    description: str = "使用 Tavily 搜索引擎获取高质量、权威的搜索结果，适合需要最新信息或权威答案的场景。"
    parameters: List[Dict[str, Any]] = [
        {
            "name": "query",
            "type": "string",
            "description": "要搜索的具体问题或关键词。",
            "required": True
        }
    ]

    def __init__(self, context: FlexibleContext = None, api_key: Optional[str] = None):
        super().__init__(context)
        
        # Determine the API key with a clear priority:
        # 1. `TAVILY_API_KEY` environment variable (recommended).
        # 2. `api_key` from the `[tavily]` section in config.ini as a fallback.
        
        effective_api_key = os.environ.get('TAVILY_API_KEY')

        if not effective_api_key:
            try:
                import configparser
                import pathlib
                config = configparser.ConfigParser()
                # The config file is expected in the project root, three levels above this file
                config_path = pathlib.Path(__file__).resolve().parent.parent.parent / 'config.ini'
                if config_path.exists():
                    config.read(str(config_path), encoding='utf-8')
                    if config.has_option('tavily', 'api_key'):
                        effective_api_key = config.get('tavily', 'api_key')
            except Exception:
                pass  # Silently ignore errors in reading config file

        self.api_key = effective_api_key

    def execute(self, query: str, max_results: int = 5, **kwargs) -> str:
        if not self.api_key:
            return "Error: Tavily API key is not set. Please set TAVILY_API_KEY environment variable or pass api_key."
        url = "https://api.tavily.com/search"
        headers = {"Authorization": f"Bearer {self.api_key}"}
        params = {
            "query": query,
            "max_results": max_results
        }
        try:
            resp = requests.post(url, headers=headers, json=params, timeout=20)
            resp.raise_for_status()
            data = resp.json()
            results = data.get("results", [])
        except Exception as e:
            return f"An error occurred during Tavily search: {e}"

        if not results:
            return "No results found for your query."

        formatted_results = []
        for i, result in enumerate(results):
            formatted_results.append(
                f"[{i}] Title: {result.get('title')}\n"
                f"   Link: {result.get('url')}\n"
                f"   Snippet: {result.get('content')}"
            )
        return "\n\n".join(formatted_results)

    async def aexecute(self, query: str, max_results: int = 5, **kwargs) -> str:
        """异步版本的Tavily搜索"""
        if not self.api_key:
            return "Error: Tavily API key is not set. Please set TAVILY_API_KEY environment variable or pass api_key."
        url = "https://api.tavily.com/search"
        headers = {"Authorization": f"Bearer {self.api_key}"}
        params = {
            "query": query,
            "max_results": max_results
        }
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(url, headers=headers, json=params, timeout=aiohttp.ClientTimeout(total=20)) as resp:
                    resp.raise_for_status()
                    data = await resp.json()
                    results = data.get("results", [])
        except Exception as e:
            return f"An error occurred during Tavily search: {e}"

        if not results:
            return "No results found for your query."

        formatted_results = []
        for i, result in enumerate(results):
            formatted_results.append(
                f"[{i}] Title: {result.get('title')}\n"
                f"   Link: {result.get('url')}\n"
                f"   Snippet: {result.get('content')}"
            )
        return "\n\n".join(formatted_results)

class ReadPDFContentFromURLTool(ExecutableTool):
    name: str = "read_pdf_content"
    description: str = "Downloads a PDF from a URL, extracts its text content, and returns it. Use this when you identify a link to a PDF file."
    parameters: List[Dict[str, Any]] = [
        {
            "name": "url",
            "type": "string",
            "description": "The direct URL to the PDF file.",
            "required": True
        }
    ]

    def execute(self, url: str, **kwargs) -> str:
        """
        下载指定URL的PDF文件并提取其文本内容。
        """
        if not url.lower().endswith('.pdf'):
            return "Error: This tool is only for URLs ending in .pdf"

        try:
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
            }
            response = requests.get(url, headers=headers, timeout=30)
            response.raise_for_status()
            if 'application/pdf' not in response.headers.get('Content-Type', ''):
                return f"Error: The content at {url} is not a PDF file."
            pdf_document = fitz.open(stream=response.content, filetype="pdf")
            full_text = []
            for page_num in range(len(pdf_document)):
                page = pdf_document.load_page(page_num)
                full_text.append(page.get_text())
            pdf_document.close()
            if not full_text:
                return "Successfully downloaded the PDF, but no text could be extracted. It might be an image-based PDF."
            return "\n".join(full_text)
        except requests.exceptions.RequestException as e:
            return f"Error downloading the PDF from {url}: {e}"
        except Exception as e:
            return f"An error occurred while processing the PDF from {url}: {e}"

    async def aexecute(self, url: str, **kwargs) -> str:
        """
        异步版本的PDF内容提取
        """
        if not url.lower().endswith('.pdf'):
            return "Error: This tool is only for URLs ending in .pdf"

        try:
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
            }
            async with aiohttp.ClientSession() as session:
                async with session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=30)) as response:
                    response.raise_for_status()
                    if 'application/pdf' not in response.headers.get('Content-Type', ''):
                        return f"Error: The content at {url} is not a PDF file."
                    pdf_content = await response.read()
                    
            # PDF处理仍然是同步的，因为fitz库不支持异步
            pdf_document = fitz.open(stream=pdf_content, filetype="pdf")
            full_text = []
            for page_num in range(len(pdf_document)):
                page = pdf_document.load_page(page_num)
                full_text.append(page.get_text())
            pdf_document.close()
            if not full_text:
                return "Successfully downloaded the PDF, but no text could be extracted. It might be an image-based PDF."
            return "\n".join(full_text)
        except aiohttp.ClientError as e:
            return f"Error downloading the PDF from {url}: {e}"
        except Exception as e:
            return f"An error occurred while processing the PDF from {url}: {e}"

class NavigateTool(ExecutableTool):
    name: str = "navigate_to_url"
    description: str = "Navigates the browser to a specified URL."
    parameters: List[Dict[str, Any]] = [
        {
            "name": "url",
            "type": "string",
            "description": "The URL to navigate to.",
            "required": True
        }
    ]

    def execute(self, url: str, **kwargs) -> str:
        """
        执行页面跳转，包含超时和错误处理。
        """
        page: Page = self.context.get('playwright_page')
        if not page:
            return "Error: Playwright page not found in context."
        try:
            page.goto(url, wait_until='networkidle', timeout=30000)
            return f"Successfully navigated to {url} and the page is idle."
        except TimeoutError:
            return f"Error: Navigation to {url} failed after 30 seconds due to a timeout. The page might be too slow or blocking access."
        except Exception as e:
            return f"An unexpected error occurred during navigation to {url}: {e}"

    async def aexecute(self, url: str, **kwargs) -> str:
        """
        异步版本的页面跳转
        """
        page: AsyncPage = self.context.get('playwright_async_page')
        if not page:
            return "Error: Playwright async page not found in context."
        try:
            await page.goto(url, wait_until='networkidle', timeout=30000)
            return f"Successfully navigated to {url} and the page is idle."
        except AsyncTimeoutError:
            return f"Error: Navigation to {url} failed after 30 seconds due to a timeout. The page might be too slow or blocking access."
        except Exception as e:
            return f"An unexpected error occurred during navigation to {url}: {e}"

class ClickTool(ExecutableTool):
    name: str = "click_element"
    description: str = "Clicks on a specified element on the page, identified by its numerical label."
    parameters: List[Dict[str, Any]] = [
        {
            "name": "element_id",
            "type": "integer",
            "description": "The numerical label of the element to click.",
            "required": True
        }
    ]

    def execute(self, element_id: int, **kwargs) -> str:
        """
        点击页面上指定编号的元素。
        """
        page: Page = self.context.get('playwright_page')
        bboxes = self.context.get('current_bboxes')
        if not page or not bboxes or not (0 <= element_id < len(bboxes)):
            return f"Error: Invalid element ID {element_id}. Please choose a valid ID from the screenshot."
        bbox = bboxes[element_id]
        x, y = bbox['x'], bbox['y']
        page.mouse.click(x, y)
        try:
            # 等待点击后可能发生的导航，直到网络空闲
            page.wait_for_load_state('networkidle', timeout=10000)
        except TimeoutError:
            # 如果超时，说明可能没有发生页面跳转（例如SPA），这不是一个错误
            print("Warning: Timeout waiting for network idle after click. The page might not have navigated.")
            pass
        return f"Successfully clicked on element {element_id}."

    async def aexecute(self, element_id: int, **kwargs) -> str:
        """
        异步版本的元素点击
        """
        page: AsyncPage = self.context.get('playwright_async_page')
        bboxes = self.context.get('current_bboxes')
        if not page or not bboxes or not (0 <= element_id < len(bboxes)):
            return f"Error: Invalid element ID {element_id}. Please choose a valid ID from the screenshot."
        bbox = bboxes[element_id]
        x, y = bbox['x'], bbox['y']
        await page.mouse.click(x, y)
        try:
            # 异步等待点击后可能发生的导航
            await page.wait_for_load_state('networkidle', timeout=10000)
        except AsyncTimeoutError:
            # 超时同样不被视为错误
            print("Warning: Timeout waiting for network idle after async click. The page might not have navigated.")
            pass
        return f"Successfully clicked on element {element_id}."

class TypeTextTool(ExecutableTool):
    name: str = "type_text"
    description: str = "Types text into a specified input element."
    parameters: List[Dict[str, Any]] = [
        {
            "name": "element_id",
            "type": "integer",
            "description": "The numerical label of the input element to type into.",
            "required": True
        },
        {
            "name": "text_to_type",
            "type": "string",
            "description": "The text to be typed into the element.",
            "required": True
        }
    ]

    def execute(self, element_id: int, text_to_type: str, **kwargs) -> str:
        """
        在指定输入框中输入文本。
        """
        page: Page = self.context.get('playwright_page')
        bboxes = self.context.get('current_bboxes')
        if not page or not bboxes or not (0 <= element_id < len(bboxes)):
            return f"Error: Invalid element ID {element_id}. Please choose a valid ID from the screenshot."
        bbox = bboxes[element_id]
        x, y = bbox['x'], bbox['y']
        page.mouse.click(x, y)
        page.keyboard.type(text_to_type)
        return f"Successfully typed '{text_to_type}' into element {element_id}."

    async def aexecute(self, element_id: int, text_to_type: str, **kwargs) -> str:
        """
        异步版本的文本输入
        """
        page: AsyncPage = self.context.get('playwright_async_page')
        bboxes = self.context.get('current_bboxes')
        if not page or not bboxes or not (0 <= element_id < len(bboxes)):
            return f"Error: Invalid element ID {element_id}. Please choose a valid ID from the screenshot."
        bbox = bboxes[element_id]
        x, y = bbox['x'], bbox['y']
        await page.mouse.click(x, y)
        await page.keyboard.type(text_to_type)
        return f"Successfully typed '{text_to_type}' into element {element_id}."

class GoBackTool(ExecutableTool):
    name: str = "go_back"
    description: str = "Navigates the browser to the previous page in its history."
    parameters: List[Dict[str, Any]] = []

    def execute(self, **kwargs) -> str:
        """
        返回浏览器历史记录中的上一页。
        """
        page: Page = self.context.get('playwright_page')
        if not page:
            return "Error: Playwright page not found in context."
        page.go_back()
        page.wait_for_load_state('domcontentloaded', timeout=5000)
        return f"Successfully navigated back to the previous page: {page.url}"

    async def aexecute(self, **kwargs) -> str:
        """
        异步版本的返回上一页
        """
        page: AsyncPage = self.context.get('playwright_async_page')
        if not page:
            return "Error: Playwright async page not found in context."
        await page.go_back()
        await page.wait_for_load_state('domcontentloaded', timeout=5000)
        return f"Successfully navigated back to the previous page: {page.url}"

class ScrollTool(ExecutableTool):
    name: str = "scroll_page"
    description: str = "Scrolls the page up or down."
    parameters: List[Dict[str, Any]] = [
        {
            "name": "direction",
            "type": "string",
            "enum": ["up", "down"],
            "description": "The direction to scroll: 'up' or 'down'.",
            "required": True
        }
    ]

    def execute(self, direction: str, **kwargs) -> str:
        """
        滚动页面向上或向下。
        """
        page: Page = self.context.get('playwright_page')
        if not page:
            return "Error: Playwright page not found in context."
        if direction == 'up':
            page.evaluate("window.scrollBy(0, -window.innerHeight * 0.8)")
        else:
            page.evaluate("window.scrollBy(0, window.innerHeight * 0.8)")
        return f"Successfully scrolled the page {direction}."

    async def aexecute(self, direction: str, **kwargs) -> str:
        """
        异步版本的页面滚动
        """
        page: AsyncPage = self.context.get('playwright_async_page')
        if not page:
            return "Error: Playwright async page not found in context."
        if direction == 'up':
            await page.evaluate("window.scrollBy(0, -window.innerHeight * 0.8)")
        else:
            await page.evaluate("window.scrollBy(0, window.innerHeight * 0.8)")
        return f"Successfully scrolled the page {direction}."

class GetLinksTool(ExecutableTool):
    name: str = "get_hyperlinks"
    description: str = "Extracts all visible hyperlinks from the current page, with optional keyword filtering."
    parameters: List[Dict[str, Any]] = [
        {
            "name": "keywords",
            "type": "array",
            "items": {"type": "string"},
            "description": "Optional. A list of keywords to filter links by.",
            "required": False
        }
    ]

    def execute(self, keywords: Optional[List[str]] = None, **kwargs) -> str:
        """
        提取当前页面所有可见的超链接，可选关键词过滤。
        """
        page: Page = self.context.get('playwright_page')
        if not page:
            return "Error: Playwright page not found in context."
        link_elements = page.query_selector_all('a[href]')
        extracted_links = []
        for link_el in link_elements:
            if not link_el.is_visible():
                continue
            href = link_el.get_attribute('href')
            text = link_el.inner_text()
            if href:
                full_url = page.urljoin(href)
                if not keywords or any(kw.lower() in text.lower() or kw.lower() in full_url.lower() for kw in keywords):
                    extracted_links.append(f'- \"{text.strip()}\" -> {full_url}')
        if not extracted_links:
            keywords_str = f' matching keywords: {", ".join(keywords)}' if keywords else ''
            return f"No visible hyperlinks found{keywords_str} on {page.url}."
        return "\n".join(extracted_links)

    async def aexecute(self, keywords: Optional[List[str]] = None, **kwargs) -> str:
        """
        异步版本的超链接提取
        """
        page: AsyncPage = self.context.get('playwright_async_page')
        if not page:
            return "Error: Playwright async page not found in context."
        link_elements = await page.query_selector_all('a[href]')
        extracted_links = []
        for link_el in link_elements:
            if not await link_el.is_visible():
                continue
            href = await link_el.get_attribute('href')
            text = await link_el.inner_text()
            if href:
                full_url = page.urljoin(href)
                if not keywords or any(kw.lower() in text.lower() or kw.lower() in full_url.lower() for kw in keywords):
                    extracted_links.append(f'- \"{text.strip()}\" -> {full_url}')
        if not extracted_links:
            keywords_str = f' matching keywords: {", ".join(keywords)}' if keywords else ''
            return f"No visible hyperlinks found{keywords_str} on {page.url}."
        return "\n".join(extracted_links)

class NavigateBackTool(ExecutableTool):
    name: str = "NavigateBack"
    description: str = "Navigates to the previous page in the browser history."
    parameters: Dict[str, Any] = {}

    def execute(self) -> str:
        """
        跳转到浏览器历史记录中的上一页。
        """
        page: Page = self.context.get('playwright_page')
        if not page:
            return "Error: Playwright page not found in context."
        try:
            page.go_back(wait_until="domcontentloaded", timeout=15000)
            return f"Successfully navigated back. New URL: {page.url}"
        except Exception as e:
            return f"Error navigating back: {type(e).__name__} - {str(e)}"

    async def aexecute(self) -> str:
        """
        异步版本的返回上一页
        """
        page: AsyncPage = self.context.get('playwright_async_page')
        if not page:
            return "Error: Playwright async page not found in context."
        try:
            await page.go_back(wait_until="domcontentloaded", timeout=15000)
            return f"Successfully navigated back. New URL: {page.url}"
        except Exception as e:
            return f"Error navigating back: {type(e).__name__} - {str(e)}"

class GoToURLTool(ExecutableTool):
    name: str = "NavigateToURL"
    description: str = "Navigates the browser to a specified absolute URL."
    parameters: Dict[str, Any] = {
        "type": "object",
        "properties": {
            "url": {"type": "string", "description": "The absolute URL to navigate to (e.g., https://www.google.com)."}
        },
        "required": ["url"]
    }

    def execute(self, url: str) -> str:
        """
        跳转到指定的绝对URL。
        """
        page: Page = self.context.get('playwright_page')
        if not page:
            return "Error: Playwright page not found in context."
        if not url.startswith("http://") and not url.startswith("https://"):
            return "Error: URL must be absolute (e.g., start with http:// or https://)."
        try:
            page.goto(url, wait_until="domcontentloaded", timeout=30000)
            return f"Successfully navigated to {url}."
        except Exception as e:
            return f"Error navigating to {url}: {type(e).__name__} - {str(e)}"

    async def aexecute(self, url: str) -> str:
        """
        异步版本的URL跳转
        """
        page: AsyncPage = self.context.get('playwright_async_page')
        if not page:
            return "Error: Playwright async page not found in context."
        if not url.startswith("http://") and not url.startswith("https://"):
            return "Error: URL must be absolute (e.g., start with http:// or https://)."
        try:
            await page.goto(url, wait_until="domcontentloaded", timeout=30000)
            return f"Successfully navigated to {url}."
        except Exception as e:
            return f"Error navigating to {url}: {type(e).__name__} - {str(e)}"

