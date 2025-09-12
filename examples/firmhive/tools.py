import os
import json
import shlex
import r2pipe
import requests
import traceback
import subprocess
from typing import Dict, Any, Optional, List
from agenthive.tools.basetool import ExecutableTool, FlexibleContext


class DockerTool:
    def __init__(self, context: Optional[FlexibleContext] = None):
        self.context = context or FlexibleContext()
        self.container_id = self.context.get("container_id")
        self.timeout = 180

    def execute_in_container(self, command: str) -> str:
        if not self.container_id:
            return "[Error] Docker container not found. The container_id is missing from the context."

        base_path = self.context.get("base_path")
        current_dir = self.context.get("current_dir")
        if not base_path or not current_dir:
            return "[Error] base_path or current_dir not in context."

        if not os.path.normpath(current_dir).startswith(os.path.normpath(base_path)):
             return f"[Security Error] The current working directory '{current_dir}' is not within the firmware root directory '{base_path}'."

        relative_dir = os.path.relpath(current_dir, base_path)
        container_dir = os.path.join("/firmware", relative_dir)

        docker_command = ["docker", "exec", "-w", container_dir, self.container_id] + shlex.split(command)

        try:
            result = subprocess.run(
                docker_command,
                shell=False,
                capture_output=True,
                text=True,
                timeout=self.timeout,
                check=False,
                encoding='utf-8',
                errors='ignore'
            )
            output = f"Exit Code: {result.returncode}\n"
            if result.stdout:
                output += f"Stdout:\n{result.stdout}\n"
            if result.stderr:
                output += f"Stderr:\n{result.stderr}\n"
            return output
        except subprocess.TimeoutExpired:
            return f"[Error] Command '{command[:100]}...' timed out after {self.timeout}s in container."
        except Exception as e:
            return f"[Error] Command '{command[:100]}...' failed to execute in container: {e}"


class GetContextInfoTool(ExecutableTool):
    name = "get_context_info"
    description = "Get context information for the current analysis task, such as the file or directory being analyzed."
    parameters: Dict[str, Any] = {
        "type": "object",
        "properties": {},
        "required": []
    }

    def execute(self) -> str:
        file_path = self.context.get("file_path")
        current_dir = self.context.get("current_dir")
        base_path = self.context.get("base_path")
        file_name_str = os.path.basename(file_path) if file_path else "Not specified"
        dir_name_str = os.path.basename(current_dir) if current_dir else "Not specified"
        rel_dir_path = os.path.relpath(current_dir, base_path) if current_dir and base_path else "Not specified"
        
        return (
            f"Current analysis focus:\n"
            f"- File: {file_name_str}\n"
            f"- Directory: {dir_name_str}\n"
            f"- Directory path relative to firmware root: {rel_dir_path}"
        )  

class ShellExecutorTool(ExecutableTool, DockerTool):
    name = "execute_shell"
    timeout = 180

    def __init__(self, context: Optional[FlexibleContext] = None):
        ExecutableTool.__init__(self, context)
        DockerTool.__init__(self, context)
        file_path = self.context.get("file_path", "Not specified")
        file_name = os.path.basename(file_path) if file_path else "Not specified"
        current_dir = self.context.get("current_dir", "Not specified")

        self.description = f"""Execute shell commands in a secure containerized environment for the current directory ({os.path.basename(current_dir)}). The current analysis focus is on the file: {file_name}.
    **Note:** All commands are executed inside a Docker container with the firmware mounted at /firmware. Commands are sandboxed for security."""

        self.parameters = {
            "type": "object",
            "properties": {
                "command": {
                    "type": "string",
                    "description": f"The shell command to execute. The command will be executed in the '{os.path.basename(current_dir)}' directory inside the container."
                }
            },
            "required": ["command"]
        }

    def _resolve_path(self, path: str, working_dir: str) -> Optional[str]:
        """
        将输入路径解析为当前工作目录内的真实绝对路径。
        如果路径有效且在工作目录内，则返回其真实路径，否则返回None。
        此方法可以处理符号链接，并防止目录逃逸。
        """
        # 禁止使用绝对路径（除了当前目录 '.'）
        if os.path.isabs(path):
            return None

        # 获取工作目录的真实路径
        real_working_dir = os.path.realpath(working_dir)
        
        # 处理特殊情况：当前目录
        if path == '.':
            return real_working_dir
            
        # 构建目标路径并解析
        prospective_path = os.path.join(real_working_dir, path)
        real_prospective_path = os.path.realpath(prospective_path)

        # 检查最终路径是否在工作目录之内
        if real_prospective_path.startswith(real_working_dir + os.sep) or real_prospective_path == real_working_dir:
            return real_prospective_path
        
        return None

    def _is_safe_command(self, command: str) -> tuple[bool, str]:
        if not command or not command.strip():
            return False, "命令不能为空。"
        
        base_path = self.context.get("base_path")
        current_dir = self.context.get("current_dir")

        if not base_path or not os.path.isdir(os.path.normpath(base_path)):
            return False, "[安全错误] 上下文中未提供有效的固件根目录 (base_path)。"
        if not current_dir or not os.path.isdir(os.path.normpath(current_dir)):
            return False, "[安全错误] 上下文中未提供有效的工作目录 (current_dir)。"
        
        # 确保 current_dir 在 base_path 内部
        norm_current_dir = os.path.normpath(current_dir)
        norm_base_path = os.path.normpath(base_path)
        if not norm_current_dir.startswith(norm_base_path):
            return False, f"[安全错误] 当前工作目录 '{current_dir}' 不在固件根目录 '{base_path}' 内。"

        try:
            tokens = shlex.split(command)
        except ValueError as e:
            return False, f"命令解析失败: {e}。"
        
        if not tokens:
            return False, "无效的命令。"
        
        # --- 路径验证逻辑 ---
        # 检查所有可能的路径参数，确保它们都在当前工作目录内
        for token in tokens[1:]:
            # 跳过明显的选项参数
            if token.startswith('-'):
                continue
            
            # 检查是否看起来像路径
            is_path_like = (
                # 包含路径分隔符
                '/' in token or '\\' in token or
                # 是特殊目录标识符
                token in ['.', '..'] or
                # 包含文件扩展名
                any(token.endswith(ext) for ext in ['.txt', '.bin', '.so', '.elf', '.img', '.gz', '.tar', '.zip', '.log', '.conf', '.cfg', '.ini']) or
                # 绝对路径
                os.path.isabs(token)
            )
            
            if is_path_like:
                # 验证路径是否安全
                if self._resolve_path(token, current_dir) is None:
                    return False, f"[安全错误] 参数 '{token}' 解析为当前工作目录之外的路径或包含非法字符。"
        
        return True, ""

    def execute(self, command: str) -> str:
        return self.execute_shell(command=command)
    
    def execute_shell(self, command: str) -> str:
        try:
            if not command or not command.strip():
                return "[Error] Command cannot be empty."
            
            # 安全检查
            is_safe, error_msg = self._is_safe_command(command)
            if not is_safe:
                return f"[Error] {error_msg}"
            
            return self.execute_in_container(command)
            
        except Exception as e: 
            return f"[Error] Command '{command[:100]}...' failed to execute: {e}"


class Radare2Tool(ExecutableTool, DockerTool):
    name: str = "r2"
    description: str = """
    Interacts with a Radare2 interactive session to analyze the current binary file. Note that this tool automatically establishes and maintains an r2 session for the current analysis focus file inside a Docker container.

    Main features:
    - Send Radare2 commands and get the output
    - Session state is maintained between calls (for the same file)
    - Supports decompilation using the r2ghidra plugin:
    * Use the `pdg` command to decompile functions
    * Provides C-like pseudocode output
    
    """
    parameters: Dict[str, Any] = {
        "type": "object",
        "properties": {
            "command": {
                "type": "string",
                "description": "Command to interact directly with Radare2"
            }
        },
        "required": ["command"]
    }
    timeout = 600

    def __init__(self, context: FlexibleContext):
        ExecutableTool.__init__(self, context)
        DockerTool.__init__(self, context)
        self.r2: Optional[r2pipe.Pipe] = None
        self._initialize_r2()

    def __del__(self):
        try:
            self.close()
        except Exception:
            pass

    def _initialize_r2(self):
        if self.r2:
            return True

        file_path = self.context.get("file_path")
        container_id = self.context.get("container_id")
        
        if not file_path:
            print("Error: Cannot initialize Radare2 without file_path in context.")
            return False
            
        if not container_id:
            print("Error: Cannot initialize Radare2 without container_id in context.")
            return False

        # 将宿主机文件路径转换为容器内路径
        container_file_path = f"/firmware/{os.path.basename(file_path)}"
        
        print(f"Initializing Radare2 session for: {file_path} (container path: {container_file_path})...")
        try:
            # 使用 r2pipe 连接到容器内的 radare2 进程
            self.r2 = r2pipe.open(f"docker exec -i {container_id} r2 -e scr.interactive=false {container_file_path}")
            print("Running initial analysis (aaa) for r2 main tool session...")
            self.r2.cmd('aaa')
            print("Radare2 session initialized in container.")
            return True
        except Exception as e:
            print(f"Error initializing Radare2 session in container: {e}")
            self.r2 = None
            return False

    def execute(self, command: str) -> str:
        if not self.r2:
            print("Radare2 session not ready, attempting initialization...")
            if not self._initialize_r2():
                return "[Error] Radare2 session failed to initialize. Check file path and container status."

        if not command:
            return "[Error] No command provided to Radare2."

        print(f"Executing r2 command: {command}")
        try:
            result = self.r2.cmd(command)
            return result.strip() if result else f"[No output from {command} command]"
        except Exception as e:
            print(f"Error executing Radare2 command '{command}': {e}. Resetting pipe.")
            return f"[Error] Failed to execute command '{command}': {e}. Radare2 pipe might be unstable."

    def close(self):
        if self.r2:
            print(f"Closing Radare2 pipe for {self.context.get('file_path', 'unknown file')}...")
            try:
                self.r2.quit()
            except Exception as e:
                print(f"Error during r2.quit() for {self.context.get('file_path', 'unknown file')}: {e}")
            finally:
                self.r2 = None
                print("Radare2 pipe closed and r2 instance reset.")
        else:
            pass


class Radare2FileTargetTool(ExecutableTool, DockerTool):
    name: str = "r2_file_target"
    description: str = """
    Interacts with a Radare2 interactive session to analyze a specified binary file inside a Docker container. Note that this tool automatically establishes and maintains an r2 session for the target analysis object.

    Main features:
    - Send Radare2 commands and get the output
    - Session state is maintained between calls (for the same file)
    - Supports decompilation using the r2ghidra plugin:
    * Use the `pdg` command to decompile functions
    * Provides C-like pseudocode output

    """
    parameters: Dict[str, Any] = {
        "type": "object",
        "properties": {
            "file_name": {
                "type": "string",
                "description": "The name of the file to be analyzed. Provide the path relative to the firmware root directory, do not start with ./."
            },
            "command": {
                "type": "string",
                "description": "Command to interact directly with Radare2"
            }
        },
        "required": ["file_name", "command"]
    }
    timeout = 600

    def __init__(self, context: FlexibleContext):
        ExecutableTool.__init__(self, context)
        DockerTool.__init__(self, context)
        self.r2: Optional[r2pipe.Pipe] = None
        self.current_analyzed_file: Optional[str] = None

    def __del__(self):
        try:
            self.close()
        except Exception:
            pass

    def _initialize_r2_for_file(self, file_name: str) -> bool:
        container_id = self.context.get("container_id")
        if not container_id:
            print("Error: Cannot initialize Radare2 without container_id in context.")
            return False
            
        # 容器内的文件路径
        container_file_path = f"/firmware/{file_name}"
        
        if self.r2 and self.current_analyzed_file == container_file_path:
            return True

        if self.r2:
            print(f"Closing Radare2 session for previous file: {self.current_analyzed_file}")
            self.close()

        if not file_name:
            print("Error: Cannot initialize Radare2 without a valid file_name.")
            return False

        print(f"Initializing Radare2 session for: {file_name} (container path: {container_file_path})...")
        try:
            # 使用 r2pipe 连接到容器内的 radare2 进程
            self.r2 = r2pipe.open(f"docker exec -i {container_id} r2 -e scr.interactive=false {container_file_path}")
            if not self.r2:
                print(f"Error: r2pipe.open failed for {container_file_path}. The file might not exist in container or r2 is not available.")
                self.current_analyzed_file = None
                return False
            print("Running initial analysis (aaa) for r2 file target tool...")
            self.r2.cmd('aaa')
            self.current_analyzed_file = container_file_path
            print(f"Radare2 session initialized successfully for: {container_file_path}")
            return True
        except Exception as e:
            print(f"Error initializing Radare2 session for {container_file_path}: {e}")
            self.r2 = None
            self.current_analyzed_file = None
            return False

    def execute(self, file_name: str, command: str) -> str:
        if not file_name:
            return "[Error] No file_name provided."

        if not self._initialize_r2_for_file(file_name):
            return f"[Error] Radare2 session failed to initialize for {file_name}. Ensure the file exists in the container and Radare2 is correctly configured."

        if not self.r2:
            return f"[Error] Radare2 session is not available for {file_name} even after initialization attempt."

        if not command:
            return "[Error] No command provided to Radare2."

        print(f"Executing r2 command: '{command}' on file '{file_name}'")
        try:
            result = self.r2.cmd(command)
            return result.strip() if result is not None else f"[No output from '{command}' command]"
        except Exception as e:
            print(f"Error executing Radare2 command '{command}' on '{file_name}': {e}. Resetting pipe for this file.")
            self.close()
            return f"[Error] Failed to execute command '{command}' on '{file_name}': {e}. Pipe has been reset."

    def close(self):
        if self.r2:
            print(f"Closing Radare2 pipe for {self.current_analyzed_file}...")
            try:
                self.r2.quit()
            except Exception as e:
                print(f"Error during r2.quit() for {self.current_analyzed_file}: {e}")
            finally:
                self.r2 = None
                self.current_analyzed_file = None
                print("Radare2 pipe closed and state cleared.")
        else:
            pass


class VulnerabilitySearchTool(ExecutableTool):
    name: str = "cve_search_nvd"
    description: str = "Search for CVE vulnerability information related to software keywords using the NVD API 2.0. Results include CVE ID, description, and CVSSv3 score, sorted in descending order by score."
    parameters: Dict[str, Any] = {
        "type": "object",
        "properties": {
            "keyword_search": {
                "type": "string",
                "description": "Software name or keyword to search for in NVD (e.g., 'BusyBox 1.33.1', 'OpenSSL', 'Linux Kernel'). Include the version number in the keyword if you need to match a specific version via NVD's keyword search."
            },
             "max_results": {
                  "type": "integer",
                  "description": "Limit the number of matching CVEs to return (the highest scored will be shown).",
                  "default": 10,
                  "minimum": 1,
                  "maximum": 50
             }
        },
        "required": ["keyword_search"]
    }
    timeout = 30

    NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    REQUEST_TIMEOUT = 30
    DEFAULT_USER_AGENT = "AgentNvdSearchTool/1.2"

    def execute(self, keyword_search: str, max_results: int = 10, **kwargs) -> str:
        max_results = min(max_results, self.parameters["properties"]["max_results"]["maximum"])
        results_to_fetch = max(max_results * 2, 50)

        params = {
            "keywordSearch": keyword_search,
            "resultsPerPage": results_to_fetch,
            "startIndex": 0,
            "keywordExactMatch": None
        }

        print(f"Querying NVD API: keyword='{keyword_search}', fetching up to {results_to_fetch} potential results.")
        
        headers = {'User-Agent': self.DEFAULT_USER_AGENT}
        api_key = os.getenv("NVD_API_KEY")
        if api_key:
            headers['apiKey'] = api_key
            print("  (Found and using NVD_API_KEY)")

        try:
            response = requests.get(self.NVD_API_URL, params=params, timeout=self.REQUEST_TIMEOUT, headers=headers)
            response.raise_for_status()
            data = response.json()

            total_results = data.get("totalResults", 0)
            if total_results == 0:
                return f"NVD API found no CVEs related to the keyword '{keyword_search}'."

            vulnerabilities = data.get("vulnerabilities", [])
            if not vulnerabilities:
                 return f"NVD API reported {total_results} results for '{keyword_search}', but failed to retrieve vulnerability list details."

            print(f"NVD API returned {len(vulnerabilities)} raw results (total available: {total_results}). Processing and sorting...")

            filtered_cves = []
            for item in vulnerabilities:
                cve_item = item.get("cve", {})
                cve_id = cve_item.get("id")
                if not cve_id: continue

                cvss_v3_score = self._get_cvss_v3_score(cve_item.get("metrics", {}))

                description = self._get_english_description(cve_item.get("descriptions", []))

                filtered_cves.append({
                    "id": cve_id,
                    "score_v3": cvss_v3_score,
                    "description": description.strip()
                })

            if not filtered_cves:
                 return f"Found {total_results} potential CVEs related to '{keyword_search}', but could not extract valid CVE information after processing."

            filtered_cves.sort(key=lambda x: (x['score_v3'] is not None, x['score_v3'] if x['score_v3'] is not None else -1.0), reverse=True)

            if len(filtered_cves) > max_results:
                print(f"Displaying top {max_results} of {len(filtered_cves)} processed CVEs, sorted by score.")
                filtered_cves = filtered_cves[:max_results]
            
            output_text = (f"Top {len(filtered_cves)} CVE results for '{keyword_search}' (sorted by CVSSv3 score):\n\n")

            for idx, cve in enumerate(filtered_cves, 1):
                 output_text += f"{idx}. [{cve['id']}] (CVSSv3 Score: {cve['score_v3'] or 'N/A'})\n   {cve['description']}\n\n"

            return self._limit_output(output_text.strip())

        except requests.exceptions.Timeout:
            return f"[Error] NVD API request timed out ({self.REQUEST_TIMEOUT} seconds)."
        except requests.exceptions.HTTPError as e:
             return f"[Error] NVD API request failed: {e.response.status_code} {e.response.reason}. Please check API status or your query."
        except requests.exceptions.RequestException as e:
            return f"[Error] NVD API network request failed: {e}"
        except json.JSONDecodeError:
             return "[Error] NVD API returned invalid JSON data. The API might be temporarily unavailable or its format may have changed."
        except Exception as e:
            traceback.print_exc()
            return f"[Error] An internal error occurred while processing NVD API results: {e}"

    def _get_english_description(self, descriptions: List[Dict[str, str]]) -> str:
        for desc_item in descriptions:
            if desc_item.get("lang") == "en":
                return desc_item.get("value", "No English description available.")
        return "No description found."

    def _get_cvss_v3_score(self, metrics: Dict[str, Any]) -> Optional[float]:
        if "cvssMetricV31" in metrics and metrics["cvssMetricV31"]:
            try: return metrics["cvssMetricV31"][0]["cvssData"]["baseScore"]
            except (KeyError, IndexError, TypeError): pass
        if "cvssMetricV30" in metrics and metrics["cvssMetricV30"]:
            try: return metrics["cvssMetricV30"][0]["cvssData"]["baseScore"]
            except (KeyError, IndexError, TypeError): pass
        return None

    def _limit_output(self, text: str, max_len: int = 10000) -> str:
        if len(text) > max_len:
             last_newline = text.rfind('\n', 0, max_len)
             if last_newline != -1:
                  return text[:last_newline] + "\n...[Output truncated]"
             else:
                  return text[:max_len] + "...[Output truncated]"
        return text





