import r2pipe
from typing import Dict, Any, Optional
from agent.tools.basetool import ExecutableTool, FlexibleContext

class Radare2Tool(ExecutableTool):
    name: str = "r2"
    description: str = """
    与 Radare2 交互式会话交互，针对当前二进制文件进行分析。需注意该工具会自动建立和当前分析焦点文件的r2会话，并保持会话状态。

    主要功能：
    - 发送 Radare2 命令并获取输出
    - 会话状态在调用之间保持（针对同一文件）
    - 支持使用 r2ghidra 插件进行反编译：
    * 使用 `pdg` 命令反编译函数
    * 提供类 C 语言伪代码输出
    
    """
    parameters: Dict[str, Any] = {
        "type": "object",
        "properties": {
            "command": {
                "type": "string",
                "description": "直接与Radare2交互的命令"
            }
        },
        "required": ["command"]
    }
    timeout = 600  # 增加到10分钟，支持大型固件文件分析

    def __init__(self, context: FlexibleContext):
        super().__init__(context)
        self.r2: Optional[r2pipe.Pipe] = None
        self._initialize_r2()

    def __del__(self):
        """析构函数：确保资源清理，防止radare2进程泄漏"""
        try:
            self.close()
        except Exception:
            pass

    def _initialize_r2(self):
        if self.r2:
            # print("Radare2 session already initialized.") # Too verbose for repeated calls
            return True

        file_path = self.context.get("file_path")
        if not file_path:
            print("Error: Cannot initialize Radare2 without file_path in context.")
            return False

        print(f"Initializing Radare2 session for: {file_path}...")
        try:
            self.r2 = r2pipe.open(file_path, flags=['-e', 'scr.interactive=false'])
            print("Running initial analysis (aaa) for r2 main tool session...")
            self.r2.cmd('aaa')
            print("Radare2 session initialized.")
            return True
        except Exception as e:
            print(f"Error initializing Radare2 session: {e}")
            self.r2 = None
            return False

    def execute(self, command: str) -> str:
        if not self.r2:
            print("Radare2 session not ready, attempting initialization...")
            if not self._initialize_r2():
                return "[Error] Radare2 session failed to initialize. Check file path and r2 installation."

        if not command:
            return "[Error] No command provided to Radare2."

        print(f"Executing r2 command: {command}")
        try:
            result = self.r2.cmd(command)
            return result.strip() if result else "[No output from {command} command]".format(command=command)
        except Exception as e:
            print(f"Error executing Radare2 command '{command}': {e}. Resetting pipe.")
            return f"[Error] Failed to execute command '{command}': {e}. Radare2 pipe might be unstable."

    def close(self):
        """Closes the current Radare2 session and resets related attributes."""
        if self.r2:
            print(f"Closing Radare2 pipe for {self.context.get('file_path', 'unknown file')}...")
            try:
                self.r2.quit()
            except Exception as e:
                print(f"Error during r2.quit() for {self.context.get('file_path', 'unknown file')}: {e}") # Use get for file_path
            finally:
                self.r2 = None
                print("Radare2 pipe closed and r2 instance reset.")
        else:
            pass # No active session to close


