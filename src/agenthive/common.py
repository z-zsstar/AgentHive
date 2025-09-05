import json
from typing import Dict, Any, Callable, Optional

class Message(Dict[str, Any]):
    def __init__(self, role: str, content: str, type: Optional[str] = None, tool_call_id: Optional[str] = None, name: Optional[str] = None):
        try:
            content_str = str(content)
        except Exception:
            print(f"Warning: Could not convert message content to string. Using repr(). Original type: {type(content)}")
            content_str = repr(content)

        super().__init__(role=role, content=content_str)
        if type:
            self['type'] = type
        if tool_call_id:
            self['tool_call_id'] = tool_call_id
        if name:
            self['name'] = name

    @property
    def role(self) -> str: return str(self.get('role', 'unknown'))
    @property
    def content(self) -> str: return str(self.get('content', ''))
    @property
    def type(self) -> Optional[str]: return self.get('type')
    @property
    def tool_call_id(self) -> Optional[str]: return self.get('tool_call_id')
    @property
    def name(self) -> Optional[str]: return self.get('name')


class Tool:
    def __init__(self, name: str, description: str, function: Callable, parameters: Optional[Dict[str, Any]] = None, timeout: Optional[int] = None):
        self.name = name
        self.description = description
        self.function = function
        self.parameters = parameters if parameters else {}
        self.timeout = timeout

    def __call__(self, *args, **kwargs):
        return self.function(*args, **kwargs)

    def format_for_prompt(self) -> str:
        param_str = json.dumps(self.parameters, ensure_ascii=False) if self.parameters else "No parameters"
        if self.parameters:
            try:
                param_str = json.dumps(self.parameters, indent=2, ensure_ascii=False)
            except TypeError:
                 param_str = str(self.parameters)
        return f"- Name: {self.name}\n  Description: {self.description}\n  Parameters (JSON Schema format):\n{param_str}"