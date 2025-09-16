from agenthive.base import BaseAgent
from agenthive.core.builder import AgentConfig

from .tools import SQLExecuteTool
from prompts import DUAL_ROLE_DBA_PROMPT


def create_dba_blueprint(max_iterations: int = 25) -> AgentConfig:
    return AgentConfig(
        agent_class=BaseAgent,
        tool_configs=[SQLExecuteTool],
        system_prompt=DUAL_ROLE_DBA_PROMPT,
        max_iterations=max_iterations,
        agent_instance_name="DBA_Agent",
    )
