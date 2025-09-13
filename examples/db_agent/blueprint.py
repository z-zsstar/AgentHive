from agenthive.base import BaseAgent
from agenthive.core.builder import AgentConfig

from tools import SQLExecuteTool
from prompts import DUAL_ROLE_DBA_PROMPT


def create_dba_blueprint(max_iterations: int = 25) -> AgentConfig:
    """
    构建一个具备双重角色（勘探与执行）的数据库专家Agent的配置。
    这个Agent在一个会话中完成所有工作，确保了知识的连续性。

    Args:
        max_iterations (int): Agent实例的最大迭代次数。

    Returns:
        AgentConfig: 为DBA专家Agent生成的配置。
    """
    
    dba_tools = [
        SQLExecuteTool
    ]

    return AgentConfig(
        agent_class=BaseAgent,
        tool_configs=dba_tools,
        system_prompt=DUAL_ROLE_DBA_PROMPT,
        max_iterations=max_iterations,
        agent_instance_name="DBA_Agent",
    )
