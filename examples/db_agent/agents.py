from agenthive.core.assistants import BaseAssistant
from agenthive.tools.basetool import FlexibleContext

class DBAExpertAssistant(BaseAssistant):
    """
    一个用于启动和管理“全能数据库专家”子Agent的助手工具。
    它负责将顶层任务传递给具备完整勘探-验证-执行流程的子Agent。
    """
    name: str = "DBA_Agent"
    description: str = "一个全能的数据库专家团队，负责接收高层级数据库任务，在一个连续的会话中完成深入的探索、规划、自我验证，并最终安全地执行。当你需要完成一个复杂的数据库操作时，请将任务委托给它。"
    parameters: dict = {
        "type": "object",
        "properties": {
            "task_description": {
                "type": "string",
                "description": "对要完成的数据库任务的详细、清晰的描述。"
            }
        },
        "required": ["task_description"]
    }

    def _prepare_sub_agent_context(self, **kwargs) -> FlexibleContext:
        """
        为子Agent创建一个干净的、隔离的上下文，只传递必要的共享资源。
        """
        return self.context.copy()

    def _build_sub_agent_prompt(self, **kwargs) -> str:
        """
        为子Agent构建初始提示。
        """
        task_description = kwargs.get("task_description", "未提供任务描述")
        return (
            "请根据以下顶层任务目标，开始你的工作流程。\n\n"
            f"**任务目标**: {task_description}"
        )
