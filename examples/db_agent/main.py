import os
import asyncio
from sentence_transformers import SentenceTransformer

from agenthive.base import BaseAgent
from agenthive.tools.basetool import FlexibleContext
from agenthive.core.builder import build_agent, AgentConfig, AssistantToolConfig

from agents import DBAExpertAssistant, BackgroundTaskDBAExpertAssistant
from blueprint import create_dba_blueprint
from prompts import DBA_MANAGER_SYSTEM_PROMPT

async def run_dba_task(question: str, embedding_model) -> str:
    """
    初始化DBA Agent并运行指定的任务。
    
    Args:
        question (str): 要执行的任务描述。
        embedding_model: 已加载的SentenceTransformer模型实例。

    Returns:
        str: Agent执行后的最终结果。
    """
    print("[*] 正在初始化 DBA 专家团队...")

    DB_PARAMS = {
        "dbname": os.getenv("DB_NAME", "postgres"),
        "user": os.getenv("DB_USER", "postgres"),
        "password": os.getenv("DB_PASSWORD", ""),
        "host": os.getenv("DB_HOST", "localhost"),
        "port": os.getenv("DB_PORT", "5432"),
    }
    
    context = FlexibleContext(
        db_params=DB_PARAMS,
        embedding_model=embedding_model,
        _shallow_copy_keys=['embedding_model', 'db_params']
    )

    expert_agent_config = create_dba_blueprint(max_iterations=50)

    assistant_tool_config = AssistantToolConfig(
        assistant_class=DBAExpertAssistant,
        sub_agent_config=expert_agent_config,
    )

    background_assistant_tool_config = AssistantToolConfig(
        assistant_class=BackgroundTaskDBAExpertAssistant,
        sub_agent_config=expert_agent_config,
    )

    manager_config = AgentConfig(
        agent_class=BaseAgent,
        tool_configs=[assistant_tool_config, background_assistant_tool_config],
        system_prompt=DBA_MANAGER_SYSTEM_PROMPT,
        max_iterations=25
    )

    manager_agent = build_agent(manager_config, context)
    print("[*] DBA 专家团队初始化成功，配备标准和后台任务两种委托工具。")

    print(f"\n--- 正在使用专家团队处理任务: {question} ---")
    
    final_result = await manager_agent.arun(question)
    return final_result

def main():
    """用于命令行直接运行的函数"""
    print("[*] Main: 正在加载嵌入模型...")
    embedding_model = SentenceTransformer("BAAI/bge-base-en-v1.5", device='cpu')
    print(" -> 模型加载成功。")

    question_long_task = (
        "请对知识库进行一次数据一致性检查与修复。"
        "任务要求：首先，请找出`authors`表中是否存在姓名完全相同的重复作者记录；"
        "如果存在，请将这些重复的记录合并为一条，并将其所有关联的论文（在`paper_authors`表中）都指向合并后的那条单一作者记录。"
        "这是一个耗时任务，请使用后台工具启动它。在它运行时，请必须语义检索来查询提到Lora的论文，并告诉我这些论文的标题、作者、发表时间、发表期刊。"
    )

    final_result = asyncio.run(run_dba_task(question_long_task, embedding_model))
    
    print("\n" + "="*30)
    print("最终结果:")
    print(final_result)
    print("="*30)

if __name__ == "__main__":
    main()
