import os
import sys
import asyncio
from sentence_transformers import SentenceTransformer


from agenthive.tools.basetool import FlexibleContext
from agenthive.core.builder import build_agent
from agenthive.core.assistants import AgentConfig

from agent import SQLAgent
from tools import AdvancedSQLTool

# --- CONFIGURATION ---

# Database connection details from your script
DB_PARAMS = {
    "dbname": "postgres",
    "user": "postgres",
    "password": "0514",
    "host": "localhost",
    "port": "5432"
}

# Embedding model for semantic search
EMBEDDING_MODEL_NAME = "BAAI/bge-base-en-v1.5"

async def main():
    print("[*] Initializing SQL Agent...")

    # 1. Load the embedding model
    print(f"[*] Loading embedding model: {EMBEDDING_MODEL_NAME}...")
    try:
        # Forcing CPU to avoid potential CUDA issues on different setups
        embedding_model = SentenceTransformer(EMBEDDING_MODEL_NAME, device='cpu')
        print(" -> Embedding model loaded successfully.")
    except Exception as e:
        print(f"[!] Critical error: Failed to load embedding model. {e}")
        return

    # 2. Create and populate the context object
    context = FlexibleContext(
        db_params=DB_PARAMS,
        embedding_model=embedding_model,
        # The 'output' directory for logs, relative to the project root
        output=os.path.join("output")
    )

    # 3. Define the Agent Configuration
    # We use AgentConfig to define how to build our agent.
    sql_agent_config = AgentConfig(
        agent_class=SQLAgent,
        tool_configs=[AdvancedSQLTool],
    )

    # 4. Build the Agent
    # The build_agent function handles the creation of the agent instance.
    agent = build_agent(sql_agent_config, context)
    print("[*] SQL Agent initialized successfully.")

    # 5. Define a question and run the agent
    question = "请原子性地完成以下操作：首先，为知识库添加一位新作者，名字叫‘吴恩达’；然后，将这位新作者与ID为'2401.00616'的论文关联起来。"
    
    print(f"\n--- Running Agent with Question ---")
    print(f"Q: {question}")
    print("-" * 30)

    try:
        final_answer = await agent.arun(user_input=question)
        print("\n" + "="*30)
        print("Final Answer from Agent:")
        print(final_answer)
        print("="*30)
    except Exception as e:
        print(f"\n[!] An error occurred during agent execution: {e}")

if __name__ == "__main__":
    asyncio.run(main())
