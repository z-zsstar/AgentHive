import uvicorn
from fastapi import FastAPI
from pydantic import BaseModel
from sentence_transformers import SentenceTransformer

from main import run_dba_task


app = FastAPI(
    title="DB Agent Service",
    description="一个用于安全执行数据库操作的Agent服务",
    version="1.0.0"
)

print("[*] Server: 正在加载嵌入模型 (此过程仅在启动时发生)...")
embedding_model_singleton = SentenceTransformer("BAAI/bge-base-en-v1.5", device='cpu')
print(" -> 模型加载成功。")


class UserQuery(BaseModel):
    question: str
    user_id: str | None = None
    session_id: str | None = None


class AgentResponse(BaseModel):
    answer: str
    session_id: str | None = None


@app.post("/ask", response_model=AgentResponse)
async def ask_agent(query: UserQuery):
    """
    接收用户问题并与DBA Agent交互。
    """
    print(f"[*] API: 接收到问题: '{query.question}'")
    final_result = run_dba_task(
        question=query.question, 
        embedding_model=embedding_model_singleton
    )
    
    print(f"[*] API: Agent处理完成，返回结果。")
    
    return AgentResponse(answer=final_result, session_id=query.session_id)


def start_server():
    """使用 uvicorn 启动服务"""
    print("[*] Server: 正在启动API服务...")
    uvicorn.run(app, host="0.0.0.0", port=8000)

if __name__ == "__main__":
    start_server()
