import redis
import json
import psycopg2
import torch # 导入 torch
from pgvector.psycopg2 import register_vector
from sentence_transformers import SentenceTransformer
import re
import os

# --- 配置 ---
REDIS_HOST = os.getenv("REDIS_HOST", "localhost")
REDIS_PORT = int(os.getenv("REDIS_PORT", 6379))
DB_NAME = os.getenv("DB_NAME", "postgres")
DB_USER = os.getenv("DB_USER", "postgres")
DB_PASSWORD = os.getenv("DB_PASSWORD", "0514")
DB_HOST = os.getenv("DB_HOST", "localhost")
DB_PORT = os.getenv("DB_PORT", "5432")
MODEL_NAME = "BAAI/bge-base-en-v1.5"
QUEUE_NAME = "sql_tasks"

# --- 全局资源初始化 ---
device = "cuda" if torch.cuda.is_available() else "cpu"
print(f"[*] Worker: 正在加载嵌入模型 (使用设备: {device})...")
embedding_model = SentenceTransformer(MODEL_NAME, device=device)
print(" -> 模型加载成功。")

def get_db_connection():
    """建立并返回一个新的数据库连接。"""
    conn = psycopg2.connect(
        dbname=DB_NAME, user=DB_USER, password=DB_PASSWORD, host=DB_HOST, port=DB_PORT
    )
    register_vector(conn)
    return conn

def execute_sql_task(task_data):
    """
    在单个数据库事务中执行SQL任务。
    这是 AdvancedSQLTool 的核心逻辑的后端实现。
    """
    queries = task_data.get("queries", [])
    if not queries:
        return "[错误] 任务中未发现任何查询。"

    conn = get_db_connection()
    cur = conn.cursor()

    try:
        cur.execute("BEGIN;")
        results_log = []

        for query in queries:
            params = []
            placeholder_match = re.search(r"<VECTOR\((['\"])(.*?)\1\)>", query)
            
            if placeholder_match:
                search_text = placeholder_match.group(2)
                embedding = embedding_model.encode(search_text)
                query = query.replace(placeholder_match.group(0), "%s")
                params.append(embedding)
            
            cur.execute(query, params)
            
            # 记录受影响的行数，即便是SELECT也记录，虽然通常为-1
            results_log.append(f"  - 查询 '{query[:80]}...' 影响了 {cur.rowcount} 行。")

        cur.execute("COMMIT;")
        return f"事务成功提交。\n" + "\n".join(results_log)

    except Exception as e:
        cur.execute("ROLLBACK;")
        return f"[错误] 事务执行失败并已回滚: {e}"
    finally:
        cur.close()
        conn.close()

def main():
    """Worker主循环，监听Redis队列并处理任务。"""
    print(f"[*] Worker: 正在连接到 Redis ({REDIS_HOST}:{REDIS_PORT})...")
    r = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, db=0, decode_responses=True)
    print(" -> Redis 连接成功。")
    print(f"[*] Worker: 开始监听 '{QUEUE_NAME}' 队列...")

    while True:
        try:
            # blpop 是一个阻塞式操作，它会一直等待直到队列中有新任务
            # 0 表示永不超时
            _, task_json = r.blpop(QUEUE_NAME, 0)
            
            print("\n" + "="*50)
            print(f"[*] Worker: 接收到新任务！")
            
            task_data = {}
            try:
                task_data = json.loads(task_json)
                task_id = task_data.get("task_id")
                print(f"  - 任务ID: {task_id}")
                print(f"  - 任务内容: {task_data.get('queries')}")
                
                result = execute_sql_task(task_data)
                
                print(f"[*] Worker: 任务处理完成。")
                print(f"  - 执行结果: {result}")

                if task_id:
                    result_key = f"sql_result:{task_id}"
                    r.rpush(result_key, result)
                    r.expire(result_key, 60) # 设置60秒后自动过期，防止孤儿key
                    print(f"  - 结果已发送至: {result_key}")

            except json.JSONDecodeError:
                print("[!] Worker: 任务解析失败，非法的JSON格式。")
            except Exception as e:
                print(f"[!] Worker: 处理任务时发生未知错误: {e}")
                # 即使处理失败，也要通知客户端，防止其永久阻塞
                task_id = task_data.get("task_id")
                if task_id:
                    result_key = f"sql_result:{task_id}"
                    error_message = f"Worker在处理任务时发生内部错误: {e}"
                    r.rpush(result_key, error_message)
                    r.expire(result_key, 60)

        except redis.exceptions.ConnectionError as e:
            print(f"[!] Worker: Redis 连接丢失: {e}。正在尝试重连...")
            # 可以添加重连逻辑
            break
        except KeyboardInterrupt:
            print("\n[*] Worker: 检测到中断信号，正在关闭...")
            break

if __name__ == "__main__":
    main()
