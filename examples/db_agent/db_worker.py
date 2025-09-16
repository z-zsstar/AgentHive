import re
import os
import json
import torch
import redis
import psycopg2

from pgvector.psycopg2 import register_vector
from sentence_transformers import SentenceTransformer

REDIS_HOST = os.getenv("REDIS_HOST", "localhost")
REDIS_PORT = int(os.getenv("REDIS_PORT", 6379))
DB_NAME = os.getenv("DB_NAME", "postgres")
DB_USER = os.getenv("DB_USER", "postgres")
DB_PASSWORD = os.getenv("DB_PASSWORD", "0514")
DB_HOST = os.getenv("DB_HOST", "localhost")
DB_PORT = os.getenv("DB_PORT", "5432")
MODEL_NAME = "BAAI/bge-base-en-v1.5"
QUEUE_NAME = "sql_tasks"

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
        return "[错误] 任务中未发现任何。"

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
            
            if cur.description:
                columns = [desc[0] for desc in cur.description]
                results = cur.fetchall()
                
                MAX_ROWS_TO_RETURN = 10000
                is_truncated = False
                if len(results) > MAX_ROWS_TO_RETURN:
                    results = results[:MAX_ROWS_TO_RETURN]
                    is_truncated = True

                if results:
                    header = "| " + " | ".join(columns) + " |"
                    separator = "| " + " | ".join(["---"] * len(columns)) + " |"
                    body = "\n".join(["| " + " | ".join(map(str, row)) + " |" for row in results])
                    
                    table = f"'{query}...' 的结果:\n{header}\n{separator}\n{body}"
                    
                    if is_truncated:
                        table += f"\n\n[警告] 返回结果集超过 {MAX_ROWS_TO_RETURN} 行，已截断。请使用更精确的（如添加 WHERE 或 LIMIT 子句）。"

                    results_log.append(table)
                else:
                    results_log.append(f" '{query[:80]}...' 成功执行，但未返回任何行。")
            else:
                results_log.append(f"操作 '{query[:80]}...' 成功执行, {cur.rowcount} 行受到影响。")

        cur.execute("COMMIT;")
        return "事务成功提交。\n\n" + "\n\n".join(results_log)

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
                    r.expire(result_key, 60)
                    print(f"  - 结果已发送至: {result_key}")

            except json.JSONDecodeError:
                print("[!] Worker: 任务解析失败，非法的JSON格式。")
            except Exception as e:
                print(f"[!] Worker: 处理任务时发生未知错误: {e}")
                task_id = task_data.get("task_id")
                if task_id:
                    result_key = f"sql_result:{task_id}"
                    error_message = f"Worker在处理任务时发生内部错误: {e}"
                    r.rpush(result_key, error_message)
                    r.expire(result_key, 60)

        except redis.exceptions.ConnectionError as e:
            print(f"[!] Worker: Redis 连接丢失: {e}。正在尝试重连...")
            break
        except KeyboardInterrupt:
            print("\n[*] Worker: 检测到中断信号，正在关闭...")
            break

if __name__ == "__main__":
    main()
