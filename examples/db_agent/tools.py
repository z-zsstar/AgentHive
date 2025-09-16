import os
import json
import redis
import uuid
import psycopg2
import asyncio
from redis.asyncio import Redis as AsyncRedis
from typing import Dict, Any, List, Union
from pgvector.psycopg2 import register_vector

from agenthive.tools.basetool import ExecutableTool, FlexibleContext


class SQLExecuteTool(ExecutableTool):
    name = "sql_execute"
    description_template = (
        "将一个或多个SQL查询作为任务发送到后台队列执行。\n"
        "支持任意SQL语句。若要进行语义搜索，请使用 <VECTOR('搜索文本')> 占位符将文本转换为向量。\n\n"
        "**语义搜索抽象示例**:\n"
        "假设你要在 `your_table` 中查找与 'your search text' 语义最相关的条目，可以这样查询:\n"
        "```sql\n"
        "SELECT t.id, t.text_column\n"
        "FROM your_table t\n"
        "JOIN your_vector_table v ON t.id = v.foreign_id\n"
        "ORDER BY v.embedding_column <-> <VECTOR('your search text')>\n"
        "LIMIT 5;\n"
        "```\n"
        "后台会自动将 `<VECTOR('your search text')>` 替换为真实的语义向量进行查询。\n\n"
        "--- 自动检测到的数据库结构 ---\n{schema_info}"
    )
    parameters: Dict[str, Any] = {
        "type": "object",
        "properties": {
            "queries": {
                "oneOf": [
                    {"type": "string"},
                    {"type": "array", "items": {"type": "string"}}
                ],
                "description": (
                    "要执行的单个SQL查询字符串，或一个SQL查询字符串列表。"
                    "如果提供的是列表，所有查询将在一个原子事务中由后台工作进程执行。"
                )
            }
        },
        "required": ["queries"]
    }
    timeout = 60
    
    def __init__(self, context: FlexibleContext):
        super().__init__(context)
        self.db_params = self.context.get("db_params")
        if not self.db_params:
            raise ValueError("在上下文中未找到数据库连接参数 'db_params'。")
        
        self.redis_host = os.getenv("REDIS_HOST", "localhost")
        self.redis_port = int(os.getenv("REDIS_PORT", 6379))
        self.queue_name = "sql_tasks"
        self.redis_client = redis.Redis(host=self.redis_host, port=self.redis_port, db=0, decode_responses=True)
        self.async_redis_client = AsyncRedis.from_url(f"redis://{self.redis_host}:{self.redis_port}/0", decode_responses=True)

        schema_info = self._get_db_schema_info()
        self.description = self.description_template.format(schema_info=schema_info)

    def _get_db_connection(self):
        conn = psycopg2.connect(**self.db_params)
        register_vector(conn)
        return conn

    def _get_db_schema_info(self) -> str:
        """连接到数据库以获取 schema 信息供工具描述使用。"""
        try:
            conn = self._get_db_connection()
            cur = conn.cursor()
            cur.execute("""
                SELECT table_name 
                FROM information_schema.tables 
                WHERE table_schema = 'public' AND table_type = 'BASE TABLE';
            """)
            tables = [row[0] for row in cur.fetchall()]
            schema_parts = []
            for table in tables:
                cur.execute("""
                    SELECT column_name, data_type 
                    FROM information_schema.columns 
                    WHERE table_name = %s ORDER BY ordinal_position;
                """, (table,))
                columns = cur.fetchall()
                schema_parts.append(f"表 `{table}`:")
                col_info = [f"  - `{col[0]}` ({col[1]})" for col in columns]
                schema_parts.extend(col_info)
            cur.close()
            conn.close()
            print(f"[SQLExecuteTool] 获取数据库 schema 信息: {schema_parts}")
            return "\n".join(schema_parts) if schema_parts else "在 public schema 中未找到任何表。"
        except Exception as e:
            print(f"[AdvancedSQLTool Init] 获取数据库 schema 时出错: {e}")
            return "无法检索 schema 信息。"

    def execute(self, queries: Union[str, List[str]]) -> str:
        """
        将SQL查询打包成任务并推送到Redis队列，然后阻塞等待执行结果。
        """
        if isinstance(queries, str):
            queries = [queries]

        task_id = str(uuid.uuid4())
        result_key = f"sql_result:{task_id}"
        
        task = {
            "task_id": task_id,
            "queries": queries
        }

        try:
            task_json = json.dumps(task)
            self.redis_client.rpush(self.queue_name, task_json)
            
            print(f"[*] Tool: 任务 {task_id} 已发送，正在等待结果...")
            result_tuple = self.redis_client.blpop(result_key, timeout=self.timeout)
            
            if result_tuple is None:
                return f"[错误] 等待后台任务结果超时（超过60秒）。"

            result = result_tuple[1]
            return f"后台任务执行完毕，结果如下：\n{result}"

        except redis.exceptions.ConnectionError as e:
            return f"[错误] 无法连接到 Redis 服务: {e}"
        except Exception as e:
            return f"[错误] 发送任务或等待结果时失败: {e}"

    async def aexecute(self, queries: Union[str, List[str]]) -> str:
        """
        异步地将SQL查询打包成任务并推送到Redis队列，然后阻塞等待执行结果。
        """
        if isinstance(queries, str):
            queries = [queries]

        task_id = str(uuid.uuid4())
        result_key = f"sql_result:{task_id}"
        
        task = {
            "task_id": task_id,
            "queries": queries
        }

        try:
            task_json = json.dumps(task)
            await self.async_redis_client.rpush(self.queue_name, task_json)
            
            print(f"[*] Tool: 异步任务 {task_id} 已发送，正在等待结果...")
            # aioredis.blpop returns a tuple of (key, value)
            result_tuple = await self.async_redis_client.blpop(result_key, timeout=self.timeout)
            
            if result_tuple is None:
                return f"[错误] 等待后台任务结果超时（超过60秒）。"

            result = result_tuple[1]
            return f"后台任务执行完毕，结果如下：\n{result}"

        except asyncio.TimeoutError:
            return f"[错误] 等待后台任务结果超时（超过60秒）。"
        except redis.exceptions.ConnectionError as e:
            return f"[错误] 无法连接到 Redis 服务: {e}"
        except Exception as e:
            return f"[错误] 发送任务或等待结果时失败: {e}"
