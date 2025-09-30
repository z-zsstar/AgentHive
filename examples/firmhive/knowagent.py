import json
import os
import fcntl
import asyncio
from typing import Dict, List, Any, Optional, Type, Union

from hivemind.base import BaseAgent
from hivemind.historystrategy import HistoryStrategy
from hivemind.tools.basetool import ExecutableTool, FlexibleContext

DEFAULT_KB_FILE = "knowledge_base.jsonl"

FINDING_SCHEMA: Dict[str, Dict[str, Any]] = {
    "name": {
        "type": "string", 
        "description": "Define a unique identifier for the item. Suggested format: '<Type>-<Function/Module>-<Unique ID>'."
    },
    "location": {
        "type": "string",
        "description": "Precise location of the code sink or key logic. Format: '<relative_file_path>:<line_number> [function_name] [address]'. Adapts to binary or script.\n"
    },
    "description": {
        "type": "string",
        "description": "Describe in detail the findings or observations.\n"
    },
    "link_identifiers": {
        "type": "array",
        "items": {"type": "string"},
        "description": "List of specific identifiers (NVRAM vars, function names, file paths) that connect this finding to others. AVOID generic terms.\n"
    },
    "code_snippet": {
        "type": "string",
        "description": "The most relevant code snippet."
    },
    "risk_score": {
        "type": "number",
        "description": "Risk score (0.0-10.0)"
    },
    "confidence": {
        "type": "number",
        "description": "Confidence in the finding's accuracy and exploitability. (0.0-10.0)"
    },
    "notes": {
        "type": "string",
        "description": "For human analysts. Includes assumptions made, remaining questions, or suggestions for the next analysis step \n"
    }
}

FINDING_SCHEMA_REQUIRED_FIELDS: List[str] = ["location", "description"]

class KnowledgeBaseMixin:
    def _initialize_kb(self, context: FlexibleContext):
        output_from_context = context.get("output")

        if output_from_context and isinstance(output_from_context, str):
            self.output = output_from_context
        else:
            raise ValueError("'output' not found in context or invalid.")

        if not os.path.exists(self.output):
            try:
                os.makedirs(self.output, exist_ok=True)
                print(f"Created output directory: {os.path.abspath(self.output)}")
            except OSError as e:
                print(f"Warning: Could not create output directory '{self.output}': {e}. Attempting to create the knowledge base file in the current directory.")
                self.output = "."

        self.kb_file_path = os.path.join(self.output, DEFAULT_KB_FILE)

        kb_specific_dir = os.path.dirname(self.kb_file_path)
        if kb_specific_dir and not os.path.exists(kb_specific_dir):
            try:
                os.makedirs(kb_specific_dir, exist_ok=True)
            except OSError as e:
                 print(f"Warning: Could not create specific directory for KB file '{kb_specific_dir}': {e}")

        print(f"Knowledge base file path set to: {os.path.abspath(self.kb_file_path)}")

    def _load_kb_data(self, lock_file) -> List[Dict[str, Any]]:
        findings = []
        try:
            fcntl.flock(lock_file, fcntl.LOCK_SH)
            lock_file.seek(0)
            for line_bytes in lock_file:
                if not line_bytes.strip():
                    continue
                try:
                    findings.append(json.loads(line_bytes.decode('utf-8-sig')))
                except json.JSONDecodeError as e:
                    print(f"Warning: Error parsing a line in the knowledge base, skipped. Error: {e}. Line: {line_bytes[:100]}...")
            return findings
        except Exception as e:
            print(f"Error loading KB '{self.kb_file_path}': {e}. Returning an empty list.")
            return []
        finally:
            try:
                fcntl.flock(lock_file, fcntl.LOCK_UN)
            except (ValueError, OSError):
                pass

    async def _aload_kb_data(self, lock_file) -> List[Dict[str, Any]]:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, self._load_kb_data, lock_file)

class StoreFindingsTool(ExecutableTool, KnowledgeBaseMixin):
    name: str = "StoreStructuredFindings"
    description: str = "Stores structured firmware analysis findings into the knowledge base in append mode. Each finding must include detailed path and condition constraints to ensure traceability and verifiability."
    parameters: Dict = {
        "type": "object",
        "properties": {
            "findings": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": FINDING_SCHEMA,
                    "required": FINDING_SCHEMA_REQUIRED_FIELDS
                },
                "description": "A list of findings to be stored. Each object in the list should follow the defined schema. Contextual information (like 'file_path') will be added automatically by the tool."
            }
        },
        "required": ["findings"]
    }

    def __init__(self, context: FlexibleContext):
        ExecutableTool.__init__(self, context)
        KnowledgeBaseMixin._initialize_kb(self, context)

    def execute(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        context_file_path = self.context.get("file_path")
        context_dir = self.context.get("current_dir")
        context_base_path = self.context.get("base_path")
        context_stage = self.context.get("stage")

        context_dir_path = None
        if context_dir and context_base_path:
            try:
                context_dir_path = os.path.relpath(context_dir, context_base_path)
            except ValueError:
                context_dir_path = context_dir

        if not findings:
            return {"status": "info", "message": "Info: No findings provided for storage."}

        enriched_findings = []
        for finding_dict in findings:
            if isinstance(finding_dict, dict):
                finding_copy = finding_dict.copy()

                if context_file_path:
                    finding_copy['file_path'] = os.path.relpath(context_file_path, context_base_path)
                elif context_dir_path:
                    finding_copy['dir_path'] = os.path.relpath(context_dir, context_base_path)
                if context_stage:
                    finding_copy['stage'] = context_stage

                enriched_findings.append(finding_copy)
            else:
                print(f"Warning: Non-dictionary item found in findings list and was ignored: {finding_dict}")

        if not enriched_findings:
            return {"status": "info", "message": "Info: No valid findings were processed for storage."}

        try:
            with open(self.kb_file_path, 'ab') as f:
                fcntl.flock(f, fcntl.LOCK_EX)
                try:
                    for finding in enriched_findings:
                        try:
                            json_string = json.dumps(finding, ensure_ascii=False)
                            f.write(json_string.encode('utf-8'))
                            f.write(b'\n')
                        except TypeError as te:
                            print(f"CRITICAL: Could not serialize finding, skipped. Error: {te}. Content: {str(finding)[:200]}...")
                            continue
                finally:
                    fcntl.flock(f, fcntl.LOCK_UN)

            num_stored = len(enriched_findings)
            message = f"Successfully appended {num_stored} findings to the knowledge base."
            print(f"{message}")
            return {"status": "success", "message": message, "stored_count": num_stored}

        except Exception as e:
            error_message = f"Error storing findings: {str(e)}"
            print(f"{error_message} (Details: {e})")
            return {"status": "error", "message": error_message}

    async def aexecute(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, self.execute, findings)


class QueryFindingsTool(ExecutableTool, KnowledgeBaseMixin):
    name: str = "QueryFindings"
    description: str = "Retrieves matching findings from the knowledge base based on a specified field name (query_key) and expected value (query_value). It iterates through each finding record in the knowledge base for a match."

    parameters: Dict = {
        "type": "object",
        "properties": {
            "query_key": {
                "type": "string",
                "description": "The name of the field in the finding record to query.",
                "enum": ["file_path", "link_identifiers", "notes"]
            },
            "query_value": {
                "description": "The value to match. For the 'link_identifiers' list, this should be a single keyword string; for other fields, a direct equality comparison will be performed."
            }
        },
        "required": ["query_key", "query_value"]
    }

    def __init__(self, context: FlexibleContext):
        ExecutableTool.__init__(self, context)
        KnowledgeBaseMixin._initialize_kb(self, context)

    def _check_match(self, finding_item: Dict[str, Any], query_key: str, query_value: Any) -> bool:
        if not isinstance(finding_item, dict) or query_key not in finding_item:
            return False

        actual_value = finding_item[query_key]

        if query_key == "link_identifiers":
            if isinstance(actual_value, list) and isinstance(query_value, str):
                return query_value in [str(item) for item in actual_value if isinstance(item, (str, int, float, bool))]
            return False

        return actual_value == query_value

    def execute(self, query_key: str, query_value: Any) -> List[Dict[str, Any]]:
        if not isinstance(query_key, str) or not query_key:
            return [{"error": "Query key 'query_key' must be a non-empty string."}]

        results = []
        try:
            if not os.path.exists(self.kb_file_path):
                 return [{"message": f"Knowledge base file '{self.kb_file_path}' does not exist, there may be no findings yet.", "query_key": query_key, "query_value": query_value}]

            with open(self.kb_file_path, 'rb') as f:
                all_findings = self._load_kb_data(f)

            if not all_findings:
                return [{"message": "Knowledge base is empty or malformed.", "query_key": query_key, "query_value": query_value}]

            for finding_item in all_findings:
                if self._check_match(finding_item, query_key, query_value):
                    results.append(finding_item.copy())

            query_value_str = str(query_value)
            if len(query_value_str) > 100: query_value_str = query_value_str[:100] + "..."

            print(f"[Tool - Query] Found {len(results)} matching findings for key '{query_key}' and value '{query_value_str}'.")
            if not results:
                return [{"message": f"No findings matched the query key '{query_key}' and value '{query_value_str}'."}]
            return results
        except FileNotFoundError:
             return [{"message": "Knowledge base file not found, there may be no findings yet.", "query_key": query_key, "query_value": query_value}]
        except Exception as e:
            print(f"[Tool - Query] Error querying findings: {e}")
            return [{"error": f"Error querying findings: {str(e)}", "query_key": query_key, "query_value": query_value}]

    async def aexecute(self, query_key: str, query_value: Any) -> List[Dict[str, Any]]:
        if not isinstance(query_key, str) or not query_key:
            return [{"error": "Query key 'query_key' must be a non-empty string."}]

        results = []
        try:
            if not os.path.exists(self.kb_file_path):
                 return [{"message": f"Knowledge base file '{self.kb_file_path}' does not exist, there may be no findings yet.", "query_key": query_key, "query_value": query_value}]

            with open(self.kb_file_path, 'rb') as f:
                all_findings = await self._aload_kb_data(f)

            if not all_findings:
                return [{"message": "Knowledge base is empty or malformed.", "query_key": query_key, "query_value": query_value}]

            for finding_item in all_findings:
                if self._check_match(finding_item, query_key, query_value):
                    results.append(finding_item.copy())

            query_value_str = str(query_value)
            if len(query_value_str) > 100: query_value_str = query_value_str[:100] + "..."

            print(f"[Tool - Query] Found {len(results)} matching findings for key '{query_key}' and value '{query_value_str}'.")
            if not results:
                return [{"message": f"No findings matched the query key '{query_key}' and value '{query_value_str}'."}]
            return results
        except FileNotFoundError:
             return [{"message": "Knowledge base file not found, there may be no findings yet.", "query_key": query_key, "query_value": query_value}]
        except Exception as e:
            print(f"[Tool - Query] Error querying findings: {e}")
            return [{"error": f"Error querying findings: {str(e)}", "query_key": query_key, "query_value": query_value}]


class ListUniqueValuesTool(ExecutableTool, KnowledgeBaseMixin):
    name: str = "ListUniqueValues"
    description: str = """
    Lists all unique values for a specified field in the knowledge base, useful for exploratory analysis and building more precise queries.

    Typical use cases:
    - List 'link_identifiers' to discover key identifiers and correlation points in the code.
    - Query the 'notes' field to get more context and related information.
    - View 'file_path' to understand the scope of analyzed files.
    - Get a list of all files in a specific directory.
    - Review all known vulnerability types and risk assessment distributions.
    """
    parameters: Dict = {
        "type": "object",
        "properties": {
            "target_key": {
                "type": "string",
                "description": "The name of the field in the finding record for which to query unique values (e.g., 'file_path', 'link_identifiers', 'notes')."
            }
        },
        "required": ["target_key"]
    }

    def __init__(self, context: FlexibleContext):
        ExecutableTool.__init__(self, context)
        KnowledgeBaseMixin._initialize_kb(self, context)

    def execute(self, target_key: str) -> Dict[str, Any]:
        if not target_key or not isinstance(target_key, str):
            return {"status": "error", "message": "Error: 'target_key' must be a valid string."}

        unique_values = set()
        try:
            if not os.path.exists(self.kb_file_path):
                return {"status": "info", "message": "Knowledge base file not found, it might not have been initialized.", "unique_values": []}

            with open(self.kb_file_path, 'rb') as f:
                all_findings = self._load_kb_data(f)

            if not all_findings:
                return {"status": "info", "message": f"Knowledge base '{self.kb_file_path}' is empty or malformed.", "target_key": target_key, "unique_values": []}

            for finding_item in all_findings:
                if not isinstance(finding_item, dict):
                    continue

                if target_key in finding_item:
                    value_to_add = finding_item[target_key]
                    if isinstance(value_to_add, list):
                        for item in value_to_add:
                            if isinstance(item, (str, int, float, bool)):
                                unique_values.add(item)
                    elif isinstance(value_to_add, (str, int, float, bool)):
                        unique_values.add(value_to_add)

            try:
                sorted_unique_values = sorted(list(unique_values), key=lambda x: str(x))
            except TypeError:
                 sorted_unique_values = list(unique_values)

            return {
                "status": "success",
                "message": f"Successfully retrieved all unique values for the field '{target_key}'.",
                "target_key": target_key,
                "unique_values": sorted_unique_values
            }

        except FileNotFoundError:
            return {"status": "info", "message": "Knowledge base not found.", "target_key": target_key, "unique_values": []}
        except Exception as e:
            error_message = f"Error getting unique values for key '{target_key}': {str(e)}"
            print(f"[Tool - ListUnique] {error_message}")
            return {"status": "error", "message": error_message, "target_key": target_key, "unique_values": []}

    async def aexecute(self, target_key: str) -> Dict[str, Any]:
        if not target_key or not isinstance(target_key, str):
            return {"status": "error", "message": "Error: 'target_key' must be a valid string."}

        unique_values = set()
        try:
            if not os.path.exists(self.kb_file_path):
                return {"status": "info", "message": "Knowledge base file not found, it might not have been initialized.", "unique_values": []}

            with open(self.kb_file_path, 'rb') as f:
                all_findings = await self._aload_kb_data(f)

            if not all_findings:
                return {"status": "info", "message": f"Knowledge base '{self.kb_file_path}' is empty or malformed.", "target_key": target_key, "unique_values": []}

            for finding_item in all_findings:
                if not isinstance(finding_item, dict):
                    continue

                if target_key in finding_item:
                    value_to_add = finding_item[target_key]
                    if isinstance(value_to_add, list):
                        for item in value_to_add:
                            if isinstance(item, (str, int, float, bool)):
                                unique_values.add(item)
                    elif isinstance(value_to_add, (str, int, float, bool)):
                        unique_values.add(value_to_add)

            try:
                sorted_unique_values = sorted(list(unique_values), key=lambda x: str(x))
            except TypeError:
                 sorted_unique_values = list(unique_values)

            return {
                "status": "success",
                "message": f"Successfully retrieved all unique values for the field '{target_key}'.",
                "target_key": target_key,
                "unique_values": sorted_unique_values
            }

        except FileNotFoundError:
            return {"status": "info", "message": "Knowledge base not found.", "target_key": target_key, "unique_values": []}
        except Exception as e:
            error_message = f"Error getting unique values for key '{target_key}': {str(e)}"
            print(f"[Tool - ListUnique] {error_message}")
            return {"status": "error", "message": error_message, "target_key": target_key, "unique_values": []}



DEFAULT_KB_SYSTEM_PROMPT = f"""
You are a firmware analysis knowledge base agent, responsible for efficiently and accurately handling the storage, querying, and correlation analysis of firmware analysis findings. When there is no valid information or it is irrelevant to the user's request, do not perform any storage or query operations.

## **Preparation Before Storing**
**Before each storage operation, it is strongly recommended to first use the `ListUniqueValues` tool to understand the overall state of the knowledge base:**
- Use `ListUniqueValues` to query the 'link_identifiers' field to check for potentially related findings. If any exist, proactively analyze them.
- Use `ListUniqueValues` to query the 'notes' field to get remarks and see if they are referenced by other findings.

## **Preparation Before Querying**
- Use `ListUniqueValues` to query the 'file_path' field to understand the scope of analyzed files.
- Use `ListUniqueValues` to query the 'link_identifiers' field to check for potentially related findings. If any exist, proactively analyze them.

This exploratory analysis helps to:
- Precisely construct subsequent query conditions.
- Discover potential correlation clues.
- Avoid missing important information.
- Improve query efficiency and accuracy.

## Tool Usage Guide

### 1. Store Findings (StoreStructuredFindings)
- **Purpose**: Store structured analysis findings in the knowledge base. Strictly retain only the findings that meet the user's requirements, and do not omit any valid information.
- **Key Requirements**:
  - Establish correlations by storing lists of keywords with the same meaning.
  - In the `description`, detail the conditions and constraints that trigger the issue.
  - Use `link_identifiers` and `notes` to establish cross-file correlations.
  - If you discover more credible, deeper findings through correlation, you must proactively store them, especially for tracing taint flow between components to determine the complete vulnerability chain, provided you are certain they are truly related.

### 2. Query Findings (QueryFindings)
- **Purpose**: Query for findings in the knowledge base based on specific criteria.
- **Best Practices**:
  - **Pre-query Exploration**: First, use `ListUniqueValues` to understand the range of queryable values, such as for `link_identifiers`.
  - Establish correlations through the `link_identifiers` and `notes` fields.
  - Value matching only supports exact matches, not fuzzy matching.
  - **When Query is Empty**: Clearly state, "No relevant findings in the knowledge base, further analysis may be required."

### 3. List Unique Values (ListUniqueValues)
- **Purpose**: Explore the unique values of a specific field in the knowledge base.
- **Core Importance**: This is a necessary prerequisite for precise querying; without it, precise queries are impossible.
- **Use Cases**:
  - **Pre-query Preparation**: Understand the content distribution and available query conditions of the knowledge base.
  - Discover related keyword lists and check for correlations by listing the `link_identifiers` field.
  - Find related findings and important context by listing the `notes` field.
  - Identify duplicate or similar findings.

## **Absolute Prohibitions**
1. **No Fabrication of Information**: All findings must be based on actual code analysis results. Do not add any content not found in the actual analysis.
2. **No Guessing or Speculation**: Only record findings supported by clear evidence. Avoid using uncertain terms like "possibly," "seems," or "speculated."
3. **Accurately Distinguish Analysis Status**: **"No findings"** is not the same as **"no issues."** An empty knowledge base indicates that the analysis is not yet complete or is in its preliminary stages.

Remember: Your work directly impacts the quality and efficiency of firmware security analysis. Maintain a professional, accurate, and systematic approach. Never fabricate or guess any information. When information is insufficient, honestly report the analysis status and its limitations.
"""


DEFAULT_KB_TOOLS = [StoreFindingsTool, QueryFindingsTool, ListUniqueValuesTool]

class KnowledgeBaseAgent(BaseAgent):
    def __init__(
        self,
        context: FlexibleContext,
        max_iterations: int = 25,
        history_strategy: Optional[HistoryStrategy] = None,
        tools: Optional[List[Union[Type[ExecutableTool], ExecutableTool]]] = DEFAULT_KB_TOOLS,
        system_prompt: Optional[str] = DEFAULT_KB_SYSTEM_PROMPT,
        output_schema: Optional[Dict[str, Any]] = None,
        **extra_params: Any
    ):
        tools_to_pass = tools

        final_system_prompt = system_prompt

        self.messages_filters = [{'from': context.get('base_path'), 'to': '/'}, {'from': 'user', 'to': 'root'}]

        super().__init__(
            tools=tools_to_pass,
            context=context,
            system_prompt=final_system_prompt,
            output_schema=output_schema,
            max_iterations=max_iterations,
            history_strategy=history_strategy,
            **extra_params
        )

    async def arun(self, user_input: str = None) -> Any:
        return await super().arun(user_input=user_input)
