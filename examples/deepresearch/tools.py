import copy
import json
import re
from typing import Optional, List, Union
import traceback

from agenthive.tools.basetool import ExecutableTool
from deepresearch.models import ReportNode, ContentBlock, ReferenceManager

class AddItemTool(ExecutableTool):
    """
    用于向报告添加新内容或结构的主要工具。
    它可以创建并插入章节节点和内容块（如段落、列表）。
    插入位置可以通过ID被精确控制。
    """
    name = "add_item"
    description = (
        "向报告添加一个新项目（章节容器或内容块）。"
        "使用 'item_type' 指定创建的类型。"
        "使用 'insert_after_id' 或 'insert_before_id' 来精确放置新项目。"
    )
    
    _parameters_template = {
        "type": "object",
        "properties": {
            "parent_path": {
                "type": "string",
                "description": "新项目要添加到的父章节的数字路径 (例如 '1', '2-1')。"
            },
            "item_type": {
                "type": "string",
                "enum": ["chapter", "paragraph", "list", "code", "table", "heading"],
                "description": "要创建的项目的类型。使用 'chapter' 创建新的空子章节容器。注意子章节需要`heading`，但是如果编写段落需要`text`。"
            },
            "text": {
                "type": "string",
                "description": "项目的文本内容，对于内容块是必需的。使用Markdown格式。如果 'item_type' 是 'chapter' 则忽略。"
            },
            "insert_after_id": {
                "type": "string",
                "description": "(可选) 一个现有项目的ID。新项目将被插入到该项之后。不能与 'insert_before_id' 同时使用。"
            },
            "insert_before_id": {
                "type": "string",
                "description": "(可选) 一个现有项目的ID。新项目将被插入到该项之前。用于在特定位置或文档开头插入。不能与 'insert_after_id' 同时使用。"
            },
            "source": {
                "type": "string",
                "description": "(可选) 内容的引用来源URL或标识符。"
            }
        },
    }

    @property
    def parameters(self) -> dict:
        workspace_path = self.context.get("workspace_node_path", "")
        path_str = f"'{workspace_path}'" if workspace_path else "根目录 ('')"
        params = copy.deepcopy(self._parameters_template)
        params["properties"]["parent_path"]["description"] = (
            f"你的当前工作区是 {path_str}。'parent_path' 必须是此路径或其子路径。默认值是当前工作区路径。" +
            self._parameters_template["properties"]["parent_path"]["description"]
        )
        return params

    def execute(
        self,
        parent_path: str,
        item_type: str,
        text: Optional[str] = None,
        insert_after_id: Optional[str] = None,
        insert_before_id: Optional[str] = None,
        source: Optional[str] = None
    ) -> str:
        """
        向报告树中插入新项目（章节或内容块）。
        """
        try:
            report_tree: Optional[ReportNode] = self.context.get("report_tree")
            ref_manager: Optional[ReferenceManager] = self.context.get("reference_manager")
            workspace_path: str = self.context.get("workspace_node_path", "")

            if not all([isinstance(report_tree, ReportNode), isinstance(ref_manager, ReferenceManager)]):
                return "错误：上下文中未找到 report_tree 或 reference_manager。"

            if not parent_path.startswith(workspace_path) and workspace_path != "":
                 return f"错误：权限被拒绝。你的工作区是 '{workspace_path}'，不能在 '{parent_path}' 中操作。"

            parent_node = report_tree.get_node_by_path(parent_path)
            if not parent_node:
                return f"错误：找不到路径为 '{parent_path}' 的父章节。"

            new_item: Optional[Union[ContentBlock, ReportNode]] = None
            if item_type == "chapter":
                new_item = ReportNode()
            else:
                if text is None:
                    return f"错误：'text' 参数对于 item_type '{item_type}' 是必需的。"
                block_text = text
                block_meta = {}
                ref_id = None
                if source and source.strip():
                    ref_id = ref_manager.add_reference(source)
                    block_text += f" [{ref_id}]"
                    block_meta['reference_ids'] = [ref_id]
                new_item = ContentBlock(block_type=item_type, text=block_text, meta=block_meta)
            
            success = parent_node.add_item(
                new_item, 
                insert_after_id=insert_after_id, 
                insert_before_id=insert_before_id
            )

            if not success:
                target_id = insert_before_id or insert_after_id
                return f"错误：插入失败。无法在父章节 '{parent_path}' 中找到ID为 '{target_id}' 的锚点项目。"
            
            item_id = new_item.id
            item_path_info = f"，其新路径为 '{new_item.path}'" if isinstance(new_item, ReportNode) else ""

            return f"成功：一个新的 '{item_type}' 项目 (ID: {item_id}) 已添加到章节 '{parent_path}'{item_path_info}。"

        except ValueError as ve:
             return f"错误：{ve}"
        except Exception as e:
            traceback.print_exc()
            return f"在 add_item 中发生未知错误: {e}"

class DeleteItemTool(ExecutableTool):
    """
    永久删除报告中的任意项目（内容块或整个章节）。
    """
    name = "delete_item"
    description = "通过唯一ID删除任意项目（内容块或整个章节及其内容）。"
    
    parameters = {
        "type": "object",
        "properties": {
            "item_id": {
                "type": "string",
                "description": "要删除的项目的唯一ID。"
            }
        },
        "required": ["item_id"]
    }
    
    def _find_parent_node(self, root_node: ReportNode, item_id: str) -> Optional[ReportNode]:
        """
        查找某个项目的直接父节点。
        """
        for node in root_node.get_subtree_items():
            if isinstance(node, ReportNode):
                for item in node.content_items:
                    if item.id == item_id:
                        return node
        return None

    def execute(self, item_id: str) -> str:
        """
        删除指定ID的项目（内容块或章节）。
        """
        try:
            report_tree: Optional[ReportNode] = self.context.get("report_tree")
            workspace_path: str = self.context.get("workspace_node_path", "")

            if not isinstance(report_tree, ReportNode):
                return "Error: Could not find report_tree in the context."

            item_to_delete = report_tree.get_item_by_id(item_id)
            if not item_to_delete:
                return f"Error: No item found with ID '{item_id}'."

            parent_node = self._find_parent_node(report_tree, item_id)
            if not parent_node:
                return f"Error: Could not find the parent of item '{item_id}'. This might be the root node, which cannot be deleted."

            if not parent_node.path.startswith(workspace_path) and workspace_path != "":
                return f"Error: Permission denied. The item is in chapter '{parent_node.path}', which is outside your workspace '{workspace_path}'."

            if parent_node.delete_item(item_id):
                item_type = 'chapter' if isinstance(item_to_delete, ReportNode) else 'block'
                return f"Success: The {item_type} with ID '{item_id}' has been deleted from chapter '{parent_node.path}'."
            else:
                return f"Error: Failed to delete item with ID '{item_id}'."

        except Exception as e:
            return f"An unexpected error occurred in delete_item: {e}"

class GetNodeContentTool(ExecutableTool):
    """
    获取指定章节的内容，可选择结构化JSON或渲染后的Markdown格式。
    """
    name = "get_node_content"
    description = "获取某章节的内容。用'json'格式查看结构、ID和所有内容项，用'markdown'格式查看最终渲染结果。"

    parameters = {
        "type": "object",
        "properties": {
            "node_path": {
                "type": "string",
                "description": "要查看的目标章节的数字路径。"
            },
            "format": {
                "type": "string",
                "enum": ["json", "markdown"],
                "default": "json",
                "description": "输出格式。'json'显示完整结构和ID，'markdown'显示渲染文本。"
            }
        },
        "required": ["node_path"]
    }

    def execute(self, node_path: str, format: str = "json") -> str:
        """
        获取指定章节的内容，支持json或markdown格式。
        """
        try:
            report_tree: Optional[ReportNode] = self.context.get("report_tree")
            if not isinstance(report_tree, ReportNode):
                return "Error: Could not find report_tree in context."
            
            target_node = report_tree.get_node_by_path(node_path)
            if not target_node:
                return f"Error: Cannot find chapter at path '{node_path}'."

            if format == "json":
                return target_node.to_json_str()
            elif format == "markdown":
                return target_node.to_markdown()
            else:
                return f"Error: Invalid format '{format}'. Choose 'json' or 'markdown'."

        except Exception as e:
            return f"An unexpected error occurred in get_node_content: {e}"

class UpdateBlockTextTool(ExecutableTool):
    """
    更新已有内容块的文本内容和/或引用来源。
    """
    name = "update_block_text"
    description = "修改已有内容块（如段落、列表）的文本或引用。用于修正或重写内容。"
    
    parameters = {
        "type": "object",
        "properties": {
            "block_id": {
                "type": "string",
                "description": "要更新的内容块的唯一ID。"
            },
            "new_text": {
                "type": "string",
                "description": "(可选) 内容块的新文本。不包含引用标记如[1]。"
            },
            "new_source": {
                "type": "string",
                "description": "(可选) 新的引用来源。空字符串('')将移除现有引用。"
            }
        },
        "required": ["block_id"]
    }
    
    _find_parent_node = DeleteItemTool._find_parent_node

    def execute(self, block_id: str, new_text: Optional[str] = None, new_source: Optional[str] = None) -> str:
        """
        更新指定内容块的文本和/或引用来源。
        """
        if new_text is None and new_source is None:
            return "Error: You must provide either 'new_text' or 'new_source' to update."
        try:
            report_tree: Optional[ReportNode] = self.context.get("report_tree")
            ref_manager: Optional[ReferenceManager] = self.context.get("reference_manager")
            workspace_path: str = self.context.get("workspace_node_path", "")

            if not all([isinstance(report_tree, ReportNode), isinstance(ref_manager, ReferenceManager)]):
                return "Error: Could not find report_tree or reference_manager in the context."

            target_item = report_tree.get_item_by_id(block_id)
            if not target_item:
                return f"Error: No item found with ID '{block_id}'."
            if not isinstance(target_item, ContentBlock):
                return f"Error: Item '{block_id}' is a chapter, not a content block. This tool only updates content blocks."

            parent_node = self._find_parent_node(report_tree, block_id)
            if not parent_node:
                 return f"Error: Could not find the parent of block '{block_id}'."
            
            if not parent_node.path.startswith(workspace_path) and workspace_path != "":
                return f"Error: Permission denied. The block is in chapter '{parent_node.path}', which is outside your workspace '{workspace_path}'."

            text_to_update = new_text if new_text is not None else target_item.text
            text_to_update = re.sub(r'\s*\[\d+\]$', '', text_to_update).strip()

            if new_source is not None:
                target_item.meta.pop('reference_ids', None)
                if new_source.strip():
                    ref_id = ref_manager.add_reference(new_source)
                    text_to_update += f" [{ref_id}]"
                    target_item.meta['reference_ids'] = [ref_id]

            target_item.text = text_to_update

            return f"Success: Content block '{block_id}' has been updated."

        except Exception as e:
            return f"An unexpected error occurred in update_block_text: {e}"

class SearchReportContentTool(ExecutableTool):
    """
    在整个报告中搜索指定关键词或短语。
    """
    name = "search_report_content"
    description = "在报告所有文本内容中搜索关键词，返回匹配块及其位置。用于避免重复劳动。"
    
    parameters = {
        "type": "object",
        "properties": {
            "query": {
                "type": "string",
                "description": "要搜索的关键词或短语。"
            }
        },
        "required": ["query"]
    }

    def execute(self, query: str) -> str:
        """
        搜索报告内容，返回所有匹配项。
        """
        try:
            report_tree: Optional[ReportNode] = self.context.get("report_tree")
            if not isinstance(report_tree, ReportNode):
                return "Error: Could not find report_tree in context."

            search_results = report_tree.search_content(query)
            
            if not search_results:
                return f"Info: No content matching '{query}' was found in the report."
            
            return json.dumps(search_results, ensure_ascii=False, indent=2)

        except Exception as e:
            return f"An unexpected error occurred in search_report_content: {e}"