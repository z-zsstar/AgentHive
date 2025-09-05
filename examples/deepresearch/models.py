from __future__ import annotations

import re
import json
import hashlib
import threading
from nanoid import generate
from typing import List, Optional, Dict, Any, Generator, Union, Tuple

class ReferenceManager:
    """管理引用来源并生成格式化的参考文献列表。"""
    def __init__(self):
        self._references: Dict[str, Tuple[int, str]] = {}
        self._counter: int = 1

    def _get_source_key(self, source: str) -> str:
        return hashlib.md5(source.strip().lower().encode()).hexdigest()

    def add_reference(self, source: str) -> int:
        if not source or not source.strip():
            raise ValueError("Reference source cannot be empty.")
        key = self._get_source_key(source)
        if key in self._references:
            return self._references[key][0]
        else:
            new_id = self._counter
            self._references[key] = (new_id, source.strip())
            self._counter += 1
            return new_id
    
    def remove_reference_by_source(self, source: str):
        key = self._get_source_key(source)
        if key in self._references:
            del self._references[key]

    def generate_references_section(self, title: str = "References") -> str:
        if not self._references: return ""
        sorted_refs = sorted(self._references.values(), key=lambda x: x[0])
        md = f"\n\n## {title}\n\n"
        for number, source in sorted_refs:
            md += f"{number}. {source}\n"
        return md

    def __repr__(self) -> str:
        return f"ReferenceManager(count={len(self._references)})"

class ContentBlock:
    """表示一个内容块，如段落、列表或代码块。"""
    def __init__(self, block_type: str, text: str = "", meta: Optional[Dict[str, Any]] = None):
        self.id: str = generate(size=8)
        self.type: str = block_type      
        self.text: str = text            
        self.meta: Dict[str, Any] = meta or {}

    def to_dict(self) -> Dict[str, Any]:
        return {'id': self.id, 'type': self.type, 'text': self.text, 'meta': self.meta, 'node_type': 'block'}

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ContentBlock":
        block = cls(block_type=data.get('type', 'paragraph'), text=data.get('text', ''), meta=data.get('meta', {}))
        block.id = data.get('id', block.id)
        return block

    def __repr__(self) -> str:
        return f"ContentBlock(id='{self.id}', type='{self.type}', text='{self.text[:30]}...')"

class ReportNode:
    """
    表示报告中的结构节点，如章节或小节。
    该类采用统一内容模型，所有内容（包括ContentBlock和子ReportNode）都存储在content_items列表中，顺序即为渲染顺序。
    """
    def __init__(self, parent: Optional[ReportNode] = None, meta: Optional[Dict[str, Any]] = None):
        """
        初始化节点。
        - id: 节点唯一标识
        - parent: 父节点，根节点为None
        - content_items: 内容项列表，包含ContentBlock和ReportNode
        - meta: 元数据字典
        """
        self.id: str = generate(size=8)
        self.parent: Optional[ReportNode] = parent
        self.content_items: List[Union[ContentBlock, "ReportNode"]] = []
        self.meta: Dict[str, Any] = meta or {}
        self.lock = threading.RLock() 

    @property
    def path(self) -> str:
        """
        计算并返回节点的数字路径（如'1'、'2-1'），基于其在父节点content_items中的位置动态生成。
        """
        if self.parent is None:
            return ""
        try: 
            sibling_nodes = [item for item in self.parent.content_items if isinstance(item, ReportNode)]
            index = sibling_nodes.index(self) + 1
        except ValueError: 
            return "detached"
        parent_path = self.parent.path
        return f"{parent_path}-{index}" if parent_path else str(index)

    def get_root(self) -> "ReportNode":
        """向上遍历树，返回根节点。"""
        node = self
        while node.parent is not None:
            node = node.parent
        return node

    def get_subtree_items(self) -> Generator[Union[ContentBlock, ReportNode], None, None]:
        """递归生成子树中的所有内容项（包括自身、内容块和子节点）。"""
        yield self
        for item in self.content_items:
            yield item
            if isinstance(item, ReportNode):
                yield from item.get_subtree_items()

    def get_item_by_id(self, item_id: str) -> Optional[Union[ContentBlock, ReportNode]]:
        """在整棵树中根据ID查找任意内容项（节点或块）。"""
        root = self.get_root()
        if root.id == item_id:
            return root
        for item in root.get_subtree_items():
            if item.id == item_id:
                return item
        return None

    def get_node_by_path(self, path: str) -> Optional[ReportNode]:
        """根据完整数字路径查找节点，从根节点开始。"""
        if not path:
            return self.get_root()
        current_node = self.get_root()
        for part in path.split('-'):
            try:
                index = int(part) - 1
                if index < 0: return None
                child_nodes = [item for item in current_node.content_items if isinstance(item, ReportNode)]
                current_node = child_nodes[index]
            except (ValueError, IndexError): 
                return None
        return current_node

    def add_item(
        self, 
        item: Union[ContentBlock, "ReportNode"], 
        insert_after_id: Optional[str] = None, 
        insert_before_id: Optional[str] = None
    ) -> bool:
        """
        向此节点的内容中添加一个ContentBlock或子ReportNode。
        支持在指定ID之前或之后插入，或在末尾追加。
        """
        with self.lock:
            if insert_after_id and insert_before_id:
                raise ValueError("'insert_after_id' and 'insert_before_id' cannot be used at the same time.")

            if isinstance(item, ReportNode):
                item.parent = self

            if insert_before_id:
                for i, existing_item in enumerate(self.content_items):
                    if existing_item.id == insert_before_id:
                        self.content_items.insert(i, item)
                        return True
                return False

            if insert_after_id:
                for i, existing_item in enumerate(self.content_items):
                    if existing_item.id == insert_after_id:
                        self.content_items.insert(i + 1, item)
                        return True
                return False
            
            self.content_items.append(item)
            return True

    def delete_item(self, item_id: str) -> bool:
        """根据ID删除此节点内容中的任意项（节点或块）。"""
        with self.lock:
            for i, item in enumerate(self.content_items):
                if item.id == item_id:
                    del self.content_items[i]
                    return True
            return False

    def update_block_text(self, block_id: str, new_text: str) -> bool:
        """根据ID更新指定ContentBlock的文本内容。"""
        item = self.get_item_by_id(block_id)
        if isinstance(item, ContentBlock):
            with self.lock:
                item.text = new_text
                return True
        return False

    def to_dict(self) -> Dict[str, Any]:
        """
        将节点及其内容序列化为字典。
        """
        with self.lock:
            return {
                'id': self.id,
                'path': self.path,
                'meta': self.meta,
                'node_type': 'node',
                'content_items': [item.to_dict() for item in self.content_items]
            }

    @classmethod
    def from_dict(cls, data: Dict[str, Any], parent: Optional[ReportNode] = None) -> ReportNode:
        """将字典反序列化为ReportNode实例。"""
        node = cls(meta=data.get('meta', {}), parent=parent)
        node.id = data.get('id', node.id)
        item_data_list = data.get('content_items', [])
        for item_data in item_data_list:
            if item_data.get('node_type') == 'node':
                child_node = cls.from_dict(item_data, parent=node)
                node.content_items.append(child_node)
            else:
                block = ContentBlock.from_dict(item_data)
                node.content_items.append(block)
        return node
    
    def to_markdown(self) -> str:
        """
        将本节点及其整个子树渲染为Markdown字符串。
        """
        md_parts = []
        with self.lock:
            for item in self.content_items:
                if isinstance(item, ContentBlock):
                    md_parts.append(item.text)
                elif isinstance(item, ReportNode):
                    md_parts.append(item.to_markdown())
        full_md = "\n\n".join(part for part in md_parts if part and part.strip())
        return full_md
        
    def __repr__(self) -> str:
        path_str = self.path or "root"
        return f"ReportNode(id='{self.id}', path='{path_str}', items={len(self.content_items)})"

    def to_json_str(self, indent: int = 2) -> str:
        """将节点的字典表示格式化为JSON字符串。"""
        return json.dumps(self.to_dict(), ensure_ascii=False, indent=indent)
    
    def search_content(self, query: str) -> List[Dict[str, Any]]:
        """在子树中所有ContentBlock的文本中搜索指定字符串。"""
        results = []
        for item in self.get_subtree_items():
            if isinstance(item, ContentBlock):
                if re.search(query, item.text, re.IGNORECASE):
                    current = item
                    parent_node = self
                    root = self.get_root()
                    for node in root.get_subtree_items():
                        if isinstance(node, ReportNode) and item in node.content_items:
                            parent_node = node
                            break
                    results.append({
                        "parent_node_path": parent_node.path,
                        "parent_node_id": parent_node.id,
                        "matching_block": item.to_dict() 
                    })
        return results