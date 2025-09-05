import copy
from abc import ABC, abstractmethod
from typing import Dict, Any, Optional, Set


class FlexibleContext:
    """
    A shared context class for tools, allowing arbitrary key-value pairs to be passed
    during initialization and stored as instance attributes.
    """
    def __init__(self, **kwargs: Any):
        self.file_path: Optional[str] = None
        # A set of keys that should be shallow-copied during a deep copy operation.
        self._shallow_copy_keys: Set[str] = set(kwargs.pop('_shallow_copy_keys', []))
        for key, value in kwargs.items():
            setattr(self, key, value)

    def __repr__(self) -> str:
        items = (f"{k}={v!r}" for k, v in self.__dict__.items() if k != '_shallow_copy_keys')
        return f"{type(self).__name__}({', '.join(items)})"

    def get(self, key: str, default: Any = None) -> Any:
        return getattr(self, key, default)

    def set(self, key: str, value: Any, shallow_copy: bool = False) -> None:
        """
        Sets a key-value pair in the context.

        Args:
            key (str): The key to set.
            value (Any): The value to associate with the key.
            shallow_copy (bool): If True, this key will be registered for shallow copying
                                 when the context's `copy()` method is called. Defaults to False.
        """
        setattr(self, key, value)
        if shallow_copy:
            self.add_shallow_copy_key(key)
        else:
            self._shallow_copy_keys.discard(key)

    def add_shallow_copy_key(self, key: str):
        """Register a key for shallow copying."""
        self._shallow_copy_keys.add(key)
        
    def copy(self) -> 'FlexibleContext':
        """
        执行一次深拷贝 (deep copy)，但对于在 _shallow_copy_keys 中指定的键，
        则执行浅拷贝。
        这将创建 context 的一个大部分独立的副本。
        """
        new_context = self.__class__()
        for k, v in self.__dict__.items():
            if k == '_shallow_copy_keys':
                # The set of keys itself should be copied.
                setattr(new_context, k, v.copy())
            elif k in self._shallow_copy_keys:
                # Shallow copy for specified keys
                setattr(new_context, k, v)
            else:
                # Deep copy for all other keys
                setattr(new_context, k, copy.deepcopy(v))
        return new_context

    def shallow_copy(self) -> 'FlexibleContext':
        new_context = self.__class__()
        new_context.__dict__.update(self.__dict__)
        return new_context
    
    def __contains__(self, key: str) -> bool:
        return key in self.__dict__ or hasattr(self, key)

    def update(self, other_dict: Optional[Dict[str, Any]] = None, **kwargs: Any) -> None:
        if other_dict:
            for key, value in other_dict.items():
                setattr(self, key, value)
        for key, value in kwargs.items():
            setattr(self, key, value)

class ExecutableTool(ABC):
    name: str
    description: str
    parameters: Dict[str, Any]
    timeout: int = 30

    def __init__(self, context: Optional[FlexibleContext] = None):
        self.context = context

    @abstractmethod
    def execute(self, **kwargs: Any) -> str:
        pass

