from typing import Any, Dict, Optional, Set


class HandleManager:
    """Manage system resource handles.

    Args:
        start_value: Handle start value.
        max_num: Maximum handle limit.
    """

    def __init__(self, start_value: int, max_num: int):
        self.start_value = start_value
        self.max_num = max_num

        self._handles: Set[int] = set()
        self._handle_props: Dict[int, dict] = {}

    def new(self) -> Optional[int]:
        """Create a new resource handle.

        Returns:
            An int representing the resource handle on success, or None on failure.
        """
        for index in range(self.max_num):
            handle = self.start_value + index

            if handle not in self._handles:
                self._handles.add(handle)
                self._handle_props[handle] = {}
                return handle

        return None

    def free(self, handle: int):
        """Release resource handle."""
        if handle not in self._handles:
            return

        self._handles.remove(handle)
        del self._handle_props[handle]

    def validate(self, handle: int) -> bool:
        """Check if a resource handle is valid."""
        return handle in self._handles

    def set_prop(self, handle: int, name: str, value: Any):
        """Set property value for a resource."""
        if handle not in self._handles:
            return

        self._handle_props[handle][name] = value

    def get_prop(self, handle: int, name: str) -> Optional[Any]:
        """Get property value for a resource."""
        if handle not in self._handles:
            return None

        if name not in self._handle_props[handle]:
            return None

        return self._handle_props[handle][name]

    def has_prop(self, handle: int, name: str) -> bool:
        """Check if the property exists."""
        if handle not in self._handles:
            return False

        return name in self._handle_props[handle]
