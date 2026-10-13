from typing import Dict, Generic, Iterator, Optional, Tuple, Type, TypeVar

EntryT = TypeVar("EntryT")
SubEntryT = TypeVar("SubEntryT")


class HandleManager(Generic[EntryT]):
    """Manage system resource handles.

    Args:
        start_value: Handle start value.
        max_num: Maximum handle limit.
    """

    def __init__(self, start_value: int, max_num: int):
        self.start_value = start_value
        self.max_num = max_num

        self._entries: Dict[int, EntryT] = {}

    def new(self, entry: EntryT, value: Optional[int] = None) -> Optional[int]:
        """Create a new resource handle.

        Returns:
            An int representing the resource handle on success, or None on failure.
        """
        for index in range(self.max_num):
            handle = self.start_value + index

            if value is not None and value != handle:
                continue

            if handle not in self._entries:
                self._entries[handle] = entry
                return handle

        return None

    def free(self, handle: int):
        """Release resource handle."""
        self._entries.pop(handle, None)

    def validate(self, handle: int) -> bool:
        """Check if a resource handle is valid."""
        return handle in self._entries

    def get(self, handle: int) -> Optional[EntryT]:
        """Get the entry bound to the handle."""
        return self._entries.get(handle)

    def get_as(self, handle: int, entry_cls: Type[SubEntryT]) -> Optional[SubEntryT]:
        """Get the entry bound to the handle, narrowed to `entry_cls`."""
        entry = self._entries.get(handle)
        if not isinstance(entry, entry_cls):
            return None
        return entry

    def items(self) -> Iterator[Tuple[int, EntryT]]:
        """Iterate all handle and entry pairs."""
        return iter(self._entries.items())
