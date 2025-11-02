from __future__ import annotations

from typing import TYPE_CHECKING, List

if TYPE_CHECKING:
    from chomper.core import Chomper


class MemoryContextManager:
    """Track memory allocations and release on exit."""

    def __init__(self, emu: Chomper):
        self.emu = emu

        # Tracking memory
        self._tracks: List[int] = []

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        for mem in self._tracks:
            self.emu.free(mem)

        return False

    def _add_track(self, mem: int):
        self._tracks.append(mem)

    def create_buffer(self, size: int) -> int:
        mem = self.emu.create_buffer(size)
        self._add_track(mem)
        return mem

    def create_string(self, string: str) -> int:
        mem = self.emu.create_string(string)
        self._add_track(mem)
        return mem
