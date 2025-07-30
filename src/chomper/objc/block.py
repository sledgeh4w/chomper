from __future__ import annotations

import ctypes
from typing import Optional, Sequence, Union, TYPE_CHECKING

from chomper.typing import HookFuncCallable
from chomper.utils import struct_to_bytes

if TYPE_CHECKING:
    from chomper.core import Chomper


class BlockLayout(ctypes.Structure):
    _fields_ = [
        ("isa", ctypes.c_uint64),
        ("flags", ctypes.c_uint32),
        ("reserved", ctypes.c_uint32),
        ("invoke", ctypes.c_uint64),
        ("desc", ctypes.c_uint64),
    ]


class BlockDescriptor(ctypes.Structure):
    _fields_ = [
        ("reserved", ctypes.c_uint64),
        ("block_size", ctypes.c_uint64),
        ("copy", ctypes.c_uint64),
        ("dispose", ctypes.c_uint64),
    ]


class ObjcBlock:
    """Provide Block wrapper in Objective-C.

    Currently only considering blocks of type `_NSConcreteGlobalBlock`.

    Args:
        emu: The emulator.
        invoke: Invoke address. If this is function, an interceptor will be added
            and called back to the specified function.
        variables: Variables captured by the Block.
        user_data: If ``invoke`` is function, this will be passed to the interceptor.
    """

    def __init__(
        self,
        emu: Chomper,
        invoke: Union[int, HookFuncCallable],
        variables: Optional[Sequence[int]] = None,
        user_data: Optional[dict] = None,
    ):
        self.emu = emu

        if variables is None:
            variables = []

        self._indirect_invoke: Optional[int] = None
        self._indirect_handle: Optional[int] = None

        if callable(invoke):
            invoke = self._wrap_callback(invoke, user_data=user_data)

        self._size = 0x20 + len(variables) * 0x8

        self._desc = self._create_block_desc(self._size)
        self._layout = self._create_block_layout(invoke, self._desc, variables)

    @property
    def size(self) -> int:
        """Actual size in memory."""
        return self._size

    @property
    def address(self) -> int:
        """Actual address in memory."""
        return self._layout

    def __del__(self):
        """Release memories and remove hooks."""
        if self._indirect_invoke:
            self.emu.free(self._indirect_invoke)

        if self._indirect_handle:
            self.emu.del_hook(self._indirect_handle)

        self.emu.free(self._desc)
        self.emu.free(self._layout)

    def _wrap_callback(
        self, callback: HookFuncCallable, user_data: Optional[dict] = None
    ) -> int:
        """Create a temporary address and forward the call to the specified function
        through an interceptor.
        """
        user_data = {
            "block": self,
            **(user_data or {}),
        }

        self._indirect_invoke = self.emu.create_buffer(8)
        self._indirect_handle = self.emu.add_interceptor(
            self._indirect_invoke,
            callback=callback,
            user_data=user_data,
        )

        return self._indirect_invoke

    def _create_block_desc(self, block_size: int) -> int:
        """Create `Block_descriptor` struct."""
        st = BlockDescriptor(
            reserved=0,
            block_size=block_size,
        )

        desc = self.emu.create_buffer(ctypes.sizeof(st))
        self.emu.write_bytes(desc, struct_to_bytes(st))

        return desc

    def _create_block_layout(
        self, invoke: int, desc: int, variables: Sequence[int]
    ) -> int:
        """Create `Block_layout` struct."""
        st = BlockLayout(
            isa=self.emu.find_symbol("__NSConcreteGlobalBlock").address,
            flags=0x50000000,
            reserved=0,
            invoke=invoke,
            desc=desc,
        )

        layout = self.emu.create_buffer(self._size)
        self.emu.write_bytes(layout, struct_to_bytes(st))

        for index, var in enumerate(variables):
            self.emu.write_u64(layout + 0x20 + index * 0x8, var)

        return layout
