from __future__ import annotations

import ctypes
from contextlib import contextmanager
from typing import Optional, Sequence, Union, TYPE_CHECKING

from .os.ios.structs import BlockLayout, BlockDescriptor
from .typing import CFObjConvertible, NSObjConvertible, HookFuncCallable
from .utils import struct2bytes

if TYPE_CHECKING:
    from .core import Chomper


class ObjC:
    """Provide an interface to Objective-C runtime."""

    def __init__(self, emu: Chomper):
        self.emu = emu

    def get_class(self, class_name: str) -> int:
        """Get class by name."""
        name_ptr = self.emu.create_string(class_name)

        try:
            return self.emu.call_symbol("_objc_getClass", name_ptr)
        finally:
            self.emu.free(name_ptr)

    def get_sel(self, sel_name: str) -> int:
        """Get selector by name."""
        name_ptr = self.emu.create_string(sel_name)

        try:
            return self.emu.call_symbol("_sel_registerName", name_ptr)
        finally:
            self.emu.free(name_ptr)

    def msg_send(
        self,
        receiver: Union[int, str],
        sel: Union[int, str],
        *args: Union[int, str],
        va_list: Optional[Sequence[int]] = None,
    ) -> int:
        """Send message to Objective-C runtime.

        Args:
            receiver: The message receiver, class or object. If is str,
                consider it as the class name.
            sel: The selector. If is str, consider it as the selector name.
            args: Parameters of the method to be called. If a str is passed in,
                it will be converted to a pointer to a C string.
            va_list: Variable number of arguments.
        """
        receiver = self.get_class(receiver) if isinstance(receiver, str) else receiver
        sel = self.get_sel(sel) if isinstance(sel, str) else sel

        mem_ptrs = []
        new_args = []

        for arg in args:
            if isinstance(arg, str):
                str_ptr = self.emu.create_string(arg)

                mem_ptrs.append(str_ptr)
                new_args.append(str_ptr)
            else:
                new_args.append(arg)

        try:
            return self.emu.call_symbol(
                "_objc_msgSend", receiver, sel, *new_args, va_list=va_list
            )
        finally:
            for mem_ptr in mem_ptrs:
                self.emu.free(mem_ptr)

    def release(self, obj: int):
        """Release object."""
        self.emu.call_symbol("_objc_release", obj)

    @contextmanager
    def autorelease_pool(self):
        """Ensure Objetive-C objects can be automatically released."""
        context = self.emu.call_symbol("_objc_autoreleasePoolPush")

        try:
            yield context
        finally:
            self.emu.call_symbol("_objc_autoreleasePoolPop", context)


class Block:
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
        """Wrap callback function as a raw address.

        Create a temporary address and forward the call to the specified function
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
        self.emu.write_bytes(desc, struct2bytes(st))

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
        self.emu.write_bytes(layout, struct2bytes(st))

        for index, var in enumerate(variables):
            self.emu.write_u64(layout + 0x20 + index * 0x8, var)

        return layout


def pyobj2nsobj(emu: Chomper, obj: NSObjConvertible) -> int:
    """Convert Python object to NS object.

    Raises:
        TypeError: If object type is not supported.
    """
    objc = ObjC(emu)

    mem_ptrs = []

    if isinstance(obj, dict):
        ns_obj = objc.msg_send("NSMutableDictionary", "dictionary")

        for key, value in obj.items():
            ns_key = pyobj2nsobj(emu, key)
            ns_value = pyobj2nsobj(emu, value)

            objc.msg_send(ns_obj, "setObject:forKey:", ns_value, ns_key)
    elif isinstance(obj, list):
        ns_obj = objc.msg_send("NSMutableArray", "array")

        for item in obj:
            ns_item = pyobj2nsobj(emu, item)
            objc.msg_send(ns_obj, "addObject:", ns_item)
    elif isinstance(obj, str):
        ns_obj = objc.msg_send("NSString", "stringWithUTF8String:", obj)
    elif isinstance(obj, bytes):
        if obj:
            buffer = emu.create_buffer(len(obj))
            emu.write_bytes(buffer, obj)
            mem_ptrs.append(buffer)
        else:
            buffer = 0

        ns_obj = objc.msg_send("NSData", "dataWithBytes:length:", buffer, len(obj))
    elif isinstance(obj, int):
        ns_obj = objc.msg_send("NSNumber", "numberWithInteger:", obj)
    else:
        raise TypeError(f"Unsupported type: {type(obj)}")

    for mem_ptr in mem_ptrs:
        emu.free(mem_ptr)

    return ns_obj


def pyobj2cfobj(emu: Chomper, obj: CFObjConvertible) -> int:
    """Convert Python object to CF object.

    Raises:
        TypeError: If object type is not supported.
    """
    cf_allocator_system_default = emu.find_symbol("___kCFAllocatorSystemDefault")

    mem_ptrs = []
    cf_strs = []

    if isinstance(obj, dict):
        cf_copy_string_dictionary_key_callbacks = emu.find_symbol(
            "_kCFCopyStringDictionaryKeyCallBacks"
        )
        cf_type_dictionary_value_callbacks = emu.find_symbol(
            "_kCFTypeDictionaryValueCallBacks"
        )

        cf_obj = emu.call_symbol(
            "_CFDictionaryCreateMutable",
            cf_allocator_system_default.address,
            0,
            cf_copy_string_dictionary_key_callbacks.address,
            cf_type_dictionary_value_callbacks.address,
        )

        for key, value in obj.items():
            cf_key = pyobj2cfobj(emu, key)
            cf_value = pyobj2cfobj(emu, value)

            cf_strs.append(cf_key)
            cf_strs.append(cf_value)

            emu.call_symbol("_CFDictionaryAddValue", cf_obj, cf_key, cf_value)
    elif isinstance(obj, list):
        cf_type_array_callbacks = emu.find_symbol("_kCFTypeArrayCallBacks")

        cf_obj = emu.call_symbol(
            "_CFArrayCreateMutable",
            cf_allocator_system_default.address,
            0,
            cf_type_array_callbacks.address,
        )

        for item in obj:
            cf_item = pyobj2cfobj(emu, item)
            emu.call_symbol("_CFArrayAppendValue", cf_obj, cf_item)
    elif isinstance(obj, str):
        str_ptr = emu.create_string(obj)
        mem_ptrs.append(str_ptr)

        cf_obj = emu.call_symbol(
            "_CFStringCreateWithCString",
            cf_allocator_system_default.address,
            str_ptr,
            0x8000100,
        )
    elif isinstance(obj, bytes):
        if obj:
            buffer = emu.create_buffer(len(obj))
            emu.write_bytes(buffer, obj)
            mem_ptrs.append(buffer)
        else:
            buffer = 0

        cf_obj = emu.call_symbol(
            "_CFDataCreate",
            cf_allocator_system_default.address,
            buffer,
            len(obj),
        )
    elif isinstance(obj, int):
        buffer = emu.create_buffer(8)
        emu.write_s64(buffer, obj)
        mem_ptrs.append(buffer)

        cf_obj = emu.call_symbol(
            "_CFNumberCreate",
            cf_allocator_system_default.address,
            9,
            buffer,
        )
    else:
        raise TypeError(f"Unsupported type: {type(obj)}")

    for mem_ptr in mem_ptrs:
        emu.free(mem_ptr)

    for cf_str in cf_strs:
        emu.call_symbol("_CFRelease", cf_str)

    return cf_obj
