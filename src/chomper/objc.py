from contextlib import contextmanager
from typing import Union


class ObjC:
    """Provide an interface to Objective-C runtime."""

    def __init__(self, emu):
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

    def msg_send(self, receiver: Union[int, str], sel: Union[int, str], *args) -> int:
        """Send message to Objective-C runtime.

        Args:
            receiver: The message receiver, class or object. If is str,
                consider it as the class name.
            sel: The selector. If is str, consider it as the selector name.
            args: Parameters of the method to be called. If a str is passed in,
                it will be converted to a pointer to a C string.
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
            return self.emu.call_symbol("_objc_msgSend", receiver, sel, *new_args)

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
