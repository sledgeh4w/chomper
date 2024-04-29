from typing import Union


class ObjC:
    """Provide an interface to Objective-C runtime."""

    def __init__(self, emu):
        self.emu = emu

        self._class_cache = {}
        self._sel_cache = {}

    def get_class(self, class_name: str) -> int:
        """Get class by name."""
        if class_name in self._class_cache:
            return self._class_cache[class_name]

        class_name_ptr = self.emu.create_string(class_name)

        cls = self.emu.call_symbol("_objc_getClass", class_name_ptr)
        self._class_cache[class_name] = cls

        return cls

    def get_sel(self, sel_name: str) -> int:
        """Get selector by name."""
        if sel_name in self._sel_cache:
            return self._sel_cache[sel_name]

        sel_name_ptr = self.emu.create_string(sel_name)

        sel = self.emu.call_symbol("_sel_registerName", sel_name_ptr)
        self._sel_cache[sel_name] = sel

        return sel

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

        c_strs = []
        args_ = []

        for arg in args:
            if isinstance(arg, str):
                c_str = self.emu.create_string(arg)

                c_strs.append(c_str)
                args_.append(c_str)

            else:
                args_.append(arg)

        try:
            return self.emu.call_symbol("_objc_msgSend", receiver, sel, *args_)

        finally:
            for c_str in c_strs:
                self.emu.free(c_str)

    def release(self, obj: int):
        """Release object."""
        self.emu.call_symbol("_objc_release", obj)
