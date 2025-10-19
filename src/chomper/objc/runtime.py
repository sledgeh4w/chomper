from __future__ import annotations

from contextlib import contextmanager
from typing import List, Optional, Sequence, Union, TYPE_CHECKING

from chomper.exceptions import EmulatorCrashed
from chomper.typing import ReturnType, NSObjConvertible, CFObjConvertible

from .types import ObjcType, ObjcClass, ObjcObject, ObjcProtocol


if TYPE_CHECKING:
    from chomper.core import Chomper


class ObjcRuntime:
    """Provide an interface to Objective-C runtime."""

    def __init__(self, emu: Chomper):
        self.emu = emu

    def selector(self, sel_name: str) -> int:
        """Get selector by name."""
        name_buf = self.emu.create_string(sel_name)

        try:
            return self.emu.call_symbol("_sel_registerName", name_buf)
        finally:
            self.emu.free(name_buf)

    def find_class(self, name: str) -> ObjcClass:
        """Find class by name.

        Args:
            name: Target class name.

        Raises:
            ValueError: If class not found.
        """
        name_buf = self.emu.create_string(name)

        try:
            class_value = self.emu.call_symbol("_objc_getClass", name_buf)
            if not class_value:
                raise ValueError(f"ObjC class '{name}' not found")

            return ObjcClass(self, class_value)
        finally:
            self.emu.free(name_buf)

    def find_protocol(self, name: str) -> ObjcProtocol:
        """Find protocol by name.

        Args:
            name: Target protocol name.

        Raises:
            ValueError: If protocol not found.
        """
        name_buf = self.emu.create_string(name)

        try:
            protocol_value = self.emu.call_symbol("_objc_getProtocol", name_buf)
            if not protocol_value:
                raise ValueError(f"ObjC protocol '{name}' not found")

            return ObjcProtocol(self, protocol_value)
        finally:
            self.emu.free(name_buf)

    def msg_send(
        self,
        receiver: Union[int, str, ObjcType],
        sel: Union[int, str],
        *args: Union[int, str, ObjcType],
        va_list: Optional[Sequence[Union[int, str, ObjcType]]] = None,
    ) -> Union[int, ObjcObject]:
        """Send message to Objective-C runtime.

        Args:
            receiver: The message receiver, class or object. If is str,
                consider it as the class name.
            sel: The selector. If is str, consider it as the selector name.
            args: Parameters of the method to be called. If a str is passed in,
                it will be converted to a pointer to a C string.
            va_list: Variable argument list.

        Returns:
            The result of this call. Its type depends on the return type of
            the method. If the return type is an object, the result is wrapped
            in an `ObjcObject`. In other cases, it directly returns the primitive
            integer value.
        """
        is_class_method = False
        return_type = ""

        if isinstance(receiver, str):
            receiver = self.find_class(receiver).value
            is_class_method = True
        elif isinstance(receiver, ObjcType):
            if isinstance(receiver, ObjcClass):
                is_class_method = True
            elif isinstance(receiver, ObjcObject) and receiver.is_class:
                is_class_method = True

            receiver = receiver.value

        if isinstance(sel, str):
            sel_name = sel
            sel = self.selector(sel_name)
        else:
            sel_name = self.emu.read_string(sel)

        try:
            if is_class_method:
                objc_class = ObjcClass(self, receiver)
                method = objc_class.get_class_method(sel_name)
            else:
                objc_class = ObjcObject(self, receiver).class_
                method = objc_class.get_instance_method(sel_name)

            return_type = method.return_type
        except (ValueError, EmulatorCrashed):
            # Failed to recognize the return type of the method,
            # typically because the selector is invalid.
            pass

        buf_list = []

        new_args: List[int] = []
        new_va_list: List[int] = []

        for old, new in zip((args, va_list or []), (new_args, new_va_list)):
            for arg in old:
                if isinstance(arg, str):
                    buf = self.emu.create_string(arg)
                    buf_list.append(buf)

                    new.append(buf)
                elif isinstance(arg, ObjcType):
                    new.append(arg.value)
                else:
                    new.append(arg)

        try:
            native_return_type: ReturnType = "int"

            if return_type == "f":
                native_return_type = "float"
            elif return_type == "d":
                native_return_type = "double"

            retval = self.emu.call_symbol(
                "_objc_msgSend",
                receiver,
                sel,
                *new_args,
                va_list=new_va_list,
                return_type=native_return_type,
            )

            if return_type.startswith("@") and return_type != "@?":
                return ObjcObject(self, retval)
            elif return_type == "v":
                return 0

            return retval
        finally:
            for buf in buf_list:
                self.emu.free(buf)

    def release(
        self,
        value: Union[int, ObjcType],
    ):
        """Release object."""
        if isinstance(value, ObjcType):
            value = value.value

        self.emu.call_symbol("_objc_release", value)

    @contextmanager
    def autorelease_pool(self):
        """Ensure Objetive-C objects can be automatically released."""
        context = self.emu.call_symbol("_objc_autoreleasePoolPush")

        try:
            yield context
        finally:
            self.emu.call_symbol("_objc_autoreleasePoolPop", context)

    def _create_ns_object(self, value: NSObjConvertible) -> ObjcObject:
        """Create a NS object based on Python types.

        Raises:
            TypeError: If object type is not supported.
        """
        buf_list = []

        if isinstance(value, dict):
            ns_obj = self.msg_send("NSMutableDictionary", "dictionary")
            assert ns_obj

            for key, value in value.items():
                ns_key = self._create_ns_object(key)
                ns_value = self._create_ns_object(value)

                self.msg_send(ns_obj, "setObject:forKey:", ns_value, ns_key)
        elif isinstance(value, list):
            ns_obj = self.msg_send("NSMutableArray", "array")
            assert ns_obj

            for item in value:
                ns_item = self._create_ns_object(item)
                self.msg_send(ns_obj, "addObject:", ns_item)
        elif isinstance(value, str):
            ns_obj = self.msg_send("NSString", "stringWithUTF8String:", value)
        elif isinstance(value, bytes):
            if value:
                buffer = self.emu.create_buffer(len(value))
                self.emu.write_bytes(buffer, value)
                buf_list.append(buffer)
            else:
                buffer = 0

            ns_obj = self.msg_send(
                "NSData", "dataWithBytes:length:", buffer, len(value)
            )
        elif isinstance(value, int):
            ns_obj = self.msg_send("NSNumber", "numberWithInteger:", value)
        else:
            raise TypeError(f"Unsupported type: {type(value)}")

        for buf in buf_list:
            self.emu.free(buf)

        assert isinstance(ns_obj, ObjcObject)
        return ns_obj

    def create_ns_number(self, value: int) -> ObjcObject:
        return self._create_ns_object(value)

    def create_ns_string(self, value: str) -> ObjcObject:
        return self._create_ns_object(value)

    def create_ns_data(self, value: bytes) -> ObjcObject:
        return self._create_ns_object(value)

    def create_ns_array(self, value: list) -> ObjcObject:
        return self._create_ns_object(value)

    def create_ns_dictionary(self, value: dict) -> ObjcObject:
        return self._create_ns_object(value)

    def _create_cf_object(self, value: CFObjConvertible) -> int:
        """Create an CF object based on Python types.

        Raises:
            TypeError: If object type is not supported.
        """
        cf_allocator_system_default = self.emu.find_symbol(
            "___kCFAllocatorSystemDefault"
        )

        buf_list = []
        cf_strs = []

        if isinstance(value, dict):
            cf_copy_string_dictionary_key_callbacks = self.emu.find_symbol(
                "_kCFCopyStringDictionaryKeyCallBacks"
            )
            cf_type_dictionary_value_callbacks = self.emu.find_symbol(
                "_kCFTypeDictionaryValueCallBacks"
            )

            cf_obj = self.emu.call_symbol(
                "_CFDictionaryCreateMutable",
                cf_allocator_system_default.address,
                0,
                cf_copy_string_dictionary_key_callbacks.address,
                cf_type_dictionary_value_callbacks.address,
            )

            for key, value in value.items():
                cf_key = self._create_cf_object(key)
                cf_value = self._create_cf_object(value)

                cf_strs.append(cf_key)
                cf_strs.append(cf_value)

                self.emu.call_symbol("_CFDictionaryAddValue", cf_obj, cf_key, cf_value)
        elif isinstance(value, list):
            cf_type_array_callbacks = self.emu.find_symbol("_kCFTypeArrayCallBacks")

            cf_obj = self.emu.call_symbol(
                "_CFArrayCreateMutable",
                cf_allocator_system_default.address,
                0,
                cf_type_array_callbacks.address,
            )

            for item in value:
                cf_item = self._create_cf_object(item)
                self.emu.call_symbol("_CFArrayAppendValue", cf_obj, cf_item)
        elif isinstance(value, str):
            str_ptr = self.emu.create_string(value)
            buf_list.append(str_ptr)

            cf_obj = self.emu.call_symbol(
                "_CFStringCreateWithCString",
                cf_allocator_system_default.address,
                str_ptr,
                0x8000100,
            )
        elif isinstance(value, bytes):
            if value:
                buffer = self.emu.create_buffer(len(value))
                self.emu.write_bytes(buffer, value)
                buf_list.append(buffer)
            else:
                buffer = 0

            cf_obj = self.emu.call_symbol(
                "_CFDataCreate",
                cf_allocator_system_default.address,
                buffer,
                len(value),
            )
        elif isinstance(value, int):
            buffer = self.emu.create_buffer(8)
            self.emu.write_s64(buffer, value)
            buf_list.append(buffer)

            cf_obj = self.emu.call_symbol(
                "_CFNumberCreate",
                cf_allocator_system_default.address,
                9,
                buffer,
            )
        else:
            raise TypeError(f"Unsupported type: {type(value)}")

        for buf in buf_list:
            self.emu.free(buf)

        for cf_str in cf_strs:
            self.emu.call_symbol("_CFRelease", cf_str)

        return cf_obj

    def create_cf_number(self, value: int) -> int:
        return self._create_cf_object(value)

    def create_cf_string(self, value: str) -> int:
        return self._create_cf_object(value)

    def create_cf_data(self, value: bytes) -> int:
        return self._create_cf_object(value)

    def create_cf_array(self, value: list) -> int:
        return self._create_cf_object(value)

    def create_cf_dictionary(self, value: dict) -> int:
        return self._create_cf_object(value)
