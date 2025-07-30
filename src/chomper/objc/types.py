from __future__ import annotations

from functools import cached_property

from typing import List, Optional, Sequence, Tuple, Type, TypeVar, Union, TYPE_CHECKING

if TYPE_CHECKING:
    from .runtime import ObjcRuntime


ObjcTypeT = TypeVar("ObjcTypeT", bound="ObjcType")


class ObjcType:
    """Base class for wrapping Objective-C types."""

    def __init__(self, runtime: ObjcRuntime, value: int = 0):
        self._runtime = runtime
        self._emu = self._runtime.emu

        if not isinstance(value, int):
            raise ValueError(f"Invalid value for ObjcType: {value}")

        self._value = value

    @property
    def value(self) -> int:
        """Raw value."""
        return self._value

    def __int__(self):
        return int(self.value)

    def __eq__(self, other):
        if isinstance(other, ObjcType):
            return self.value == other.value
        return NotImplemented

    def _get_by_name(
        self,
        get_func: str,
        name: str,
        objc_type_class: Type[ObjcTypeT],
    ) -> ObjcTypeT:
        name_buf = self._emu.create_string(name)

        try:
            ivar_value = self._emu.call_symbol(get_func, self.value, name_buf)
            return objc_type_class(self._runtime, ivar_value)
        finally:
            self._emu.free(name_buf)

    def _copy_list(
        self,
        copy_func: str,
        objc_type_class: Type[ObjcTypeT],
    ) -> List[ObjcTypeT]:
        value_list = []

        out_count = self._emu.create_buffer(8)

        retval = self._emu.call_symbol(copy_func, self.value, out_count)
        count = self._emu.read_u32(out_count)

        for index in range(count):
            value = self._emu.read_u64(retval + index * 8)
            value_list.append(objc_type_class(self._runtime, value))

        self._emu.free(retval)

        return value_list


class ObjcObject(ObjcType):
    """Wrap objects in Objective-C."""

    def __init__(self, runtime: ObjcRuntime, value: int):
        super().__init__(runtime, value)

        # if not self.value:
        #     raise ValueError(f"Invalid value for ObjcObject: {hex(self.value)}")

    @cached_property
    def class_(self) -> ObjcClass:
        retval = self._emu.call_symbol("_object_getClass", self.value)
        return ObjcClass(self._runtime, retval)

    @cached_property
    def class_name(self) -> str:
        retval = self._emu.call_symbol("_object_getClassName", self.value)
        return self._emu.read_string(retval)

    @cached_property
    def is_class(self) -> bool:
        return bool(self._emu.call_symbol("_object_isClass", self.value))

    def get_ivar(self, ivar: ObjcIvar) -> ObjcObject:
        retval = self._emu.call_symbol("_object_getIvar", self.value, ivar.value)
        return ObjcObject(self._runtime, retval)

    def set_ivar(self, ivar: ObjcIvar, new_value: ObjcObject):
        self._emu.call_symbol(
            "_object_setIvar", self.value, ivar.value, new_value.value
        )

    def get_variable(self, var_name: str) -> Union[int, ObjcObject]:
        """Get variable of the object by name.

        Args:
            var_name: The variable name.

        Returns:
            Depends on type encoding of the variable. If it is an object type, return
            an `ObjcObject`; if it is a complex struct type, return its address;
            otherwise, directly return an integer value.

        Raises:
            ValueError: If type encoding of the variable not supported.
        """
        ivar = self.class_.get_instance_variable(var_name)

        type_encoding = ivar.type_encoding
        address = self.value + ivar.offset

        if type_encoding == "c":
            return self._emu.read_s8(address)
        elif type_encoding == "s":
            return self._emu.read_s16(address)
        elif type_encoding in ("i", "l"):
            return self._emu.read_s32(address)
        elif type_encoding == "q":
            return self._emu.read_s64(address)
        elif type_encoding in ("C", "B"):
            return self._emu.read_u8(address)
        elif type_encoding == "S":
            return self._emu.read_u16(address)
        elif type_encoding in ("I", "L", "f"):
            return self._emu.read_u32(address)
        elif type_encoding in ("Q", "d", "@?", "#", ":"):
            return self._emu.read_u64(address)
        # Object types
        elif type_encoding.startswith("^") or type_encoding == "*":
            return self._emu.read_pointer(address)
        elif type_encoding.startswith("@"):
            value = self._emu.read_u64(address)
            return ObjcObject(self._runtime, value)
        # Complex struct types
        elif (
            type_encoding.startswith("{")
            or type_encoding.startswith("(")
            or type_encoding.startswith("[")
            or type_encoding.startswith("b")
        ):
            return address
        else:
            raise ValueError(f"Unsupported type encoding: '{type_encoding}'")

    def call_method(
        self,
        sel: Union[int, str],
        *args: Union[int, str, ObjcType],
        va_list: Optional[Sequence[Union[int, str, ObjcType]]] = None,
    ) -> Union[int, ObjcObject]:
        return self._runtime.msg_send(self._value, sel, *args, va_list=va_list)


class ObjcClass(ObjcType):
    """Wrap classes in Objective-C."""

    def __init__(self, runtime: ObjcRuntime, value: int):
        super().__init__(runtime, value)

        if not self.value:
            raise ValueError(f"Invalid value for ObjcClass: {hex(self.value)}")

    @cached_property
    def name(self) -> str:
        retval = self._emu.call_symbol("_class_getName", self.value)
        return self._emu.read_string(retval)

    @cached_property
    def version(self) -> int:
        return self._emu.call_symbol("_class_getVersion", self.value)

    @cached_property
    def is_meta_class(self) -> bool:
        return bool(self._emu.call_symbol("_class_isMetaClass", self.value))

    @cached_property
    def super_class(self) -> ObjcClass:
        retval = self._emu.call_symbol("_class_getSuperclass", self.value)
        return ObjcClass(self._runtime, retval)

    @cached_property
    def instance_size(self) -> int:
        return self._emu.call_symbol("_class_getInstanceSize", self.value)

    def get_instance_variable(self, name: str) -> ObjcIvar:
        return self._get_by_name("_class_getInstanceVariable", name, ObjcIvar)

    def get_ivar_list(self) -> List[ObjcIvar]:
        return self._copy_list("_class_copyIvarList", ObjcIvar)

    def get_property(self, name: str) -> ObjcProperty:
        return self._get_by_name("_class_getProperty", name, ObjcProperty)

    def get_property_list(self) -> List[ObjcIvar]:
        return self._copy_list("_class_copyPropertyList", ObjcIvar)

    def get_class_method(self, sel_name: str) -> ObjcMethod:
        sel = self._runtime.selector(sel_name)
        method_value = self._emu.call_symbol("_class_getClassMethod", self.value, sel)

        return ObjcMethod(self._runtime, method_value)

    def get_instance_method(self, sel_name: str) -> ObjcMethod:
        sel = self._runtime.selector(sel_name)
        method_value = self._emu.call_symbol(
            "_class_getInstanceMethod", self.value, sel
        )

        return ObjcMethod(self._runtime, method_value)

    def get_method_list(self) -> List[ObjcMethod]:
        """Get method list of the class.

        This function only returns instance methods. To obtain class methods,
        you need to invoke it on the class's metaclass.
        """
        return self._copy_list("_class_copyMethodList", ObjcMethod)

    def get_class_method_list(self) -> List[ObjcMethod]:
        class_value = self._emu.call_symbol("_object_getClass", self.value)
        meta_class = ObjcClass(self._runtime, class_value)

        return meta_class.get_method_list()

    def call_method(
        self,
        sel: Union[int, str],
        *args: Union[int, str, ObjcType],
        va_list: Optional[Sequence[Union[int, str, ObjcType]]] = None,
    ) -> Union[int, ObjcObject]:
        return self._runtime.msg_send(self.value, sel, *args, va_list=va_list)


class ObjcMethod(ObjcType):
    """Wrap methods in Objective-C."""

    def __init__(self, runtime: ObjcRuntime, value: int):
        super().__init__(runtime, value)

        if not self.value:
            raise ValueError(f"Invalid value for ObjcMethod: {hex(self.value)}")

    @cached_property
    def name(self) -> str:
        retval = self._emu.call_symbol("_method_getName", self.value)
        return self._emu.read_string(retval)

    @cached_property
    def type_encoding(self) -> str:
        retval = self._emu.call_symbol("_method_getTypeEncoding", self.value)
        return self._emu.read_string(retval)

    @cached_property
    def implementation(self) -> int:
        return self._emu.call_symbol("_method_getImplementation", self.value)

    @cached_property
    def number_of_arguments(self) -> int:
        return self._emu.call_symbol("_method_getNumberOfArguments", self.value)

    @cached_property
    def argument_types(self) -> Tuple[str, ...]:
        number_of_arguments = self.number_of_arguments
        argument_types = []

        dst_len = 256
        dst = self._emu.create_buffer(dst_len)

        try:
            for index in range(number_of_arguments):
                self._emu.call_symbol(
                    "_method_getArgumentType", self.value, index, dst, dst_len
                )

                argument_type = self._emu.read_string(dst)
                argument_types.append(argument_type)

            return tuple(argument_types)
        finally:
            self._emu.free(dst)

    @cached_property
    def return_type(self) -> str:
        dst_len = 256
        dst = self._emu.create_buffer(dst_len)

        try:
            self._emu.call_symbol("_method_getReturnType", self.value, dst, dst_len)
            return self._emu.read_string(dst)
        finally:
            self._emu.free(dst)


class ObjcIvar(ObjcType):
    """Wrap ivar in Objective-C."""

    def __init__(self, runtime: ObjcRuntime, value: int):
        super().__init__(runtime, value)

        if not self.value:
            raise ValueError(f"Invalid value for ObjcIvar: {hex(self.value)}")

    @cached_property
    def offset(self) -> int:
        return self._emu.call_symbol("_ivar_getOffset", self.value)

    @cached_property
    def name(self) -> str:
        reval = self._emu.call_symbol("_ivar_getName", self.value)
        return self._emu.read_string(reval)

    @cached_property
    def type_encoding(self) -> str:
        retval = self._emu.call_symbol("_ivar_getTypeEncoding", self.value)
        return self._emu.read_string(retval)


class ObjcProperty(ObjcType):
    """Wrap property in Objective-C."""

    def __init__(self, runtime: ObjcRuntime, value: int):
        super().__init__(runtime, value)

        if not self.value:
            raise ValueError(f"Invalid value for ObjcProperty: {hex(self.value)}")

    @cached_property
    def name(self) -> str:
        reval = self._emu.call_symbol("_property_getName", self.value)
        return self._emu.read_string(reval)

    @cached_property
    def attributes(self) -> str:
        reval = self._emu.call_symbol("_property_getAttributes", self.value)
        return self._emu.read_string(reval)
