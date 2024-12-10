import inspect
import os
from ctypes import addressof, create_string_buffer, sizeof, memmove, Structure
from functools import wraps
from typing import Optional

from .log import get_logger
from .objc import ObjC


def aligned(x: int, n: int) -> int:
    """Align `x` based on `n`."""
    return ((x - 1) // n + 1) * n


def struct2bytes(st: Structure) -> bytes:
    """Convert struct to bytes."""
    buffer = create_string_buffer(sizeof(st))
    memmove(buffer, addressof(st), sizeof(st))
    return buffer.raw


def pyobj2nsobj(emu, obj: object) -> int:
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
    else:
        raise TypeError(f"Unsupported type: {type(obj)}")

    for mem_ptr in mem_ptrs:
        emu.free(mem_ptr)

    return ns_obj


def pyobj2cfobj(emu, obj: object) -> int:
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
    else:
        raise TypeError(f"Unsupported type: {type(obj)}")

    for mem_ptr in mem_ptrs:
        emu.free(mem_ptr)

    for cf_str in cf_strs:
        emu.call_symbol("_CFRelease", cf_str)

    return cf_obj


def log_call(func):
    """Decorator to print function calls and parameters."""

    current_frame = inspect.currentframe()
    caller_frame = inspect.getouterframes(current_frame)[1]
    module_name = caller_frame.frame.f_globals["__name__"]

    @wraps(func)
    def decorator(*args, **kwargs):
        logger = get_logger(module_name)

        sig = inspect.signature(func)
        bound_args = sig.bind(*args, **kwargs)
        bound_args.apply_defaults()

        args_str = ""

        for name, value in bound_args.arguments.items():
            if name in ("self", "cls"):
                continue
            if args_str:
                args_str += ", "
            args_str += f"{name}={repr(value)}"

        log_prefix = f"Monitor '{func.__name__}' "
        logger.info(f"{log_prefix}call: {args_str}")

        retval = func(*args, **kwargs)

        if isinstance(retval, int):
            logger.info(f"{log_prefix}return: {retval}")
        else:
            logger.info(f"{log_prefix}return")

        return retval

    return decorator


def safe_join(directory: str, *paths: str) -> Optional[str]:
    """Safely join path to avoid escaping the base directory."""
    full_path = os.path.join(directory, *paths)
    abs_path = os.path.abspath(full_path)

    if not abs_path.startswith(os.path.abspath(directory)):
        return None

    return abs_path
