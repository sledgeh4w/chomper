from ctypes import addressof, create_string_buffer, sizeof, memmove, Structure

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
        TypeError: If the object type is not supported.
    """
    objc = ObjC(emu)

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

    else:
        raise TypeError(f"Unsupported type: {type(obj)}")

    return ns_obj
