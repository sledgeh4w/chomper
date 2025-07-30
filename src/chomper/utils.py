import ctypes
import inspect
import os
import struct
from ctypes import addressof, create_string_buffer, sizeof, memmove, Structure
from functools import wraps
from typing import Any, Callable, Optional, Type, TypeVar, Union

from .const import LITTLE_ENDIAN, BIG_ENDIAN, SINGLE_PRECISION, DOUBLE_PRECISION
from .log import get_logger
from .typing import EndianType, PrecisionType


StructureT = TypeVar("StructureT", bound=ctypes.Structure)


def aligned(x: int, n: int) -> int:
    """Align `x` based on `n`."""
    return ((x - 1) // n + 1) * n


def to_signed(value: int, size: int = 8) -> int:
    """Convert an unsigned integer to signed."""
    nbits = size * 8
    if value >= (1 << (nbits - 1)):
        return value - (1 << nbits)
    return value


def to_unsigned(value: int, size: int = 8) -> int:
    """Convert a signed integer to unsigned."""
    nbits = size * 8
    mask = (1 << nbits) - 1

    if value < 0:
        return value + (1 << nbits)

    if value > mask:
        return value & mask

    return value


def bytes_to_float(data: bytes, endian: EndianType = LITTLE_ENDIAN) -> float:
    """Convert bytes to float/double."""
    size = len(data)

    if size == 4:
        c_type = "f"
    elif size == 8:
        c_type = "d"
    else:
        raise ValueError("Wrong data length")

    if endian == LITTLE_ENDIAN:
        char = "<"
    elif endian == BIG_ENDIAN:
        char = ">"
    else:
        raise ValueError("Wrong endian")

    fmt = f"{char}{c_type}"
    return struct.unpack(fmt, data)[0]


def float_to_bytes(
    value: Union[float, int],
    endian: EndianType = LITTLE_ENDIAN,
    precision: PrecisionType = SINGLE_PRECISION,
) -> bytes:
    """Convert float/double to bytes."""
    if endian == LITTLE_ENDIAN:
        char = "<"
    elif endian == BIG_ENDIAN:
        char = ">"
    else:
        raise ValueError("Wrong endian")

    if precision == SINGLE_PRECISION:
        c_type = "f"
    elif precision == DOUBLE_PRECISION:
        c_type = "d"
    else:
        raise ValueError("Wrong precision")

    fmt = f"{char}{c_type}"

    try:
        return struct.pack(fmt, value)
    except struct.error as e:
        raise ValueError(f"Convert failed: {str(e)}")


def struct_to_bytes(st: Structure) -> bytes:
    """Convert struct to bytes."""
    buffer = create_string_buffer(sizeof(st))
    memmove(buffer, addressof(st), sizeof(st))
    return buffer.raw


def bytes_to_struct(data: bytes, struct_class: Type[StructureT]) -> StructureT:
    """Create struct from bytes."""
    instance = struct_class()
    size = ctypes.sizeof(struct_class)

    if len(data) < size:
        raise ValueError("Not enough data length")

    ctypes.memmove(ctypes.addressof(instance), data, size)
    return instance


def log_call(f: Callable[..., Any]):
    """Decorator to print function calls and parameters."""

    current_frame = inspect.currentframe()
    caller_frame = inspect.getouterframes(current_frame)[1]
    module_name = caller_frame.frame.f_globals["__name__"]

    @wraps(f)
    def decorator(*args, **kwargs):
        logger = get_logger(module_name)

        sig = inspect.signature(f)
        bound_args = sig.bind(*args, **kwargs)
        bound_args.apply_defaults()

        args_str = ""

        for name, value in bound_args.arguments.items():
            if name in ("self", "cls"):
                continue
            if args_str:
                args_str += ", "
            args_str += f"{name}={repr(value)}"

        log_prefix = f"Monitor '{f.__name__}' "
        logger.info(f"{log_prefix}call: {args_str}")

        retval = f(*args, **kwargs)

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
