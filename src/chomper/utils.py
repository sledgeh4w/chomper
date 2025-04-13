import inspect
import os
from ctypes import addressof, create_string_buffer, sizeof, memmove, Structure
from functools import wraps
from typing import Any, Callable, Optional

from .log import get_logger


def aligned(x: int, n: int) -> int:
    """Align `x` based on `n`."""
    return ((x - 1) // n + 1) * n


def to_signed(value: int, size: int = 8) -> int:
    """Convert an unsigned integer to signed."""
    nbits = size * 8
    if value >= (1 << (nbits - 1)):
        return value - (1 << nbits)
    return value


def struct2bytes(st: Structure) -> bytes:
    """Convert struct to bytes."""
    buffer = create_string_buffer(sizeof(st))
    memmove(buffer, addressof(st), sizeof(st))
    return buffer.raw


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
