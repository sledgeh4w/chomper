import os
import random
import threading
from functools import wraps
from typing import TYPE_CHECKING, Any, Callable

from unicorn.unicorn import UC_HOOK_CODE_TYPE

if TYPE_CHECKING:
    from .core import Infernum


def intercept(f: Callable[["Infernum"], Any]) -> UC_HOOK_CODE_TYPE:
    @wraps(f)
    def decorator(*args):
        emulator = args[-1]["emulator"]
        f(emulator)
        emulator.jump_back()

    return decorator


@intercept
def hook_ctype_get_mb_cur_max(emulator: "Infernum"):
    """Intercept ``__ctype_get_mb_cur_max`` of ``libc.so``."""
    emulator.set_retval(1)


@intercept
def hook_arc4random(emulator: "Infernum"):
    """Intercept ``arc4random`` of ``libc.so``."""
    emulator.set_retval(random.randint(0, 0x100000000))


@intercept
def hook_clock_nanosleep(emulator: "Infernum"):
    """Intercept ``clock_nanosleep`` of ``libc.so``."""
    emulator.set_retval(0)


@intercept
def hook_free(emulator: "Infernum"):
    """Intercept ``free`` of ``libc.so``."""
    addr = emulator.get_argument(0)
    emulator.memory_manager.free(addr)


@intercept
def hook_getcwd(emulator: "Infernum"):
    """Intercept ``getcwd`` of ``libc.so``."""
    buf = emulator.get_argument(0)
    cwd = os.getcwd()
    if not buf:
        buf = emulator.create_string(cwd)
    else:
        emulator.write_string(buf, cwd)
    emulator.set_argument(0, buf)
    emulator.set_retval(buf)


@intercept
def hook_getpid(emulator: "Infernum"):
    """Intercept ``getpid`` of ``libc.so``."""
    emulator.set_retval(os.getpid())


@intercept
def hook_gettid(emulator: "Infernum"):
    """Intercept ``gettid`` of ``libc.so``."""
    emulator.set_retval(threading.get_ident())


@intercept
def hook_malloc(emulator: "Infernum"):
    """Intercept ``malloc`` of ``libc.so``."""
    size = emulator.get_argument(0)
    addr = emulator.memory_manager.alloc(size)
    emulator.set_retval(addr)


@intercept
def hook_memcpy(emulator: "Infernum"):
    """Intercept ``memcpy`` of ``libc.so``."""
    dst = emulator.get_argument(0)
    src = emulator.get_argument(1)
    size = emulator.get_argument(2)
    emulator.write_bytes(dst, emulator.read_bytes(src, size))
    emulator.set_retval(dst)


@intercept
def hook_memset(emulator: "Infernum"):
    """Intercept ``memset`` of ``libc.so``."""
    addr = emulator.get_argument(0)
    char = emulator.get_argument(1)
    size = emulator.get_argument(2)
    emulator.write_bytes(addr, bytes([char for _ in range(size)]))
    emulator.set_retval(addr)


@intercept
def hook_nanosleep(emulator: "Infernum"):
    """Intercept ``nanosleep`` of ``libc.so``."""
    emulator.set_retval(0)
