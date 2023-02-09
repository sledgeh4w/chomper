import os
import random
import threading
from functools import wraps
from typing import TYPE_CHECKING, Any, Callable

from unicorn.unicorn import UC_HOOK_CODE_TYPE

if TYPE_CHECKING:
    from .core import Chomper


def intercept(f: Callable[["Chomper"], Any]) -> UC_HOOK_CODE_TYPE:
    """Intercept function call."""

    @wraps(f)
    def decorator(*args):
        emulator = args[-1]["emulator"]
        emulator.return_call(f(emulator))

    return decorator


@intercept
def hook_arc4random(_):
    """Intercept `arc4random` of `libc.so`."""
    return random.randint(0, 0x100000000)


@intercept
def hook_free(emulator: "Chomper"):
    """Intercept `free` of `libc.so`."""
    addr = emulator.get_argument(0)

    emulator.memory_manager.free(addr)


@intercept
def hook_getcwd(emulator: "Chomper") -> int:
    """Intercept `getcwd` of `libc.so`."""
    buf = emulator.get_argument(0)
    cwd = os.getcwd()

    if not buf:
        buf = emulator.create_string(cwd)
    else:
        emulator.write_string(buf, cwd)

    emulator.set_argument(0, buf)

    return buf


@intercept
def hook_getpid(emulator: "Chomper"):
    """Intercept `getpid` of `libc.so`."""
    emulator.set_retval(os.getpid())


@intercept
def hook_gettid(emulator: "Chomper"):
    """Intercept `gettid` of `libc.so`."""
    emulator.set_retval(threading.get_ident())


@intercept
def hook_malloc(emulator: "Chomper") -> int:
    """Intercept `malloc` of `libc.so`."""
    size = emulator.get_argument(0)
    addr = emulator.memory_manager.alloc(size)

    return addr


@intercept
def hook_memcpy(emulator: "Chomper") -> int:
    """Intercept `memcpy` of `libc.so`."""
    dst, src, size = emulator.get_arguments(3)
    emulator.write_bytes(dst, emulator.read_bytes(src, size))

    return dst


@intercept
def hook_memset(emulator: "Chomper") -> int:
    """Intercept `memset` of `libc.so`."""
    addr, char, size = emulator.get_arguments(3)
    emulator.write_bytes(addr, bytes([char for _ in range(size)]))

    return addr


@intercept
def hook_ctype_get_mb_cur_max(_) -> int:
    """Intercept `__ctype_get_mb_cur_max` of `libc.so`."""
    return 1


@intercept
def hook_nanosleep(_) -> int:
    """Intercept `nanosleep` and `clock_nanosleep` of `libc.so`."""
    return 0


@intercept
def hook_pthread_mutex_lock(_):
    """Intercept `pthread_mutex_lock` of `libc.so`."""
    return


@intercept
def hook_pthread_mutex_unlock(_):
    """Intercept `pthread_mutex_unlock` of `libc.so`."""
    return


default_symbol_hooks = {
    "__ctype_get_mb_cur_max": hook_ctype_get_mb_cur_max,
    "arc4random": hook_arc4random,
    "clock_nanosleep": hook_nanosleep,
    "free": hook_free,
    "getcwd": hook_getcwd,
    "getpid": hook_getpid,
    "gettid": hook_gettid,
    "malloc": hook_malloc,
    "nanosleep": hook_nanosleep,
    "pthread_mutex_lock": hook_pthread_mutex_lock,
    "pthread_mutex_unlock": hook_pthread_mutex_unlock,
}
