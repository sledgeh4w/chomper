from functools import wraps
from typing import Callable, Dict

from unicorn import Uc

from chomper.typing import HookContext

hooks: Dict[str, Callable] = {}


def get_hooks() -> Dict[str, Callable]:
    """Returns a dictionary of default hooks."""
    return hooks.copy()


def register_hook(symbol_name: str):
    """Decorator to register a hook function for a given symbol name."""

    def wrapper(func):
        @wraps(func)
        def decorator(uc: Uc, address: int, size: int, user_data: HookContext):
            return func(uc, address, size, user_data)

        hooks[symbol_name] = decorator
        return func

    return wrapper


@register_hook("malloc")
def hook_malloc(uc: Uc, address: int, size: int, user_data: HookContext):
    emu = user_data["emu"]

    size = emu.get_arg(0)
    addr = emu.memory_manager.alloc(size)

    return addr


@register_hook("calloc")
def hook_calloc(uc: Uc, address: int, size: int, user_data: HookContext):
    emu = user_data["emu"]

    numitems = emu.get_arg(0)
    size = emu.get_arg(1)

    addr = emu.memory_manager.alloc(numitems * size)
    emu.write_bytes(addr, b"\x00" * (numitems * size))

    return addr


@register_hook("realloc")
def hook_realloc(uc: Uc, address: int, size: int, user_data: HookContext):
    emu = user_data["emu"]

    addr = emu.get_arg(0)
    size = emu.get_arg(1)

    return emu.memory_manager.realloc(addr, size)


@register_hook("free")
def hook_free(uc: Uc, address: int, size: int, user_data: HookContext):
    emu = user_data["emu"]

    addr = emu.get_arg(0)
    emu.memory_manager.free(addr)


@register_hook("memalign")
def hook_memalign(uc: Uc, address: int, size: int, user_data: HookContext):
    emu = user_data["emu"]

    alignment = emu.get_arg(0)
    size = emu.get_arg(1)

    addr = emu.memory_manager.memalign(alignment, size)

    return addr


@register_hook("posix_memalign")
def hook_posix_memalign(uc: Uc, address: int, size: int, user_data: HookContext):
    emu = user_data["emu"]

    memptr = emu.get_arg(0)
    alignment = emu.get_arg(1)
    size = emu.get_arg(2)

    addr = emu.memory_manager.memalign(alignment, size)
    emu.write_pointer(memptr, addr)

    return 0


@register_hook("pthread_mutex_lock")
def hook_pthread_mutex_lock(uc: Uc, address: int, size: int, user_data: HookContext):
    return 0


@register_hook("pthread_mutex_unlock")
def hook_pthread_mutex_unlock(uc: Uc, address: int, size: int, user_data: HookContext):
    return 0


@register_hook("__ctype_get_mb_cur_max")
def hook_ctype_get_mb_cur_max(uc: Uc, address: int, size: int, user_data: HookContext):
    return 1
