from functools import wraps
from typing import Callable, Dict

from unicorn import Uc

from chomper.os.ios import hooks as ios_hooks
from chomper.typing import UserData

hooks: Dict[str, Callable] = {}


def get_hooks() -> Dict[str, Callable]:
    """Returns a dictionary of default hooks."""
    return hooks.copy()


def register_hook(symbol_name: str):
    """Decorator to register a hook function for a given symbol name."""

    def wrapper(func):
        @wraps(func)
        def decorator(uc: Uc, address: int, size: int, user_data: UserData):
            return func(uc, address, size, user_data)

        hooks[symbol_name] = decorator
        return func

    return wrapper


@register_hook("malloc")
def hook_malloc(uc: Uc, address: int, size: int, user_data: UserData):
    return ios_hooks.hook_malloc(uc, address, size, user_data)


@register_hook("calloc")
def hook_calloc(uc: Uc, address: int, size: int, user_data: UserData):
    return ios_hooks.hook_calloc(uc, address, size, user_data)


@register_hook("realloc")
def hook_realloc(uc: Uc, address: int, size: int, user_data: UserData):
    return ios_hooks.hook_realloc(uc, address, size, user_data)


@register_hook("free")
def hook_free(uc: Uc, address: int, size: int, user_data: UserData):
    return ios_hooks.hook_free(uc, address, size, user_data)


@register_hook("memalign")
def hook_memalign(uc: Uc, address: int, size: int, user_data: UserData):
    emu = user_data["emu"]

    alignment = emu.get_arg(0)
    size = emu.get_arg(1)

    mem = emu.memory_manager.memalign(alignment, size)

    return mem


@register_hook("posix_memalign")
def hook_posix_memalign(uc: Uc, address: int, size: int, user_data: UserData):
    return ios_hooks.hook_posix_memalign(uc, address, size, user_data)


@register_hook("pthread_mutex_lock")
def hook_pthread_mutex_lock(uc: Uc, address: int, size: int, user_data: UserData):
    return 0


@register_hook("pthread_mutex_unlock")
def hook_pthread_mutex_unlock(uc: Uc, address: int, size: int, user_data: UserData):
    return 0


@register_hook("__ctype_get_mb_cur_max")
def hook_ctype_get_mb_cur_max(uc: Uc, address: int, size: int, user_data: UserData):
    return 1
