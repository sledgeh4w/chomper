import os
import random
from functools import wraps
from typing import Callable, Dict

hooks: Dict[str, Callable] = {}


def get_hooks() -> Dict[str, Callable]:
    """Returns a dictionary of default hooks."""
    return hooks.copy()


def register_hook(symbol_name: str):
    """Decorator to register a hook function for a given symbol name."""

    def wrapper(func):
        @wraps(func)
        def decorator(uc, address, size, user_data):
            return func(uc, address, size, user_data)

        hooks[symbol_name] = decorator
        return func

    return wrapper


@register_hook("malloc")
def hook_malloc(uc, address, size, user_data):
    emu = user_data["emu"]

    size = emu.get_arg(0)
    addr = emu.memory_manager.alloc(size)

    return addr


@register_hook("free")
def hook_free(uc, address, size, user_data):
    emu = user_data["emu"]

    addr = emu.get_arg(0)
    emu.memory_manager.free(addr)


@register_hook("getpid")
def hook_getpid(uc, address, size, user_data):
    return os.getpid()


@register_hook("arc4random")
def hook_arc4random(uc, address, size, user_data):
    return random.randint(0, 0x100000000)


@register_hook("nanosleep")
def hook_nanosleep(uc, address, size, user_data):
    return 0


@register_hook("clock_nanosleep")
def hook_clock_nanosleep(uc, address, size, user_data):
    return 0


@register_hook("pthread_mutex_lock")
def hook_pthread_mutex_lock(uc, address, size, user_data):
    return 0


@register_hook("pthread_mutex_unlock")
def hook_pthread_mutex_unlock(uc, address, size, user_data):
    return 0


@register_hook("__ctype_get_mb_cur_max")
def hook_ctype_get_mb_cur_max(uc, address, size, user_data):
    return 1
