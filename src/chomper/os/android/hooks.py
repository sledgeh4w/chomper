import os
import random

from chomper.types import FuncHooks


class CStandardLibraryHooks(FuncHooks):
    """Hooks for `libc.so`."""

    @classmethod
    def register(cls, emu):
        hooks = {
            "malloc": cls.hook_malloc,
            "free": cls.hook_free,
            "getpid": cls.hook_getpid,
            "arc4random": cls.hook_arc4random,
            "nanosleep": cls.hook_retval(0),
            "clock_nanosleep": cls.hook_retval(0),
            "pthread_mutex_lock": cls.hook_retval(0),
            "pthread_mutex_unlock": cls.hook_retval(0),
            "__ctype_get_mb_cur_max": cls.hook_retval(1),
        }

        emu.hooks.update(hooks)

    @staticmethod
    def hook_malloc(uc, address, size, user_data):
        emu = user_data["emu"]

        size = emu.get_arg(0)
        addr = emu.memory_manager.alloc(size)

        return addr

    @staticmethod
    def hook_free(uc, address, size, user_data):
        emu = user_data["emu"]

        addr = emu.get_arg(0)
        emu.memory_manager.free(addr)

    @staticmethod
    def hook_getpid(uc, address, size, user_data):
        return os.getpid()

    @staticmethod
    def hook_arc4random(uc, address, size, user_data):
        return random.randint(0, 0x100000000)
