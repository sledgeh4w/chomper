import os
import random
import threading


def hook_arc4random(uc, address, size, user_data):
    """Intercept `arc4random` of `libc.so`."""
    return random.randint(0, 0x100000000)


def hook_free(uc, address, size, user_data):
    """Intercept `free` of `libc.so`."""
    emu = user_data["emu"]

    addr = emu.get_argument(0)
    emu.free_memory(addr)


def hook_getcwd(uc, address, size, user_data):
    """Intercept `getcwd` of `libc.so`."""
    emu = user_data["emu"]

    buf = emu.get_argument(0)
    cwd = os.getcwd()

    if not buf:
        buf = emu.alloc_memory(len(cwd) + 1)

    emu.write_string(buf, cwd)
    emu.set_argument(0, buf)

    return buf


def hook_getpid(uc, address, size, user_data):
    """Intercept `getpid` of `libc.so`."""
    emu = user_data["emu"]

    emu.set_retval(os.getpid())


def hook_gettid(uc, address, size, user_data):
    """Intercept `gettid` of `libc.so`."""
    emu = user_data["emu"]

    emu.set_retval(threading.get_ident())


def hook_malloc(uc, address, size, user_data):
    """Intercept `malloc` of `libc.so`."""
    emu = user_data["emu"]

    size = emu.get_argument(0)
    addr = emu.alloc_memory(size)

    return addr


def hook_memcpy(uc, address, size, user_data):
    """Intercept `memcpy` of `libc.so`."""
    emu = user_data["emu"]

    dst, src, size = emu.get_arguments(3)
    emu.write_bytes(dst, emu.read_bytes(src, size))

    return dst


def hook_memset(uc, address, size, user_data):
    """Intercept `memset` of `libc.so`."""
    emu = user_data["emu"]

    addr, char, size = emu.get_arguments(3)
    emu.write_bytes(addr, bytes([char for _ in range(size)]))

    return addr


def hook_ctype_get_mb_cur_max(uc, address, size, user_data):
    """Intercept `__ctype_get_mb_cur_max` of `libc.so`."""
    return 1


def hook_nanosleep(uc, address, size, user_data):
    """Intercept `nanosleep` and `clock_nanosleep` of `libc.so`."""
    return 0


def hook_pthread_mutex_lock(uc, address, size, user_data):
    """Intercept `pthread_mutex_lock` of `libc.so`."""
    return


def hook_pthread_mutex_unlock(uc, address, size, user_data):
    """Intercept `pthread_mutex_unlock` of `libc.so`."""
    return
