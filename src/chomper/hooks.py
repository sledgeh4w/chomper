import random


def hook_arc4random(uc, address, size, user_data):
    """Intercept `arc4random` of `libc.so`."""
    return random.randint(0, 0x100000000)


def hook_free(uc, address, size, user_data):
    """Intercept `free` of `libc.so`."""
    emu = user_data["emu"]

    addr = emu.get_argument(0)
    emu.free(addr)


def hook_malloc(uc, address, size, user_data):
    """Intercept `malloc` of `libc.so`."""
    emu = user_data["emu"]

    size = emu.get_argument(0)
    addr = emu.create_buffer(size)

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


def hook_localconv_l(uc, address, size, user_data):
    emu = user_data["emu"]

    decimal_point = emu.create_string(".")

    lc = emu.create_buffer(128)
    emu.write_address(lc, decimal_point)

    return lc


def hook_os_unfair_lock_lock(uc, address, size, user_data):
    return


def hook_os_unfair_lock_unlock(uc, address, size, user_data):
    return


def hook_cxa_atexit(uc, address, size, user_data):
    return
