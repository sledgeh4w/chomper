import os
import random
import time
import threading
import uuid
from functools import wraps
from typing import Callable, Dict

from unicorn import arm64_const

from chomper.os.ios import const


syscall_handlers: Dict[int, Callable] = {}


def get_syscall_handlers() -> Dict[int, Callable]:
    """Get the default system call handlers."""
    return syscall_handlers.copy()


def register_syscall_handler(syscall_no: int):
    """Decorator to register a system call handler."""

    def wrapper(func):
        @wraps(func)
        def decorator(emu):
            return func(emu)

        syscall_handlers[syscall_no] = decorator
        return func

    return wrapper


def clear_carry_flag(emu):
    """Clear the carry flag.

    Some system functions will check the carry flag after system calls,
    such as `_csops` and `proc_pidpath`.
    """
    nzcv = emu.uc.reg_read(arm64_const.UC_ARM64_REG_NZCV)
    emu.uc.reg_write(arm64_const.UC_ARM64_REG_NZCV, nzcv & ~(1 << 29))


@register_syscall_handler(const.SYS_GETPID)
def handle_sys_getpid(emu):
    return os.getpid()


@register_syscall_handler(const.SYS_GETUID)
def handle_sys_getuid(emu):
    return 1


@register_syscall_handler(const.SYS_GETEUID)
def handle_sys_geteuid(emu):
    return 1


@register_syscall_handler(const.SYS_ACCESS)
def handle_sys_access(emu):
    return 0


@register_syscall_handler(const.SYS_GETEGID)
def handle_sys_getegid(emu):
    return 1


@register_syscall_handler(const.SYS_GETTIMEOFDAY)
def handle_sys_gettimeofday(emu):
    tv = emu.get_arg(0)

    emu.write_u64(tv, int(time.time()))
    emu.write_u64(tv + 8, 0)

    return 0


@register_syscall_handler(const.SYS_CSOPS)
def handle_sys_csops(emu):
    useraddr = emu.get_arg(2)

    emu.write_u32(useraddr, 0x4000800)

    clear_carry_flag(emu)

    return 0


@register_syscall_handler(const.SYS_RLIMIT)
def handle_sys_rlimit(emu):
    return 0


@register_syscall_handler(const.SYS_SYSCTL)
def handle_sys_sysctl(emu):
    return 0


@register_syscall_handler(const.SYS_SHM_OPEN)
def handle_sys_shm_open(emu):
    return 0x80000000


@register_syscall_handler(const.SYS_SYSCTLBYNAME)
def handle_sys_sysctlbyname(emu):
    name = emu.read_string(emu.get_arg(0))
    oldp = emu.get_arg(2)
    oldlenp = emu.get_arg(3)

    if not oldp or not oldlenp:
        return 0

    if name == "kern.boottime":
        emu.write_u64(oldp, int(time.time()) - 3600 * 24)
        emu.write_u64(oldp + 8, 0)

    elif name == "kern.osvariant_status":
        # internal_release_type = 3
        emu.write_u64(oldp, 0x30)

    elif name == "hw.memsize":
        emu.write_u64(oldp, 4 * 1024 * 1024 * 1024)

    else:
        emu.logger.warning("Unhandled sysctl command: %s" % name)
        # raise RuntimeError("Unhandled sysctl command: %s" % name)

    return 0


@register_syscall_handler(const.SYS_GETTID)
def handle_sys_gettid(emu):
    thread = threading.current_thread()
    return thread.ident


@register_syscall_handler(const.SYS_ISSETUGID)
def handle_sys_issetugid(emu):
    return 0


@register_syscall_handler(const.SYS_PROC_INFO)
def handle_sys_proc_info(emu):
    # pid = emu.get_arg(1)
    flavor = emu.get_arg(2)
    buffer = emu.get_arg(4)

    if flavor == 11:
        emu.write_string(
            buffer,
            "/private/var/containers/Bundle/Application/%s/App.app" % uuid.uuid4(),
        )

    clear_carry_flag(emu)

    return 0


@register_syscall_handler(const.SYS_STAT64)
def handle_sys_stat64(emu):
    # path = emu.read_string(emu.get_arg(0))
    stat = emu.get_arg(1)

    # st_mode
    emu.write_u32(stat + 4, 0x4000)

    return 0


@register_syscall_handler(const.SYS_LSTAT64)
def handle_sys_lstat64(emu):
    # path = emu.read_string(emu.get_arg(0))
    stat = emu.get_arg(1)

    # st_mode
    emu.write_u32(stat + 4, 0x4000)

    return 0


@register_syscall_handler(const.SYS_GETENTROPY)
def handle_sys_getentropy(emu):
    buffer = emu.get_arg(0)
    size = emu.get_arg(1)

    rand_bytes = bytes([random.randint(0, 255) for _ in range(size)])
    emu.write_bytes(buffer, rand_bytes)

    return 0


@register_syscall_handler(const.MACH_ABSOLUTE_TIME_TRAP)
def handle_mach_absolute_time_trap(emu):
    emu.set_retval(int(time.time_ns() % (3600 * 10**9)))


@register_syscall_handler(const.MACH_TIMEBASE_INFO_TRAP)
def handle_mach_timebase_info_trap(emu):
    info = emu.get_arg(0)

    emu.write_u32(info, 1)
    emu.write_u32(info + 4, 1)

    return 0


@register_syscall_handler(const.MACH_MSG_TRAP)
def handle_mach_msg_trap(emu):
    # msg = emu.get_arg(0)

    # msgh_size:
    # emu.write_u32(msg + 0x4, 36)

    # msgh_remote_port
    # emu.write_u32(msg + 0x8, 0)

    # msgh_id
    # emu.write_u32(msg + 0x14, 8100)

    return 6


@register_syscall_handler(const.MACH_REPLY_PORT_TRAP)
def handle_mach_reply_port_trap(emu):
    return 0


@register_syscall_handler(const.KERNELRPC_MACH_VM_MAP_TRAP)
def handle_kernelrpc_mach_vm_map_trap(emu):
    address = emu.get_arg(1)
    size = emu.get_arg(2)

    mem = emu.memory_manager.alloc(size)
    emu.write_pointer(address, mem)

    return 0
