import ctypes
import os
import random
import sys
import time
from functools import wraps
from typing import Callable, Dict

from unicorn import arm64_const

from chomper.structs import Rusage
from chomper.utils import struct2bytes

from . import const
from .sysctl import sysctl, sysctlbyname

syscall_handlers: Dict[int, Callable] = {}


def get_syscall_handlers() -> Dict[int, Callable]:
    """Get the default system call handlers."""
    return syscall_handlers.copy()


def register_syscall_handler(syscall_no: int):
    """Decorator to register a system call handler."""

    def wrapper(func):
        @wraps(func)
        def decorator(emu):
            retval = func(emu)

            # Clear the carry flag after called, many functions will
            # check it after system calls.
            nzcv = emu.uc.reg_read(arm64_const.UC_ARM64_REG_NZCV)
            emu.uc.reg_write(arm64_const.UC_ARM64_REG_NZCV, nzcv & ~(1 << 29))

            return retval

        syscall_handlers[syscall_no] = decorator
        return func

    return wrapper


def catch_file_errors(func):
    """Decorator to catch all file related errors."""

    @wraps(func)
    def decorator(emu):
        try:
            return func(emu)
        except FileNotFoundError:
            return -1

    return decorator


@register_syscall_handler(const.SYS_READ)
@register_syscall_handler(const.SYS_READ_NOCANCEL)
def handle_sys_read(emu):
    fd = emu.get_arg(0)
    buf = emu.get_arg(1)
    size = emu.get_arg(2)

    data = emu.file_manager.read(fd, size)
    emu.write_bytes(buf, data)

    return len(data)


@register_syscall_handler(const.SYS_OPEN)
@register_syscall_handler(const.SYS_OPEN_NOCANCEL)
@catch_file_errors
def handle_sys_open(emu):
    path = emu.read_string(emu.get_arg(0))
    flags = emu.get_arg(1)

    if sys.platform == "win32":
        flags |= os.O_BINARY

    return emu.file_manager.open(path, flags)


@register_syscall_handler(const.SYS_CLOSE)
@register_syscall_handler(const.SYS_CLOSE_NOCANCEL)
def handle_sys_close(emu):
    fd = emu.get_arg(0)
    emu.file_manager.close(fd)

    return 0


@register_syscall_handler(const.SYS_GETPID)
def handle_sys_getpid(emu):
    return emu.os.proc_id


@register_syscall_handler(const.SYS_GETUID)
def handle_sys_getuid(emu):
    return 1


@register_syscall_handler(const.SYS_GETEUID)
def handle_sys_geteuid(emu):
    return 1


@register_syscall_handler(const.SYS_ACCESS)
def handle_sys_access(emu):
    path = emu.read_string(emu.get_arg(0))
    mode = emu.get_arg(1)

    if not emu.file_manager.access(path, mode):
        return -1

    return 0


@register_syscall_handler(const.SYS_GETPPID)
def handle_sys_getppid(emu):
    return 1


@register_syscall_handler(const.SYS_SIGACTION)
def handle_sys_sigaction(emu):
    return 0


@register_syscall_handler(const.SYS_SIGALTSTACK)
def handle_sys_sigaltstack(emu):
    return 0


@register_syscall_handler(const.SYS_IOCTL)
def handle_sys_ioctl(emu):
    fd = emu.get_arg(0)
    req = emu.get_arg(1)

    inout = req & ~((0x3FFF << 16) | 0xFF00 | 0xFF)
    group = (req >> 8) & 0xFF
    num = req & 0xFF
    length = (req >> 16) & 0x3FFF

    emu.logger.info(
        f"Recv ioctl request: fd={fd}, inout={hex(inout)}, group='{chr(group)}', "
        f"num={num}, length={length}"
    )

    emu.logger.warning("ioctl request not processed")
    return 0


@register_syscall_handler(const.SYS_READLINK)
def handle_sys_readlink(emu):
    path = emu.read_string(emu.get_arg(0))
    buf = emu.get_arg(1)
    buf_size = emu.get_arg(2)

    result = emu.file_manager.readlink(path)
    if result is None or len(result) > buf_size:
        return -1

    emu.write_string(buf, result)

    return 0


@register_syscall_handler(const.SYS_MUNMAP)
def handle_sys_munmap(emu):
    addr = emu.get_arg(0)

    emu.free(addr)

    return 0


@register_syscall_handler(const.SYS_MADVISE)
def handle_sys_madvise(emu):
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


@register_syscall_handler(const.SYS_GETRUSAGE)
def handle_sys_getrusage(emu):
    r = emu.get_arg(1)

    rusage = Rusage()
    emu.write_bytes(r, struct2bytes(rusage))

    return 0


@register_syscall_handler(const.SYS_MKDIR)
@catch_file_errors
def handle_sys_mkdir(emu):
    path = emu.read_string(emu.get_arg(0))
    mode = emu.get_arg(1)

    emu.file_manager.mkdir(path, mode)

    return 0


@register_syscall_handler(const.SYS_CSOPS)
def handle_sys_csops(emu):
    useraddr = emu.get_arg(2)
    emu.write_u32(useraddr, 0x4000800)

    return 0


@register_syscall_handler(const.SYS_RLIMIT)
def handle_sys_rlimit(emu):
    return 0


@register_syscall_handler(const.SYS_MMAP)
def handle_sys_mmap(emu):
    length = emu.get_arg(1)
    fd = emu.get_arg(4)
    offset = emu.get_arg(5)

    buf = emu.create_buffer(length)

    chunk_size = 1024 * 1024
    content = b""

    while True:
        chunk = os.read(fd, chunk_size)
        if not chunk:
            break
        content += chunk

    emu.write_bytes(buf, content[offset:])

    return buf


@register_syscall_handler(const.SYS_LSEEK)
def handle_sys_lseek(emu):
    fd = emu.get_arg(0)
    offset = emu.get_arg(1)
    whence = emu.get_arg(2)

    # Convert to signed integer
    offset_bytes = offset.to_bytes(8, "little")
    offset = int.from_bytes(offset_bytes, "little", signed=True)

    return emu.file_manager.lseek(fd, offset, whence)


@register_syscall_handler(const.SYS_FCNTL)
@register_syscall_handler(const.SYS_FCNTL_NOCANCEL)
def handle_sys_fcntl(emu):
    fd = emu.get_arg(0)
    cmd = emu.get_arg(1)
    arg = emu.get_arg(2)

    if cmd == const.F_GETPATH:
        path = emu.file_manager.dir_fds.get(fd)
        if not path:
            path = emu.file_manager.fd_path_map.get(fd)

        if path:
            emu.write_string(arg, path)

    return 0


@register_syscall_handler(const.SYS_SYSCTL)
def handle_sys_sysctl(emu):
    name = emu.get_arg(0)
    oldp = emu.get_arg(2)

    ctl_type = emu.read_u32(name)
    ctl_ident = emu.read_u32(name + 4)

    result = sysctl(ctl_type, ctl_ident)
    if result is None:
        emu.logger.warning(f"Unhandled sysctl command: {ctl_type}, {ctl_ident}")
        return -1

    if isinstance(result, ctypes.Structure):
        emu.write_bytes(oldp, struct2bytes(result))
    elif isinstance(result, str):
        emu.write_string(oldp, result)
    elif isinstance(result, int):
        emu.write_u64(oldp, result)

    return 0


@register_syscall_handler(const.SYS_GETATTRLIST)
@catch_file_errors
def handle_sys_getattrlist(emu):
    path = emu.read_string(emu.get_arg(0))
    stat = emu.get_arg(2)

    emu.write_bytes(stat, emu.file_manager.stat(path))

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

    result = sysctlbyname(name)
    if result is None:
        emu.logger.warning(f"Unhandled sysctl command: {name}")
        return -1

    if isinstance(result, ctypes.Structure):
        emu.write_bytes(oldp, struct2bytes(result))
    elif isinstance(result, str):
        emu.write_string(oldp, result)
    elif isinstance(result, int):
        emu.write_u64(oldp, result)

    return 0


@register_syscall_handler(const.SYS_GETTID)
def handle_sys_gettid(emu):
    return 1000


@register_syscall_handler(const.SYS_PSYNCH_MUTEXWAIT)
def handle_sys_psynch_mutexwait(emu):
    return 0


@register_syscall_handler(const.SYS_ISSETUGID)
def handle_sys_issetugid(emu):
    return 0


@register_syscall_handler(const.SYS_PROC_INFO)
def handle_sys_proc_info(emu):
    # pid = emu.get_arg(1)
    flavor = emu.get_arg(2)
    buffer = emu.get_arg(4)

    if flavor == 11:
        emu.write_string(buffer, emu.os.proc_path)

    return 0


@register_syscall_handler(const.SYS_STAT64)
@catch_file_errors
def handle_sys_stat64(emu):
    path = emu.read_string(emu.get_arg(0))
    stat = emu.get_arg(1)

    emu.write_bytes(stat, emu.file_manager.stat(path))

    return 0


@register_syscall_handler(const.SYS_FSTAT64)
def handle_sys_fstat64(emu):
    fd = emu.get_arg(0)
    stat = emu.get_arg(1)

    emu.write_bytes(stat, emu.file_manager.fstat(fd))

    return 0


@register_syscall_handler(const.SYS_LSTAT64)
@catch_file_errors
def handle_sys_lstat64(emu):
    path = emu.read_string(emu.get_arg(0))
    stat = emu.get_arg(1)

    emu.write_bytes(stat, emu.file_manager.lstat(path))

    return 0


@register_syscall_handler(const.SYS_STATFS64)
@catch_file_errors
def handle_sys_statfs64(emu):
    path = emu.read_string(emu.get_arg(0))
    stat = emu.get_arg(1)

    emu.write_bytes(stat, emu.file_manager.statfs(path))

    return 0


@register_syscall_handler(const.SYS_FSTATFS64)
@catch_file_errors
def handle_sys_fstatfs64(emu):
    fd = emu.get_arg(0)
    stat = emu.get_arg(1)

    emu.write_bytes(stat, emu.file_manager.fstatfs(fd))

    return 0


@register_syscall_handler(const.SYS_BSDTHREAD_CREATE)
def handle_sys_bsdthread_create(emu):
    return 0


@register_syscall_handler(const.SYS_GETENTROPY)
def handle_sys_getentropy(emu):
    buffer = emu.get_arg(0)
    size = emu.get_arg(1)

    rand_bytes = bytes([random.randint(0, 255) for _ in range(size)])
    emu.write_bytes(buffer, rand_bytes)

    return 0


@register_syscall_handler(const.SYS_OPENAT)
@register_syscall_handler(const.SYS_OPENAT_NOCANCEL)
@catch_file_errors
def handle_sys_openat(emu):
    dir_fd = emu.get_arg(0)
    path = emu.read_string(emu.get_arg(1))
    flags = emu.get_arg(2)

    if sys.platform == "win32":
        flags |= os.O_BINARY

    return emu.file_manager.openat(dir_fd, path, flags)


@register_syscall_handler(const.SYS_MKDIRAT)
def handle_sys_mkdirat(emu):
    dir_fd = emu.get_arg(0)
    path = emu.read_string(emu.get_arg(1))
    mode = emu.get_arg(2)

    emu.file_manager.mkdirat(dir_fd, path, mode)

    return 0


@register_syscall_handler(const.MACH_ABSOLUTE_TIME_TRAP)
def handle_mach_absolute_time_trap(emu):
    return int(time.time_ns() % (3600 * 10**9))


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
