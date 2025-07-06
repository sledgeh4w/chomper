from __future__ import annotations

import os
from functools import wraps
from typing import Dict, TYPE_CHECKING

from chomper.exceptions import SystemOperationFailed
from chomper.typing import SyscallHandleCallable
from chomper.os.base import SyscallError
from chomper.os.ios import syscall as ios_syscall

from . import const

if TYPE_CHECKING:
    from chomper.core import Chomper

SYSCALL_MAP: Dict[int, str] = {
    const.NR_GETCWD: "NR_getcwd",
    const.NR_FCNTL: "NR_fcntl",
    const.NR_IOCTL: "NR_ioctl",
    const.NR_MKDIRAT: "NR_mkdirat",
    const.NR_UNLINKAT: "NR_unlinkat",
    const.NR_SYMLINKAT: "NR_symlinkat",
    const.NR_LINKAT: "NR_linkat",
    const.NR_RENAMEAT: "NR_renameat",
    const.NR_FACCESSAT: "NR_faccessat",
    const.NR_CHDIR: "NR_chdir",
    const.NR_FCHDIR: "NR_fchdir",
    const.NR_FCHMOD: "NR_fchmod",
    const.NR_FCHMODAT: "NR_fchmodat",
    const.NR_FCHOWNAT: "NR_fchownat",
    const.NR_FCHOWN: "NR_fchown",
    const.NR_OPENAT: "NR_openat",
    const.NR_CLOSE: "NR_close",
    const.NR_GETDENTS64: "NR_getdents64",
    const.NR_LSEEK: "NR_lseek",
    const.NR_READ: "NR_read",
    const.NR_WRITE: "NR_write",
    const.NR_READV: "NR_readv",
    const.NR_WRITEV: "NR_writev",
    const.NR_PREAD64: "NR_pread64",
    const.NR_PREADV64: "NR_preadv64",
    const.NR_READLINKAT: "NR_readlinkat",
    const.NR_FSTATAT: "NR_fstatat",
    const.NR_FSTAT: "NR_fstat",
    const.NR_FSYNC: "NR_fsync",
    const.NR_EXIT_GROUP: "NR_exit_group",
    const.NR_NANOSLEEP: "NR_nanosleep",
    const.NR_CLOCK_SETTIME: "NR_clock_settime",
    const.NR_CLOCK_GETTIME: "NR_clock_gettime",
    const.NR_CLOCK_GETRES: "NR_clock_getres",
    const.NR_CLOCK_NANOSLEEP: "NR_clock_nanosleep",
    const.NR_SETRESGID: "NR_setresgid",
    const.NR_GETPGID: "NR_getpgid",
    const.NR_UNAME: "NR_uname",
    const.NR_PRCTL: "NR_prctl",
    const.NR_GETTIMEOFDAY: "NR_gettimeofday",
    const.NR_GETPID: "NR_getpid",
    const.NR_GETPPID: "NR_getppid",
    const.NR_GETUID: "NR_getuid",
    const.NR_GETEGID: "NR_getegid",
    const.NR_MUNMAP: "NR_munmap",
    const.NR_MMAP: "NR_mmap",
    const.NR_CLOCK_ADJTIME: "NR_clock_adjtime",
}

ERROR_MAP = {
    SyscallError.EPERM: (const.EPERM, "EPERM"),
    SyscallError.ENOENT: (const.ENOENT, "ENOENT"),
    SyscallError.EBADF: (const.EBADF, "EBADF"),
    SyscallError.EACCES: (const.EACCES, "EACCES"),
    SyscallError.EEXIST: (const.EEXIST, "EEXIST"),
    SyscallError.ENOTDIR: (const.ENOTDIR, "ENOTDIR"),
}

syscall_handlers: Dict[int, SyscallHandleCallable] = {}


def get_syscall_handlers() -> Dict[int, SyscallHandleCallable]:
    """Get the default system call handlers."""
    return syscall_handlers.copy()


def register_syscall_handler(syscall_no: int):
    """Decorator to register a system call handler."""

    def wrapper(f):
        @wraps(f)
        def decorator(emu: Chomper):
            retval = -1
            error_type = None

            try:
                retval = f(emu)
            except (FileNotFoundError, PermissionError):
                error_type = SyscallError.ENOENT
            except FileExistsError:
                error_type = SyscallError.EEXIST
            except SystemOperationFailed as e:
                error_type = e.error_type

            if error_type in ERROR_MAP:
                error_no, error_name = ERROR_MAP[error_type]

                emu.logger.info(f"Set errno {error_name}({error_no})")
                emu.os.set_errno(error_no)

            return retval

        syscall_handlers[syscall_no] = decorator
        return f

    return wrapper


def permission_denied():
    raise SystemOperationFailed("No permission", SyscallError.EPERM)


@register_syscall_handler(const.NR_GETCWD)
def handle_nr_getcwd(emu: Chomper):
    buf = emu.get_arg(0)

    emu.write_string(buf, emu.os.get_working_dir())

    return 0


@register_syscall_handler(const.NR_FCNTL)
def handle_nr_fcntl(emu: Chomper):
    fd = emu.get_arg(0)
    cmd = emu.get_arg(1)
    # arg = emu.get_arg(2)

    if cmd == const.F_GETFL:
        if fd in (emu.os.stdin,):
            return os.O_RDONLY
        elif fd in (emu.os.stdout, emu.os.stderr):
            return os.O_WRONLY
    else:
        emu.logger.warning(f"Unhandled fcntl command: {cmd}")

    return 0


@register_syscall_handler(const.NR_IOCTL)
def handle_nr_ioctl(emu: Chomper):
    return ios_syscall.handle_sys_ioctl(emu)


@register_syscall_handler(const.NR_MKDIRAT)
def handle_nr_mkdirat(emu: Chomper):
    return ios_syscall.handle_sys_mkdirat(emu)


@register_syscall_handler(const.NR_UNLINKAT)
def handle_nr_unlinkat(emu: Chomper):
    return ios_syscall.handle_sys_unlinkat(emu)


@register_syscall_handler(const.NR_SYMLINKAT)
def handle_nr_symlinkat(emu: Chomper):
    return ios_syscall.handle_sys_symlinkat(emu)


@register_syscall_handler(const.NR_LINKAT)
def handle_nr_linkat(emu: Chomper):
    return ios_syscall.handle_sys_linkat(emu)


@register_syscall_handler(const.NR_RENAMEAT)
def handle_nr_renameat(emu: Chomper):
    return ios_syscall.handle_sys_renameat(emu)


@register_syscall_handler(const.NR_FACCESSAT)
def handle_nr_faccessat(emu: Chomper):
    return ios_syscall.handle_sys_faccessat(emu)


@register_syscall_handler(const.NR_CHDIR)
def handle_nr_chdir(emu: Chomper):
    return ios_syscall.handle_sys_chdir(emu)


@register_syscall_handler(const.NR_FCHDIR)
def handle_nr_fchdir(emu: Chomper):
    return ios_syscall.handle_sys_fchdir(emu)


@register_syscall_handler(const.NR_FCHMOD)
def handle_nr_fchmod(emu: Chomper):
    return ios_syscall.handle_sys_fchmod(emu)


@register_syscall_handler(const.NR_FCHMODAT)
def handle_nr_fchmodat(emu: Chomper):
    return ios_syscall.handle_sys_fchmodat(emu)


@register_syscall_handler(const.NR_FCHOWNAT)
def handle_nr_fchownat(emu: Chomper):
    return ios_syscall.handle_sys_fchownat(emu)


@register_syscall_handler(const.NR_FCHOWN)
def handle_nr_fchown(emu: Chomper):
    return ios_syscall.handle_sys_fchown(emu)


@register_syscall_handler(const.NR_OPENAT)
def handle_nr_openat(emu: Chomper):
    return ios_syscall.handle_sys_openat(emu)


@register_syscall_handler(const.NR_CLOSE)
def handle_nr_close(emu: Chomper):
    return ios_syscall.handle_sys_close(emu)


@register_syscall_handler(const.NR_GETDENTS64)
def handle_nr_getdents64(emu: Chomper):
    fd = emu.get_arg(0)
    buf = emu.get_arg(1)
    buf_size = emu.get_arg(2)

    result = emu.android_os.getdents(fd)
    if result is None:
        return 0

    if buf_size < len(result):
        return 0

    emu.write_bytes(buf, result[:buf_size])

    return len(result)


@register_syscall_handler(const.NR_LSEEK)
def handle_nr_lseek(emu: Chomper):
    return ios_syscall.handle_sys_lseek(emu)


@register_syscall_handler(const.NR_READ)
def handle_nr_read(emu: Chomper):
    return ios_syscall.handle_sys_read(emu)


@register_syscall_handler(const.NR_WRITE)
def handle_nr_write(emu: Chomper):
    return ios_syscall.handle_sys_write(emu)


@register_syscall_handler(const.NR_READV)
def handle_nr_readv(emu: Chomper):
    return ios_syscall.handle_sys_readv(emu)


@register_syscall_handler(const.NR_WRITEV)
def handle_nr_writev(emu: Chomper):
    return ios_syscall.handle_sys_writev(emu)


@register_syscall_handler(const.NR_PREAD64)
def handle_nr_pread64(emu: Chomper):
    return ios_syscall.handle_sys_pread(emu)


@register_syscall_handler(const.NR_PREADV64)
def handle_nr_preadv64(emu: Chomper):
    return ios_syscall.handle_sys_preadv(emu)


@register_syscall_handler(const.NR_READLINKAT)
def handle_nr_readlinkat(emu: Chomper):
    return ios_syscall.handle_sys_readlinkat(emu)


@register_syscall_handler(const.NR_FSTATAT)
def handle_nr_fstatat(emu: Chomper):
    return ios_syscall.handle_sys_fstatat64(emu)


@register_syscall_handler(const.NR_FSTAT)
def handle_nr_fstat(emu: Chomper):
    return ios_syscall.handle_sys_fstat64(emu)


@register_syscall_handler(const.NR_FSYNC)
def handle_nr_fsync(emu: Chomper):
    return ios_syscall.handle_sys_fsync(emu)


@register_syscall_handler(const.NR_EXIT_GROUP)
def handle_nr_exit_group(emu: Chomper):
    return ios_syscall.handle_sys_exit(emu)


@register_syscall_handler(const.NR_NANOSLEEP)
def handle_nr_nanosleep(emu: Chomper):
    return 0


@register_syscall_handler(const.NR_CLOCK_SETTIME)
def handle_nr_clock_settime(emu: Chomper):
    return 0


@register_syscall_handler(const.NR_CLOCK_GETTIME)
def handle_nr_clock_gettime(emu: Chomper):
    timespec = emu.get_arg(1)

    result = emu.android_os.clock_gettime()
    emu.write_bytes(timespec, result)

    return 0


@register_syscall_handler(const.NR_CLOCK_GETRES)
def handle_nr_clock_getres(emu: Chomper):
    timespec = emu.get_arg(1)

    result = emu.android_os.clock_getres()
    emu.write_bytes(timespec, result)

    return 0


@register_syscall_handler(const.NR_CLOCK_NANOSLEEP)
def handle_nr_clock_nanosleep(emu: Chomper):
    return 0


@register_syscall_handler(const.NR_SETRESGID)
def handle_nr_setresgid(emu: Chomper):
    permission_denied()


@register_syscall_handler(const.NR_GETPGID)
def handle_nr_getpgid(emu: Chomper):
    pid = emu.get_arg(0)

    if pid != 0:
        permission_denied()

    return 1


@register_syscall_handler(const.NR_PRCTL)
def handle_nr_prctl(emu: Chomper):
    return 0


@register_syscall_handler(const.NR_GETTIMEOFDAY)
def handle_nr_gettimeofday(emu: Chomper):
    return ios_syscall.handle_sys_gettimeofday(emu)


@register_syscall_handler(const.NR_GETPID)
def handle_nr_getpid(emu: Chomper):
    return emu.os.pid


@register_syscall_handler(const.NR_GETPPID)
def handle_nr_getppid(emu: Chomper):
    return 1


@register_syscall_handler(const.NR_GETUID)
def handle_ur_getuid(emu: Chomper):
    return emu.os.uid


@register_syscall_handler(const.NR_GETEUID)
def handle_ur_geteuid(emu: Chomper):
    return emu.os.uid


@register_syscall_handler(const.NR_GETEGID)
def handle_ur_getegid(emu: Chomper):
    return 1


@register_syscall_handler(const.NR_MUNMAP)
def handle_nr_munmap(emu: Chomper):
    return ios_syscall.handle_sys_munmap(emu)


@register_syscall_handler(const.NR_MMAP)
def handle_nr_mmap(emu: Chomper):
    return ios_syscall.handle_sys_mmap(emu)


@register_syscall_handler(const.NR_CLOCK_ADJTIME)
def handle_nr_clock_adjtime(emu: Chomper):
    return 0
