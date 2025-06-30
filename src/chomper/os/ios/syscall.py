from __future__ import annotations

import ctypes
import os
import random
import time
from functools import wraps
from typing import Dict, TYPE_CHECKING

from unicorn import arm64_const

from chomper.exceptions import SystemOperationFailed, ProgramTerminated
from chomper.os.base import SyscallError
from chomper.typing import SyscallHandleCallable
from chomper.utils import struct2bytes, to_signed

from . import const
from .structs import Rusage
from .sysctl import sysctl, sysctlbyname

if TYPE_CHECKING:
    from chomper.core import Chomper

SYSCALL_MAP: Dict[int, str] = {
    const.SYS_EXIT: "SYS_exit",
    const.SYS_READ: "SYS_read",
    const.SYS_WRITE: "SYS_write",
    const.SYS_OPEN: "SYS_open",
    const.SYS_CLOSE: "SYS_close",
    const.SYS_LINK: "SYS_link",
    const.SYS_UNLINK: "SYS_unlink",
    const.SYS_CHDIR: "SYS_chdir",
    const.SYS_FCHDIR: "SYS_fchdir",
    const.SYS_CHMOD: "SYS_chmod",
    const.SYS_CHOWN: "SYS_chown",
    const.SYS_GETPID: "SYS_getpid",
    const.SYS_GETUID: "SYS_getuid",
    const.SYS_GETEUID: "SYS_geteuid",
    const.SYS_KILL: "SYS_kill",
    const.SYS_ACCESS: "SYS_access",
    const.SYS_CHFLAGS: "SYS_chflags",
    const.SYS_FCHFLAGS: "SYS_fchflags",
    const.SYS_GETPPID: "SYS_getppid",
    const.SYS_PIPE: "SYS_pipe",
    const.SYS_GETEGID: "SYS_getegid",
    const.SYS_SIGACTION: "SYS_sigaction",
    const.SYS_SIGPROCMASK: "SYS_sigprocmask",
    const.SYS_SIGALTSTACK: "SYS_sigaltstack",
    const.SYS_IOCTL: "SYS_ioctl",
    const.SYS_SYMLINK: "SYS_symlink",
    const.SYS_READLINK: "SYS_readlink",
    const.SYS_MUNMAP: "SYS_munmap",
    const.SYS_MPROTECT: "SYS_mprotect",
    const.SYS_MADVISE: "SYS_madvise",
    const.SYS_FCNTL: "SYS_fcntl",
    const.SYS_FSYNC: "SYS_fsync",
    const.SYS_SOCKET: "SYS_socket",
    const.SYS_SIGSUSPEND: "SYS_sigsuspend",
    const.SYS_GETTIMEOFDAY: "SYS_gettimeofday",
    const.SYS_GETRUSAGE: "SYS_getrusage",
    const.SYS_READV: "SYS_readv",
    const.SYS_WRITEV: "SYS_writev",
    const.SYS_FCHOWN: "SYS_fchown",
    const.SYS_FCHMOD: "SYS_fchmod",
    const.SYS_RENAME: "SYS_rename",
    const.SYS_MKDIR: "SYS_mkdir",
    const.SYS_RMDIR: "SYS_rmdir",
    const.SYS_ADJTIME: "SYS_adjtime",
    const.SYS_PREAD: "SYS_pread",
    const.SYS_QUOTACTL: "SYS_quotactl",
    const.SYS_CSOPS: "SYS_csops",
    const.SYS_CSOPS_AUDITTOKEN: "SYS_csops_audittoken",
    const.SYS_RLIMIT: "SYS_rlimit",
    const.SYS_SETRLIMIT: "SYS_setrlimit",
    const.SYS_MMAP: "SYS_mmap",
    const.SYS_LSEEK: "SYS_lseek",
    const.SYS_SYSCTL: "SYS_sysctl",
    const.SYS_OPEN_DPROTECTED_NP: "SYS_open_dprotected_np",
    const.SYS_GETATTRLIST: "SYS_getattrlist",
    const.SYS_SETXATTR: "SYS_setxattr",
    const.SYS_FSETXATTR: "SYS_fsetxattr",
    const.SYS_LISTXATTR: "SYS_listxattr",
    const.SYS_SHM_OPEN: "SYS_shm_open",
    const.SYS_SYSCTLBYNAME: "SYS_sysctlbyname",
    const.SYS_GETTID: "SYS_gettid",
    const.SYS_IDENTITYSVC: "SYS_identitysvc",
    const.SYS_PSYNCH_MUTEXWAIT: "SYS_psynch_mutexwait",
    const.SYS_PROCESS_POLICY: "SYS_process_policy",
    const.SYS_ISSETUGID: "SYS_issetugid",
    const.SYS_PROC_INFO: "SYS_proc_info",
    const.SYS_STAT64: "SYS_stat64",
    const.SYS_FSTAT64: "SYS_fstat64",
    const.SYS_LSTAT64: "SYS_lstat64",
    const.SYS_GETDIRENTRIES64: "SYS_getdirentries64",
    const.SYS_STATFS64: "SYS_statfs64",
    const.SYS_FSTATFS64: "SYS_fstatfs64",
    const.SYS_FSSTAT64: "SYS_fsstat64",
    const.SYS_BSDTHREAD_CREATE: "SYS_bsdthread_create",
    const.SYS_LCHOWN: "SYS_lchown",
    const.SYS_MAC_SYSCALL: "SYS_mac_syscall",
    const.SYS_READ_NOCANCEL: "SYS_read_nocancel",
    const.SYS_WRITE_NOCANCEL: "SYS_write_nocancel",
    const.SYS_OPEN_NOCANCEL: "SYS_open_nocancel",
    const.SYS_CLOSE_NOCANCEL: "SYS_close_nocancel",
    const.SYS_FCNTL_NOCANCEL: "SYS_fcntl_nocancel",
    const.SYS_FSYNC_NOCANCEL: "SYS_fsync_nocancel",
    const.SYS_READV_NOCANCEL: "SYS_readv_nocancel",
    const.SYS_WRITEV_NOCANCEL: "SYS_writev_nocancel",
    const.SYS_PREAD_NOCANCEL: "SYS_pread_nocancel",
    const.SYS_GETATTRLISTBULK: "SYS_getattrlistbulk",
    const.SYS_OPENAT: "SYS_openat",
    const.SYS_OPENAT_NOCANCEL: "SYS_openat_nocancel",
    const.SYS_RENAMEAT: "SYS_renameat",
    const.SYS_FACCESSAT: "SYS_faccessat",
    const.SYS_FCHMODAT: "SYS_fchmodat",
    const.SYS_FCHOWNAT: "SYS_fchownat",
    const.SYS_FSTATAT64: "SYS_fstatat64",
    const.SYS_LINKAT: "SYS_linkat",
    const.SYS_UNLINKAT: "SYS_unlinkat",
    const.SYS_READLINKAT: "SYS_readlinkat",
    const.SYS_SYMLINKAT: "SYS_symlinkat",
    const.SYS_MKDIRAT: "SYS_mkdirat",
    const.SYS_PERSONA: "SYS_persona",
    const.SYS_GETENTROPY: "SYS_getentropy",
    const.SYS_ULOCK_WAIT: "SYS_ulock_wait",
    const.SYS_PREADV: "SYS_preadv",
    const.SYS_PREADV_NOCANCEL: "SYS_preadv_nocancel",
    const.SYS_GUARDED_OPEN_NP: "SYS_guarded_open_np",
    const.MACH_ABSOLUTE_TIME_TRAP: "MACH_ABSOLUTE_TIME_TRAP",
    const.KERNELRPC_MACH_VM_ALLOCATE_TRAP: "KERNELRPC_MACH_VM_ALLOCATE_TRAP",
    const.KERNELRPC_MACH_VM_PURGABLE_CONTROL_TRAP: (
        "KERNELRPC_MACH_VM_PURGABLE_CONTROL_TRAP"
    ),
    const.KERNELRPC_MACH_VM_DEALLOCATE_TRAP: "KERNELRPC_MACH_VM_DEALLOCATE_TRAP",
    const.KERNELRPC_MACH_PORT_ALLOCATE_TRAP: "KERNELRPC_MACH_PORT_ALLOCATE_TRAP",
    const.KERNELRPC_MACH_PORT_INSERT_MEMBER_TRAP: (
        "KERNELRPC_MACH_PORT_INSERT_MEMBER_TRAP"
    ),
    const.KERNELRPC_MACH_VM_PROTECT_TRAP: "KERNELRPC_MACH_VM_PROTECT_TRAP",
    const.KERNELRPC_MACH_VM_MAP_TRAP: "KERNELRPC_MACH_VM_MAP_TRAP",
    const.KERNELRPC_MACH_PORT_CONSTRUCT_TRAP: "KERNELRPC_MACH_PORT_CONSTRUCT_TRAP",
    const.MACH_REPLY_PORT_TRAP: "MACH_REPLY_PORT_TRAP",
    const.TASK_SELF_TRAP: "TASK_SELF_TRAP",
    const.HOST_SELF_TRAP: "HOST_SELF_TRAP",
    const.MACH_MSG_TRAP: "MACH_MSG_TRAP",
    const.KERNELRPC_MACH_PORT_TYPE_TRAP: "KERNELRPC_MACH_PORT_TYPE_TRAP",
    const.MACH_TIMEBASE_INFO_TRAP: "MACH_TIMEBASE_INFO_TRAP",
    const.MK_TIMER_CREATE_TRAP: "MK_TIMER_CREATE_TRAP",
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
                emu.os.errno = error_no

            # Clear the carry flag after called, many functions will
            # check it after system calls.
            nzcv = emu.uc.reg_read(arm64_const.UC_ARM64_REG_NZCV)
            emu.uc.reg_write(arm64_const.UC_ARM64_REG_NZCV, nzcv & ~(1 << 29))

            return retval

        syscall_handlers[syscall_no] = decorator
        return f

    return wrapper


def permission_denied():
    raise SystemOperationFailed("No permission", SyscallError.EPERM)


@register_syscall_handler(const.SYS_EXIT)
def handle_sys_exit(emu: Chomper):
    status = emu.get_arg(0)

    raise ProgramTerminated("Program terminated with status: %s" % status)


@register_syscall_handler(const.SYS_READ)
@register_syscall_handler(const.SYS_READ_NOCANCEL)
def handle_sys_read(emu: Chomper):
    fd = emu.get_arg(0)
    buf = emu.get_arg(1)
    size = emu.get_arg(2)

    data = emu.os.read(fd, size)
    emu.write_bytes(buf, data)

    return len(data)


@register_syscall_handler(const.SYS_WRITE)
@register_syscall_handler(const.SYS_WRITE_NOCANCEL)
def handle_sys_write(emu: Chomper):
    fd = emu.get_arg(0)
    buf = emu.get_arg(1)
    size = emu.get_arg(2)

    return emu.os.write(fd, buf, size)


@register_syscall_handler(const.SYS_OPEN)
@register_syscall_handler(const.SYS_OPEN_NOCANCEL)
def handle_sys_open(emu: Chomper):
    path = emu.read_string(emu.get_arg(0))
    flags = emu.get_arg(1)
    mode = emu.get_arg(2)

    return emu.os.open(path, flags, mode)


@register_syscall_handler(const.SYS_CLOSE)
@register_syscall_handler(const.SYS_CLOSE_NOCANCEL)
def handle_sys_close(emu: Chomper):
    fd = emu.get_arg(0)

    emu.os.close(fd)

    return 0


@register_syscall_handler(const.SYS_LINK)
def handle_sys_link(emu: Chomper):
    src_path = emu.read_string(emu.get_arg(0))
    dst_path = emu.read_string(emu.get_arg(1))

    emu.os.link(src_path, dst_path)

    return 0


@register_syscall_handler(const.SYS_UNLINK)
def handle_sys_unlink(emu: Chomper):
    path = emu.read_string(emu.get_arg(0))

    emu.os.unlink(path)

    return 0


@register_syscall_handler(const.SYS_CHDIR)
def handle_sys_chdir(emu: Chomper):
    path = emu.read_string(emu.get_arg(0))

    emu.os.chdir(path)

    return 0


@register_syscall_handler(const.SYS_FCHDIR)
def handle_sys_fchdir(emu: Chomper):
    fd = emu.get_arg(0)

    emu.os.fchdir(fd)

    return 0


@register_syscall_handler(const.SYS_CHMOD)
def handle_sys_chmod(emu: Chomper):
    path = emu.read_string(emu.get_arg(0))
    mode = emu.get_arg(1)

    emu.os.chmod(path, mode)

    return 0


@register_syscall_handler(const.SYS_CHOWN)
def handle_sys_chown(emu: Chomper):
    path = emu.read_string(emu.get_arg(0))
    uid = emu.get_arg(1)
    gid = emu.get_arg(2)

    emu.os.chown(path, uid, gid)

    return 0


@register_syscall_handler(const.SYS_GETPID)
def handle_sys_getpid(emu: Chomper):
    return emu.os.pid


@register_syscall_handler(const.SYS_GETUID)
def handle_sys_getuid(emu: Chomper):
    return emu.os.uid


@register_syscall_handler(const.SYS_GETEUID)
def handle_sys_geteuid(emu: Chomper):
    return emu.os.uid


@register_syscall_handler(const.SYS_KILL)
def handle_sys_kill(emu: Chomper):
    return -1


@register_syscall_handler(const.SYS_ACCESS)
def handle_sys_access(emu: Chomper):
    path = emu.read_string(emu.get_arg(0))
    mode = emu.get_arg(1)

    if not emu.os.access(path, mode):
        return -1

    return 0


@register_syscall_handler(const.SYS_CHFLAGS)
def handle_sys_chflags(emu: Chomper):
    permission_denied()


@register_syscall_handler(const.SYS_FCHFLAGS)
def handle_sys_fchflags(emu: Chomper):
    permission_denied()


@register_syscall_handler(const.SYS_GETPPID)
def handle_sys_getppid(emu: Chomper):
    return 1


@register_syscall_handler(const.SYS_PIPE)
def handle_sys_pipe(emu: Chomper):
    return -1


@register_syscall_handler(const.SYS_SIGACTION)
def handle_sys_sigaction(emu: Chomper):
    return 0


@register_syscall_handler(const.SYS_SIGPROCMASK)
def handle_sys_sigprocmask(emu: Chomper):
    return 0


@register_syscall_handler(const.SYS_SIGALTSTACK)
def handle_sys_sigaltstack(emu: Chomper):
    return 0


@register_syscall_handler(const.SYS_IOCTL)
def handle_sys_ioctl(emu: Chomper):
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


@register_syscall_handler(const.SYS_SYMLINK)
def handle_sys_symlink(emu: Chomper):
    src_path = emu.read_string(emu.get_arg(0))
    dst_path = emu.read_string(emu.get_arg(1))

    emu.os.symlink(src_path, dst_path)

    return 0


@register_syscall_handler(const.SYS_READLINK)
def handle_sys_readlink(emu: Chomper):
    path = emu.read_string(emu.get_arg(0))
    buf = emu.get_arg(1)
    buf_size = emu.get_arg(2)

    result = emu.os.readlink(path)
    if result is None or len(result) > buf_size:
        return -1

    emu.write_string(buf, result)

    return 0


@register_syscall_handler(const.SYS_MUNMAP)
def handle_sys_munmap(emu: Chomper):
    addr = emu.get_arg(0)

    emu.free(addr)

    return 0


@register_syscall_handler(const.SYS_MPROTECT)
def handle_sys_mprotect(emu: Chomper):
    return 0


@register_syscall_handler(const.SYS_MADVISE)
def handle_sys_madvise(emu: Chomper):
    return 0


@register_syscall_handler(const.SYS_GETEGID)
def handle_sys_getegid(emu: Chomper):
    return 1


@register_syscall_handler(const.SYS_GETTIMEOFDAY)
def handle_sys_gettimeofday(emu: Chomper):
    tv = emu.get_arg(0)

    result = emu.os.gettimeofday()
    emu.write_bytes(tv, result)

    return 0


@register_syscall_handler(const.SYS_GETRUSAGE)
def handle_sys_getrusage(emu: Chomper):
    r = emu.get_arg(1)

    rusage = Rusage()
    emu.write_bytes(r, struct2bytes(rusage))

    return 0


@register_syscall_handler(const.SYS_READV)
@register_syscall_handler(const.SYS_READV_NOCANCEL)
def handle_sys_readv(emu: Chomper):
    fd = emu.get_arg(0)
    iov = emu.get_arg(1)
    iovcnt = emu.get_arg(2)

    result = 0

    for _ in range(iovcnt):
        iov_base = emu.read_pointer(iov)
        iov_len = emu.read_u64(iov + 8)

        data = emu.os.read(fd, iov_len)
        emu.write_bytes(iov_base, data)

        result += len(data)

        if len(data) != iov_len:
            break

        iov += 16

    return result


@register_syscall_handler(const.SYS_WRITEV)
@register_syscall_handler(const.SYS_WRITEV_NOCANCEL)
def handle_sys_writev(emu: Chomper):
    fd = emu.get_arg(0)
    iov = emu.get_arg(1)
    iovcnt = emu.get_arg(2)

    result = 0

    for _ in range(iovcnt):
        iov_base = emu.read_pointer(iov)
        iov_len = emu.read_u64(iov + 8)

        write_len = emu.os.write(fd, iov_base, iov_len)
        result += write_len

        if write_len != iov_len:
            break

        iov += 16

    return result


@register_syscall_handler(const.SYS_FCHOWN)
def handle_sys_fchown(emu: Chomper):
    fd = emu.get_arg(0)
    uid = emu.get_arg(1)
    gid = emu.get_arg(2)

    emu.os.fchown(fd, uid, gid)

    return 0


@register_syscall_handler(const.SYS_FCHMOD)
def handle_sys_fchmod(emu: Chomper):
    fd = emu.get_arg(0)
    mode = emu.get_arg(1)

    emu.os.fchmod(fd, mode)

    return 0


@register_syscall_handler(const.SYS_RENAME)
def handle_sys_rename(emu: Chomper):
    old = emu.read_string(emu.get_arg(0))
    new = emu.read_string(emu.get_arg(1))

    emu.os.rename(old, new)

    return 0


@register_syscall_handler(const.SYS_MKDIR)
def handle_sys_mkdir(emu: Chomper):
    path = emu.read_string(emu.get_arg(0))
    mode = emu.get_arg(1)

    emu.os.mkdir(path, mode)

    return 0


@register_syscall_handler(const.SYS_RMDIR)
def handle_sys_rmdir(emu: Chomper):
    path = emu.read_string(emu.get_arg(0))

    emu.os.rmdir(path)

    return 0


@register_syscall_handler(const.SYS_ADJTIME)
def handle_sys_adjtime(emu: Chomper):
    permission_denied()


@register_syscall_handler(const.SYS_PREAD)
@register_syscall_handler(const.SYS_PREAD_NOCANCEL)
def handle_sys_pread(emu: Chomper):
    fd = emu.get_arg(0)
    buf = emu.get_arg(1)
    size = emu.get_arg(2)
    offset = emu.get_arg(3)

    data = emu.os.pread(fd, size, offset)
    emu.write_bytes(buf, data)

    return len(data)


@register_syscall_handler(const.SYS_QUOTACTL)
def handle_sys_quotactl(emu: Chomper):
    return 0


@register_syscall_handler(const.SYS_CSOPS)
def handle_sys_csops(emu: Chomper):
    useraddr = emu.get_arg(2)
    emu.write_u32(useraddr, 0x4000800)

    return 0


@register_syscall_handler(const.SYS_CSOPS_AUDITTOKEN)
def handle_sys_csops_audittoken(emu: Chomper):
    return 0


@register_syscall_handler(const.SYS_RLIMIT)
def handle_sys_rlimit(emu: Chomper):
    return 0


@register_syscall_handler(const.SYS_SETRLIMIT)
def handle_sys_setrlimit(emu: Chomper):
    return 0


@register_syscall_handler(const.SYS_MMAP)
def handle_sys_mmap(emu: Chomper):
    length = emu.get_arg(1)
    fd = to_signed(emu.get_arg(4), 4)
    offset = emu.get_arg(5)

    buf = emu.create_buffer(length)

    if fd != -1:
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
def handle_sys_lseek(emu: Chomper):
    fd = emu.get_arg(0)
    offset = emu.get_arg(1)
    whence = emu.get_arg(2)

    offset = to_signed(offset, 8)

    return emu.os.lseek(fd, offset, whence)


@register_syscall_handler(const.SYS_FSYNC)
@register_syscall_handler(const.SYS_FSYNC_NOCANCEL)
def handle_sys_fsync(emu: Chomper):
    fd = emu.get_arg(0)

    emu.os.fsync(fd)

    return 0


@register_syscall_handler(const.SYS_SOCKET)
def handle_sys_socket(emu: Chomper):
    return -1


@register_syscall_handler(const.SYS_SIGSUSPEND)
def handle_sys_sigsuspend(emu: Chomper):
    return -1


@register_syscall_handler(const.SYS_FCNTL)
@register_syscall_handler(const.SYS_FCNTL_NOCANCEL)
def handle_sys_fcntl(emu: Chomper):
    fd = emu.get_arg(0)
    cmd = emu.get_arg(1)
    arg = emu.get_arg(2)

    if cmd == const.F_GETFL:
        if fd in (emu.os.stdin,):
            return os.O_RDONLY
        elif fd in (emu.os.stdout, emu.os.stderr):
            return os.O_WRONLY
    elif cmd == const.F_GETPATH:
        path = emu.os.get_dir_path(fd)
        if path:
            emu.write_string(arg, path)
    else:
        emu.logger.warning(f"Unhandled fcntl command: {cmd}")

    return 0


@register_syscall_handler(const.SYS_SYSCTL)
def handle_sys_sysctl(emu: Chomper):
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


@register_syscall_handler(const.SYS_OPEN_DPROTECTED_NP)
def handle_sys_open_dprotected_np(emu: Chomper):
    path = emu.read_string(emu.get_arg(0))
    flags = emu.get_arg(1)
    mode = emu.get_arg(4)

    return emu.os.open(path, flags, mode)


@register_syscall_handler(const.SYS_GETATTRLIST)
def handle_sys_getattrlist(emu: Chomper):
    return -1


@register_syscall_handler(const.SYS_SETXATTR)
def handle_sys_setxattr(emu: Chomper):
    return 0


@register_syscall_handler(const.SYS_FSETXATTR)
def handle_sys_fsetxattr(emu: Chomper):
    return 0


@register_syscall_handler(const.SYS_LISTXATTR)
def handle_sys_listxattr(emu: Chomper):
    return 0


@register_syscall_handler(const.SYS_SHM_OPEN)
def handle_sys_shm_open(emu: Chomper):
    return 0x80000000


@register_syscall_handler(const.SYS_SYSCTLBYNAME)
def handle_sys_sysctlbyname(emu: Chomper):
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
def handle_sys_gettid(emu: Chomper):
    return 1000


@register_syscall_handler(const.SYS_IDENTITYSVC)
def handle_sys_identitysvc(emu: Chomper):
    permission_denied()


@register_syscall_handler(const.SYS_PSYNCH_MUTEXWAIT)
def handle_sys_psynch_mutexwait(emu: Chomper):
    return 0


@register_syscall_handler(const.SYS_PROCESS_POLICY)
def handle_sys_process_policy(emu: Chomper):
    return 0


@register_syscall_handler(const.SYS_ISSETUGID)
def handle_sys_issetugid(emu: Chomper):
    return 0


@register_syscall_handler(const.SYS_PROC_INFO)
def handle_sys_proc_info(emu: Chomper):
    pid = emu.get_arg(1)
    flavor = emu.get_arg(2)
    buffer = emu.get_arg(4)

    if pid != emu.ios_os.pid:
        permission_denied()

    if flavor == 3:
        emu.write_string(buffer, emu.ios_os.program_path.split("/")[-1])
    elif flavor == 11:
        emu.write_string(buffer, emu.ios_os.program_path)

    return 0


@register_syscall_handler(const.SYS_STAT64)
def handle_sys_stat64(emu: Chomper):
    path = emu.read_string(emu.get_arg(0))
    stat = emu.get_arg(1)

    emu.write_bytes(stat, emu.os.stat(path))

    return 0


@register_syscall_handler(const.SYS_FSTAT64)
def handle_sys_fstat64(emu: Chomper):
    fd = emu.get_arg(0)
    stat = emu.get_arg(1)

    emu.write_bytes(stat, emu.os.fstat(fd))

    return 0


@register_syscall_handler(const.SYS_LSTAT64)
def handle_sys_lstat64(emu: Chomper):
    path = emu.read_string(emu.get_arg(0))
    stat = emu.get_arg(1)

    emu.write_bytes(stat, emu.os.lstat(path))

    return 0


@register_syscall_handler(const.SYS_GETDIRENTRIES64)
def handle_sys_getdirentries64(emu: Chomper):
    fd = emu.get_arg(0)
    buf = emu.get_arg(1)
    nbytes = emu.get_arg(2)
    basep = emu.get_arg(3)

    base = emu.read_u64(basep)

    result = emu.ios_os.getdirentries(fd, base)
    if result is None:
        return 0

    if nbytes < len(result):
        return 0

    emu.write_bytes(buf, result[:nbytes])
    emu.write_u64(basep, base + 1)

    return len(result)


@register_syscall_handler(const.SYS_STATFS64)
def handle_sys_statfs64(emu: Chomper):
    path = emu.read_string(emu.get_arg(0))
    statfs = emu.get_arg(1)

    emu.write_bytes(statfs, emu.os.statfs(path))

    return 0


@register_syscall_handler(const.SYS_FSTATFS64)
def handle_sys_fstatfs64(emu: Chomper):
    fd = emu.get_arg(0)
    statfs = emu.get_arg(1)

    emu.write_bytes(statfs, emu.os.fstatfs(fd))

    return 0


@register_syscall_handler(const.SYS_FSSTAT64)
def handle_sys_fsstat64(emu: Chomper):
    statfs = emu.get_arg(0)
    if not statfs:
        return 1

    emu.write_bytes(statfs, emu.os.statfs("/"))

    return 0


@register_syscall_handler(const.SYS_BSDTHREAD_CREATE)
def handle_sys_bsdthread_create(emu: Chomper):
    emu.logger.warning("Emulator ignored a thread create reqeust.")
    emu.log_backtrace()
    return 0


@register_syscall_handler(const.SYS_LCHOWN)
def handle_sys_lchown(emu: Chomper):
    path = emu.read_string(emu.get_arg(0))
    uid = emu.get_arg(1)
    gid = emu.get_arg(2)

    emu.os.lchown(path, uid, gid)

    return 0


@register_syscall_handler(const.SYS_MAC_SYSCALL)
def handle_sys_mac_syscall(emu: Chomper):
    cmd = emu.read_string(emu.get_arg(0))
    emu.logger.info(f"Recv mac syscall command: {cmd}")

    if cmd == "Sandbox":
        pass
    else:
        emu.logger.warning(f"Unhandled mac syscall command: {cmd}")

    return 0


@register_syscall_handler(const.SYS_PERSONA)
def handle_sys_persona(emu: Chomper):
    return 0


@register_syscall_handler(const.SYS_GETENTROPY)
def handle_sys_getentropy(emu: Chomper):
    buffer = emu.get_arg(0)
    size = emu.get_arg(1)

    rand_bytes = bytes([random.randint(0, 255) for _ in range(size)])
    emu.write_bytes(buffer, rand_bytes)

    return 0


@register_syscall_handler(const.SYS_GETATTRLISTBULK)
def handle_sys_getattrlistbulk(emu: Chomper):
    return 0


@register_syscall_handler(const.SYS_OPENAT)
@register_syscall_handler(const.SYS_OPENAT_NOCANCEL)
def handle_sys_openat(emu: Chomper):
    dir_fd = to_signed(emu.get_arg(0), 4)
    path = emu.read_string(emu.get_arg(1))
    flags = emu.get_arg(2)
    mode = emu.get_arg(3)

    return emu.os.openat(dir_fd, path, flags, mode)


@register_syscall_handler(const.SYS_FACCESSAT)
def handle_sys_faccessat(emu: Chomper):
    dir_fd = to_signed(emu.get_arg(0), 4)
    path = emu.read_string(emu.get_arg(1))
    mode = emu.get_arg(2)

    if not emu.os.faccessat(dir_fd, path, mode):
        return -1

    return 0


@register_syscall_handler(const.SYS_FCHMODAT)
def handle_sys_fchmodat(emu: Chomper):
    dir_fd = to_signed(emu.get_arg(0), 4)
    path = emu.read_string(emu.get_arg(1))
    mode = emu.get_arg(2)

    emu.os.fchmodat(dir_fd, path, mode)

    return 0


@register_syscall_handler(const.SYS_FCHOWNAT)
def handle_sys_fchownat(emu: Chomper):
    dir_fd = to_signed(emu.get_arg(0), 4)
    path = emu.read_string(emu.get_arg(1))
    uid = emu.get_arg(2)
    gid = emu.get_arg(3)

    emu.os.fchownat(dir_fd, path, uid, gid)

    return 0


@register_syscall_handler(const.SYS_FSTATAT64)
def handle_sys_fstatat64(emu: Chomper):
    dir_fd = to_signed(emu.get_arg(0), 4)
    path = emu.read_string(emu.get_arg(1))
    stat = emu.get_arg(2)

    emu.write_bytes(stat, emu.os.fstatat(dir_fd, path))

    return 0


@register_syscall_handler(const.SYS_RENAMEAT)
def handle_sys_renameat(emu: Chomper):
    src_fd = emu.get_arg(0)
    old = emu.read_string(emu.get_arg(1))
    dst_fd = emu.get_arg(2)
    new = emu.read_string(emu.get_arg(3))

    emu.os.renameat(src_fd, old, dst_fd, new)

    return 0


@register_syscall_handler(const.SYS_LINKAT)
def handle_sys_linkat(emu: Chomper):
    src_dir_fd = to_signed(emu.get_arg(0), 4)
    src_path = emu.read_string(emu.get_arg(1))
    dst_dir_fd = to_signed(emu.get_arg(2), 4)
    dst_path = emu.read_string(emu.get_arg(3))

    emu.os.linkat(src_dir_fd, src_path, dst_dir_fd, dst_path)

    return 0


@register_syscall_handler(const.SYS_UNLINKAT)
def handle_sys_unlinkat(emu: Chomper):
    dir_fd = to_signed(emu.get_arg(0), 4)
    path = emu.read_string(emu.get_arg(1))

    emu.os.unlinkat(dir_fd, path)

    return 0


@register_syscall_handler(const.SYS_READLINKAT)
def handle_sys_readlinkat(emu: Chomper):
    dir_fd = to_signed(emu.get_arg(0), 4)
    path = emu.read_string(emu.get_arg(1))

    emu.os.readlinkat(dir_fd, path)

    return 0


@register_syscall_handler(const.SYS_SYMLINKAT)
def handle_sys_symlinkat(emu: Chomper):
    src_dir_fd = to_signed(emu.get_arg(0), 4)
    src_path = emu.read_string(emu.get_arg(1))
    dst_dir_fd = to_signed(emu.get_arg(2), 4)
    dst_path = emu.read_string(emu.get_arg(3))

    emu.os.symlinkat(src_dir_fd, src_path, dst_dir_fd, dst_path)

    return 0


@register_syscall_handler(const.SYS_MKDIRAT)
def handle_sys_mkdirat(emu: Chomper):
    dir_fd = to_signed(emu.get_arg(0), 4)
    path = emu.read_string(emu.get_arg(1))
    mode = emu.get_arg(2)

    emu.os.mkdirat(dir_fd, path, mode)

    return 0


# @register_syscall_handler(const.SYS_ULOCK_WAIT)
# def handle_sys_ulock_wait(emu: Chomper):
#     return 0


@register_syscall_handler(const.SYS_PREADV)
@register_syscall_handler(const.SYS_PREADV_NOCANCEL)
def handle_sys_preadv(emu: Chomper):
    fd = emu.get_arg(0)
    iov = emu.get_arg(1)
    iovcnt = emu.get_arg(2)
    offset = emu.get_arg(3)

    pos = os.lseek(fd, 0, os.SEEK_CUR)
    os.lseek(fd, offset, os.SEEK_SET)

    result = 0

    for _ in range(iovcnt):
        iov_base = emu.read_pointer(iov)
        iov_len = emu.read_u64(iov + 8)

        data = emu.os.read(fd, iov_len)
        emu.write_bytes(iov_base, data)

        result += len(data)

        if len(data) != iov_len:
            break

        iov += 16

    os.lseek(fd, pos, os.SEEK_SET)

    return result


@register_syscall_handler(const.SYS_GUARDED_OPEN_NP)
def handle_sys_guarded_open_np(emu: Chomper):
    path = emu.read_string(emu.get_arg(0))
    flags = emu.get_arg(3)
    mode = emu.get_arg(4)

    return emu.os.open(path, flags, mode)


@register_syscall_handler(const.MACH_ABSOLUTE_TIME_TRAP)
def handle_mach_absolute_time_trap(emu: Chomper):
    return int(time.time_ns() % (3600 * 10**9))


@register_syscall_handler(const.KERNELRPC_MACH_VM_ALLOCATE_TRAP)
def handle_kernelrpc_mach_vm_allocate_trap(emu: Chomper):
    address = emu.get_arg(1)
    size = emu.get_arg(2)

    mem = emu.memory_manager.alloc(size)
    emu.write_pointer(address, mem)

    return 0


@register_syscall_handler(const.KERNELRPC_MACH_VM_PURGABLE_CONTROL_TRAP)
def handle_kernelrpc_mach_vm_purgable_control_trap(emu: Chomper):
    return 0


@register_syscall_handler(const.KERNELRPC_MACH_VM_DEALLOCATE_TRAP)
def handle_kernelrpc_mach_vm_deallocate_trap(emu: Chomper):
    mem = emu.get_arg(1)

    emu.memory_manager.free(mem)

    return 0


@register_syscall_handler(const.KERNELRPC_MACH_VM_PROTECT_TRAP)
def handle_kernelrpc_mach_vm_protect_trap(emu: Chomper):
    return 0


@register_syscall_handler(const.KERNELRPC_MACH_VM_MAP_TRAP)
def handle_kernelrpc_mach_vm_map_trap(emu: Chomper):
    address = emu.get_arg(1)
    size = emu.get_arg(2)

    mem = emu.memory_manager.alloc(size)
    emu.write_pointer(address, mem)

    return 0


@register_syscall_handler(const.KERNELRPC_MACH_PORT_ALLOCATE_TRAP)
def handle_kernelrpc_mach_port_allocate_trap(emu: Chomper):
    return 0


@register_syscall_handler(const.KERNELRPC_MACH_PORT_INSERT_MEMBER_TRAP)
def handle_kernelrpc_mach_port_insert_member_trap(emu: Chomper):
    return 0


@register_syscall_handler(const.KERNELRPC_MACH_PORT_CONSTRUCT_TRAP)
def handle_kernelrpc_mach_port_construct_trap(emu: Chomper):
    name = emu.get_arg(3)

    # mach_port_name
    emu.write_u32(name, 1)

    return 0


@register_syscall_handler(const.MACH_REPLY_PORT_TRAP)
def handle_mach_reply_port_trap(emu: Chomper):
    return 0


@register_syscall_handler(const.TASK_SELF_TRAP)
def handle_task_self_trap(emu: Chomper):
    return 0


@register_syscall_handler(const.HOST_SELF_TRAP)
def handle_host_self_trap(emu: Chomper):
    return 2563


@register_syscall_handler(const.MACH_MSG_TRAP)
def handle_mach_msg_trap(emu: Chomper):
    # msg = emu.get_arg(0)

    # msgh_size:
    # emu.write_u32(msg + 0x4, 36)

    # msgh_remote_port
    # emu.write_u32(msg + 0x8, 0)

    # msgh_id
    # emu.write_u32(msg + 0x14, 8100)

    return 6


@register_syscall_handler(const.KERNELRPC_MACH_PORT_TYPE_TRAP)
def handle_kernelrpc_mach_port_type_trap(emu: Chomper):
    ptype = emu.get_arg(2)

    value = 0
    value |= const.MACH_PORT_TYPE_SEND
    value |= const.MACH_PORT_TYPE_RECEIVE

    emu.write_u32(ptype, value)

    return 0


@register_syscall_handler(const.MACH_TIMEBASE_INFO_TRAP)
def handle_mach_timebase_info_trap(emu: Chomper):
    info = emu.get_arg(0)

    emu.write_u32(info, 1)
    emu.write_u32(info + 4, 1)

    return 0


@register_syscall_handler(const.MK_TIMER_CREATE_TRAP)
def handle_mk_timer_create_trap(emu: Chomper):
    # Return mach_port_name
    return 1
