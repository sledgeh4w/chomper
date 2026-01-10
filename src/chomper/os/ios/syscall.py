from __future__ import annotations

import ctypes
import os
import random
import time
from functools import wraps
from typing import Dict, Optional, TYPE_CHECKING

from unicorn import arm64_const

from chomper.exceptions import SystemOperationFailed, ProgramTerminated
from chomper.os.posix import SyscallError
from chomper.typing import SyscallHandleCallable
from chomper.utils import to_signed, struct_to_bytes, bytes_to_struct

from . import const
from .structs import (
    Timespec,
    Rusage,
    ProcBsdinfo,
    ProcBsdshortinfo,
    ProcUniqidentifierinfo,
)
from .sysctl import sysctl, sysctlbyname

if TYPE_CHECKING:
    from chomper.core import Chomper


SYSCALL_ERRORS = {
    SyscallError.EPERM: (const.EPERM, "EPERM"),
    SyscallError.ENOENT: (const.ENOENT, "ENOENT"),
    SyscallError.EBADF: (const.EBADF, "EBADF"),
    SyscallError.EACCES: (const.EACCES, "EACCES"),
    SyscallError.EFAULT: (const.EFAULT, "EFAULT"),
    SyscallError.EEXIST: (const.EEXIST, "EEXIST"),
    SyscallError.ENOTDIR: (const.ENOTDIR, "ENOTDIR"),
    SyscallError.EXT1: (60, "EXT1"),
}

syscall_handlers: Dict[int, SyscallHandleCallable] = {}
syscall_names: Dict[int, str] = {}


def get_syscall_handlers() -> Dict[int, SyscallHandleCallable]:
    """Get the default system call handlers."""
    return syscall_handlers.copy()


def get_syscall_names() -> Dict[int, str]:
    """Get the system call name mapping."""
    return syscall_names.copy()


def register_syscall_handler(syscall_no: int, syscall_name: Optional[str] = None):
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
            except UnicodeDecodeError:
                error_type = SyscallError.EPERM
            except SystemOperationFailed as e:
                error_type = e.error_type

            if error_type in SYSCALL_ERRORS:
                error_no, error_name = SYSCALL_ERRORS[error_type]

                emu.logger.info(f"Set errno {error_name}({error_no})")
                emu.os.set_errno(error_no)
            else:
                emu.os.set_errno(0)

            # Clear the carry flag after called, many functions will
            # check it after system calls.
            nzcv = emu.uc.reg_read(arm64_const.UC_ARM64_REG_NZCV)
            emu.uc.reg_write(arm64_const.UC_ARM64_REG_NZCV, nzcv & ~(1 << 29))

            return retval

        syscall_handlers[syscall_no] = decorator

        if syscall_name:
            syscall_names[syscall_no] = syscall_name

        return f

    return wrapper


def raise_permission_denied():
    raise SystemOperationFailed("No permission", SyscallError.EPERM)


@register_syscall_handler(const.SYS_EXIT, "SYS_exit")
def handle_sys_exit(emu: Chomper):
    status = emu.get_arg(0)

    raise ProgramTerminated("Program terminated with status: %s" % status)


@register_syscall_handler(const.SYS_READ, "SYS_read")
@register_syscall_handler(const.SYS_READ_NOCANCEL, "SYS_read_nocancel")
def handle_sys_read(emu: Chomper):
    fd = emu.get_arg(0)
    buf = emu.get_arg(1)
    size = emu.get_arg(2)

    data = emu.os.read(fd, size)
    emu.write_bytes(buf, data)

    return len(data)


@register_syscall_handler(const.SYS_WRITE, "SYS_write")
@register_syscall_handler(const.SYS_WRITE_NOCANCEL, "SYS_write_nocancel")
def handle_sys_write(emu: Chomper):
    fd = emu.get_arg(0)
    buf = emu.get_arg(1)
    size = emu.get_arg(2)

    return emu.os.write(fd, buf, size)


@register_syscall_handler(const.SYS_OPEN, "SYS_open")
@register_syscall_handler(const.SYS_OPEN_NOCANCEL, "SYS_open_nocancel")
def handle_sys_open(emu: Chomper):
    path = emu.read_string(emu.get_arg(0))
    flags = emu.get_arg(1)
    mode = emu.get_arg(2)

    return emu.os.open(path, flags, mode)


@register_syscall_handler(const.SYS_CLOSE, "SYS_close")
@register_syscall_handler(const.SYS_CLOSE_NOCANCEL, "SYS_close_nocancel")
def handle_sys_close(emu: Chomper):
    fd = emu.get_arg(0)

    emu.os.close(fd)

    return 0


@register_syscall_handler(const.SYS_LINK, "SYS_link")
def handle_sys_link(emu: Chomper):
    src_path = emu.read_string(emu.get_arg(0))
    dst_path = emu.read_string(emu.get_arg(1))

    emu.os.link(src_path, dst_path)

    return 0


@register_syscall_handler(const.SYS_UNLINK, "SYS_unlink")
def handle_sys_unlink(emu: Chomper):
    path = emu.read_string(emu.get_arg(0))

    emu.os.unlink(path)

    return 0


@register_syscall_handler(const.SYS_CHDIR, "SYS_chdir")
def handle_sys_chdir(emu: Chomper):
    path = emu.read_string(emu.get_arg(0))

    emu.os.chdir(path)

    return 0


@register_syscall_handler(const.SYS_FCHDIR, "SYS_fchdir")
def handle_sys_fchdir(emu: Chomper):
    fd = emu.get_arg(0)

    emu.os.fchdir(fd)

    return 0


@register_syscall_handler(const.SYS_CHMOD, "SYS_chmod")
def handle_sys_chmod(emu: Chomper):
    path = emu.read_string(emu.get_arg(0))
    mode = emu.get_arg(1)

    emu.os.chmod(path, mode)

    return 0


@register_syscall_handler(const.SYS_CHOWN, "SYS_chown")
def handle_sys_chown(emu: Chomper):
    path = emu.read_string(emu.get_arg(0))
    uid = emu.get_arg(1)
    gid = emu.get_arg(2)

    emu.os.chown(path, uid, gid)

    return 0


@register_syscall_handler(const.SYS_GETPID, "SYS_getpid")
def handle_sys_getpid(emu: Chomper):
    return emu.os.pid


@register_syscall_handler(const.SYS_GETUID, "SYS_getuid")
def handle_sys_getuid(emu: Chomper):
    return emu.os.uid


@register_syscall_handler(const.SYS_GETEUID, "SYS_geteuid")
def handle_sys_geteuid(emu: Chomper):
    return emu.os.uid


@register_syscall_handler(const.SYS_SENDMSG, "SYS_sendmsg")
@register_syscall_handler(const.SYS_SENDMSG_NOCANCEL, "SYS_sendmsg_nocancel")
def handle_sys_sendmsg(emu: Chomper):
    sock = emu.get_arg(0)
    buffer = emu.get_arg(1)
    flags = emu.get_arg(2)

    return emu.os.sendmsg(sock, buffer, flags)


@register_syscall_handler(const.SYS_RECVFROM, "SYS_recvfrom")
@register_syscall_handler(const.SYS_RECVFROM_NOCANCEL, "SYS_recvfrom_nocancel")
def handle_sys_recvfrom(emu: Chomper):
    sock = emu.get_arg(0)
    buffer = emu.get_arg(1)
    length = emu.get_arg(2)
    flags = emu.get_arg(3)
    address = emu.get_arg(4)
    address_len = emu.get_arg(5)

    return emu.os.recvfrom(sock, buffer, length, flags, address, address_len)


@register_syscall_handler(const.SYS_KILL, "SYS_kill")
def handle_sys_kill(emu: Chomper):
    return -1


@register_syscall_handler(const.SYS_ACCESS, "SYS_access")
def handle_sys_access(emu: Chomper):
    path = emu.read_string(emu.get_arg(0))
    mode = emu.get_arg(1)

    if not emu.os.access(path, mode):
        return -1

    return 0


@register_syscall_handler(const.SYS_CHFLAGS, "SYS_chflags")
def handle_sys_chflags(emu: Chomper):
    raise_permission_denied()

    return 0


@register_syscall_handler(const.SYS_FCHFLAGS, "SYS_fchflags")
def handle_sys_fchflags(emu: Chomper):
    raise_permission_denied()

    return 0


@register_syscall_handler(const.SYS_GETPPID, "SYS_getppid")
def handle_sys_getppid(emu: Chomper):
    return 1


@register_syscall_handler(const.SYS_PIPE, "SYS_pipe")
def handle_sys_pipe(emu: Chomper):
    return -1


@register_syscall_handler(const.SYS_SIGACTION, "SYS_sigaction")
def handle_sys_sigaction(emu: Chomper):
    return 0


@register_syscall_handler(const.SYS_SIGPROCMASK, "SYS_sigprocmask")
def handle_sys_sigprocmask(emu: Chomper):
    return 0


@register_syscall_handler(const.SYS_SIGALTSTACK, "SYS_sigaltstack")
def handle_sys_sigaltstack(emu: Chomper):
    return 0


@register_syscall_handler(const.SYS_IOCTL, "SYS_ioctl")
def handle_sys_ioctl(emu: Chomper):
    fd = emu.get_arg(0)
    req = emu.get_arg(1)

    inout = req & ~((0x3FFF << 16) | 0xFF00 | 0xFF)
    group = (req >> 8) & 0xFF
    num = req & 0xFF
    length = (req >> 16) & 0x3FFF

    emu.logger.info(
        f"Received an ioctl request: fd={fd}, inout={hex(inout)}, "
        f"group='{chr(group)}', num={num}, length={length}"
    )

    emu.logger.warning("ioctl request not processed")
    return 0


@register_syscall_handler(const.SYS_SYMLINK, "SYS_symlink")
def handle_sys_symlink(emu: Chomper):
    src_path = emu.read_string(emu.get_arg(0))
    dst_path = emu.read_string(emu.get_arg(1))

    emu.os.symlink(src_path, dst_path)

    return 0


@register_syscall_handler(const.SYS_READLINK, "SYS_readlink")
def handle_sys_readlink(emu: Chomper):
    path = emu.read_string(emu.get_arg(0))
    buf = emu.get_arg(1)
    buf_size = emu.get_arg(2)

    result = emu.os.readlink(path)
    if result is None or len(result) > buf_size:
        return -1

    emu.write_string(buf, result)

    return 0


@register_syscall_handler(const.SYS_MUNMAP, "SYS_munmap")
def handle_sys_munmap(emu: Chomper):
    addr = emu.get_arg(0)

    emu.free(addr)

    return 0


@register_syscall_handler(const.SYS_MPROTECT, "SYS_mprotect")
def handle_sys_mprotect(emu: Chomper):
    return 0


@register_syscall_handler(const.SYS_MADVISE, "SYS_madvise")
def handle_sys_madvise(emu: Chomper):
    return 0


@register_syscall_handler(const.SYS_GETEGID, "SYS_getegid")
def handle_sys_getegid(emu: Chomper):
    return emu.os.gid


@register_syscall_handler(const.SYS_GETTIMEOFDAY, "SYS_gettimeofday")
def handle_sys_gettimeofday(emu: Chomper):
    tv = emu.get_arg(0)

    result = emu.os.gettimeofday()
    emu.write_bytes(tv, result)

    return 0


@register_syscall_handler(const.SYS_GETRUSAGE, "SYS_getrusage")
def handle_sys_getrusage(emu: Chomper):
    r = emu.get_arg(1)

    rusage = Rusage()
    emu.write_bytes(r, struct_to_bytes(rusage))

    return 0


@register_syscall_handler(const.SYS_READV, "SYS_readv")
@register_syscall_handler(const.SYS_READV_NOCANCEL, "SYS_readv_nocancel")
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


@register_syscall_handler(const.SYS_WRITEV, "SYS_writev")
@register_syscall_handler(const.SYS_WRITEV_NOCANCEL, "SYS_writev_nocancel")
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


@register_syscall_handler(const.SYS_FCHOWN, "SYS_fchown")
def handle_sys_fchown(emu: Chomper):
    fd = emu.get_arg(0)
    uid = emu.get_arg(1)
    gid = emu.get_arg(2)

    emu.os.fchown(fd, uid, gid)

    return 0


@register_syscall_handler(const.SYS_FCHMOD, "SYS_fchmod")
def handle_sys_fchmod(emu: Chomper):
    fd = emu.get_arg(0)
    mode = emu.get_arg(1)

    emu.os.fchmod(fd, mode)

    return 0


@register_syscall_handler(const.SYS_RENAME, "SYS_rename")
def handle_sys_rename(emu: Chomper):
    old = emu.read_string(emu.get_arg(0))
    new = emu.read_string(emu.get_arg(1))

    emu.os.rename(old, new)

    return 0


@register_syscall_handler(const.SYS_SENDTO, "SYS_sendto")
@register_syscall_handler(const.SYS_SENDTO_NOCANCEL, "SYS_sendto_nocancel")
def handle_sys_sendto(emu: Chomper):
    sock = emu.get_arg(0)
    buffer = emu.get_arg(1)
    length = emu.get_arg(2)
    flags = emu.get_arg(3)
    dest_addr = emu.get_arg(4)
    dest_len = emu.get_arg(5)

    return emu.os.sendto(sock, buffer, length, flags, dest_addr, dest_len)


@register_syscall_handler(const.SYS_SOCKETPAIR, "SYS_socketpair")
def handle_sys_socketpair(emu):
    domain = emu.get_arg(0)
    sock_type = emu.get_arg(1)
    protocol = emu.get_arg(2)
    socket_vector = emu.get_arg(3)

    result = emu.os.socketpair(domain, sock_type, protocol)
    if not result:
        return -1

    emu.write_s32(socket_vector, result[0])
    emu.write_s32(socket_vector + 4, result[1])

    return 0


@register_syscall_handler(const.SYS_MKDIR, "SYS_mkdir")
def handle_sys_mkdir(emu: Chomper):
    path = emu.read_string(emu.get_arg(0))
    mode = emu.get_arg(1)

    emu.os.mkdir(path, mode)

    return 0


@register_syscall_handler(const.SYS_RMDIR, "SYS_rmdir")
def handle_sys_rmdir(emu: Chomper):
    path = emu.read_string(emu.get_arg(0))

    emu.os.rmdir(path)

    return 0


@register_syscall_handler(const.SYS_UTIMES, "SYS_utimes")
def handle_sys_utimes(emu: Chomper):
    path = emu.read_string(emu.get_arg(0))
    times_ptr = emu.get_arg(1)

    if times_ptr:
        time1 = emu.read_bytes(times_ptr, ctypes.sizeof(Timespec))
        time2 = emu.read_bytes(
            times_ptr + ctypes.sizeof(Timespec), ctypes.sizeof(Timespec)
        )
        times = (
            bytes_to_struct(time1, Timespec).to_seconds(),
            bytes_to_struct(time2, Timespec).to_seconds(),
        )
    else:
        times = None

    emu.os.utimes(path, times)

    return 0


@register_syscall_handler(const.SYS_FUTIMES, "SYS_futimes")
def handle_sys_futimes(emu: Chomper):
    fd = emu.get_arg(0)
    times_ptr = emu.get_arg(1)

    if times_ptr:
        time1 = emu.read_bytes(times_ptr, ctypes.sizeof(Timespec))
        time2 = emu.read_bytes(
            times_ptr + ctypes.sizeof(Timespec), ctypes.sizeof(Timespec)
        )
        times = (
            bytes_to_struct(time1, Timespec).to_seconds(),
            bytes_to_struct(time2, Timespec).to_seconds(),
        )
    else:
        times = None

    emu.os.futimes(fd, times)

    return 0


@register_syscall_handler(const.SYS_ADJTIME, "SYS_adjtime")
def handle_sys_adjtime(emu: Chomper):
    raise_permission_denied()

    return 0


@register_syscall_handler(const.SYS_PREAD, "SYS_pread")
@register_syscall_handler(const.SYS_PREAD_NOCANCEL, "SYS_pread_nocancel")
def handle_sys_pread(emu: Chomper):
    fd = emu.get_arg(0)
    buf = emu.get_arg(1)
    size = emu.get_arg(2)
    offset = emu.get_arg(3)

    data = emu.os.pread(fd, size, offset)
    emu.write_bytes(buf, data)

    return len(data)


@register_syscall_handler(const.SYS_PWRITE, "SYS_pwrite")
@register_syscall_handler(const.SYS_PWRITE_NOCANCEL, "SYS_pwrite_nocancel")
def handle_sys_pwrite(emu: Chomper):
    fd = emu.get_arg(0)
    buf = emu.get_arg(1)
    size = emu.get_arg(2)
    offset = emu.get_arg(3)

    return emu.os.pwrite(fd, buf, size, offset)


@register_syscall_handler(const.SYS_QUOTACTL, "SYS_quotactl")
def handle_sys_quotactl(emu: Chomper):
    return 0


@register_syscall_handler(const.SYS_CSOPS, "SYS_csops")
def handle_sys_csops(emu: Chomper):
    useraddr = emu.get_arg(2)
    emu.write_u32(useraddr, 0x4000800)

    return 0


@register_syscall_handler(const.SYS_CSOPS_AUDITTOKEN, "SYS_csops_audittoken")
def handle_sys_csops_audittoken(emu: Chomper):
    return 0


@register_syscall_handler(const.SYS_RLIMIT, "SYS_rlimit")
def handle_sys_rlimit(emu: Chomper):
    return 0


@register_syscall_handler(const.SYS_SETRLIMIT, "SYS_setrlimit")
def handle_sys_setrlimit(emu: Chomper):
    return 0


@register_syscall_handler(const.SYS_MMAP, "SYS_mmap")
def handle_sys_mmap(emu: Chomper):
    length = emu.get_arg(1)
    fd = to_signed(emu.get_arg(4), 4)
    offset = emu.get_arg(5)

    buf = emu.create_buffer(length)

    if fd != -1:
        chunk_size = 1024 * 1024
        content = b""

        while True:
            chunk = emu.ios_os.read(fd, chunk_size)
            if not chunk:
                break
            content += chunk

        emu.write_bytes(buf, content[offset:])

    return buf


@register_syscall_handler(const.SYS_LSEEK, "SYS_lseek")
def handle_sys_lseek(emu: Chomper):
    fd = emu.get_arg(0)
    offset = emu.get_arg(1)
    whence = emu.get_arg(2)

    offset = to_signed(offset, 8)

    return emu.os.lseek(fd, offset, whence)


@register_syscall_handler(const.SYS_FSYNC, "SYS_fsync")
@register_syscall_handler(const.SYS_FSYNC_NOCANCEL, "SYS_fsync_nocancel")
def handle_sys_fsync(emu: Chomper):
    fd = emu.get_arg(0)

    emu.os.fsync(fd)

    return 0


@register_syscall_handler(const.SYS_SOCKET, "SYS_socket")
def handle_sys_socket(emu):
    domain = emu.get_arg(0)
    sock_type = emu.get_arg(1)
    protocol = emu.get_arg(2)

    return emu.os.socket(domain, sock_type, protocol)


@register_syscall_handler(const.SYS_CONNECT, "SYS_connect")
@register_syscall_handler(const.SYS_CONNECT_NOCANCEL, "SYS_connect_nocancel")
def handle_sys_connect(emu):
    sock = emu.get_arg(0)
    address = emu.get_arg(1)
    address_len = emu.get_arg(2)

    return emu.os.connect(sock, address, address_len)


@register_syscall_handler(const.SYS_BIND, "SYS_bind")
def handle_sys_bind(emu):
    sock = emu.get_arg(0)
    address = emu.get_arg(1)
    address_len = emu.get_arg(2)

    return emu.os.bind(sock, address, address_len)


@register_syscall_handler(const.SYS_SETSOCKOPT, "SYS_setsockopt")
def handle_sys_setsockopt(emu):
    sock = emu.get_arg(0)
    level = emu.get_arg(1)
    option_name = emu.get_arg(2)
    option_value = emu.get_arg(3)
    option_len = emu.get_arg(4)

    return emu.os.setsockopt(sock, level, option_name, option_value, option_len)


@register_syscall_handler(const.SYS_GETSOCKOPT, "SYS_getsockopt")
def handle_sys_getsockopt(emu):
    sock = emu.get_arg(0)
    level = emu.get_arg(1)
    option_name = emu.get_arg(2)
    option_value = emu.get_arg(3)
    option_len = emu.get_arg(4)

    return emu.os.getsockopt(sock, level, option_name, option_value, option_len)


@register_syscall_handler(const.SYS_SIGSUSPEND, "SYS_sigsuspend")
def handle_sys_sigsuspend(emu: Chomper):
    return -1


@register_syscall_handler(const.SYS_FCNTL, "SYS_fcntl")
@register_syscall_handler(const.SYS_FCNTL_NOCANCEL, "SYS_fcntl_nocancel")
def handle_sys_fcntl(emu: Chomper):
    fd = emu.get_arg(0)
    cmd = emu.get_arg(1)
    arg = emu.get_arg(2)

    return emu.os.fcntl(fd, cmd, arg)


@register_syscall_handler(const.SYS_SELECT, "SYS_select")
@register_syscall_handler(const.SYS_SELECT_NOCANCEL, "SYS_select_nocancel")
def handle_sys_select(emu: Chomper):
    nfds = emu.get_arg(0)
    readfds = emu.get_arg(1)
    writefds = emu.get_arg(2)
    errorfds = emu.get_arg(3)
    timeout = emu.get_arg(4)

    return emu.os.select(nfds, readfds, writefds, errorfds, timeout)


@register_syscall_handler(const.SYS_FTRUNCATE, "SYS_ftruncate")
def handle_sys_ftruncate(emu: Chomper):
    fd = emu.get_arg(0)
    length = emu.get_arg(1)

    emu.os.ftruncate(fd, length)

    return 0


@register_syscall_handler(const.SYS_SYSCTL, "SYS_sysctl")
def handle_sys_sysctl(emu: Chomper):
    name = emu.get_arg(0)
    oldp = emu.get_arg(2)
    oldlenp = emu.get_arg(3)

    ctl_type = emu.read_u32(name)
    ctl_ident = emu.read_u32(name + 4)

    result = sysctl(ctl_type, ctl_ident)
    if result is None:
        emu.logger.warning(f"Unhandled sysctl command: {ctl_type}, {ctl_ident}")
        return -1

    if oldp:
        if isinstance(result, ctypes.Structure):
            emu.write_bytes(oldp, struct_to_bytes(result))
        elif isinstance(result, str):
            emu.write_string(oldp, result)
        elif isinstance(result, int):
            emu.write_u64(oldp, result)

    if oldlenp:
        if isinstance(result, ctypes.Structure):
            emu.write_u32(oldlenp, ctypes.sizeof(result))
        elif isinstance(result, str):
            emu.write_u32(oldlenp, len(result))
        elif isinstance(result, int):
            emu.write_u32(oldlenp, 8)

    return 0


@register_syscall_handler(const.SYS_OPEN_DPROTECTED_NP, "SYS_open_dprotected_np")
def handle_sys_open_dprotected_np(emu: Chomper):
    path = emu.read_string(emu.get_arg(0))
    flags = emu.get_arg(1)
    mode = emu.get_arg(4)

    return emu.os.open(path, flags, mode)


@register_syscall_handler(const.SYS_GETATTRLIST, "SYS_getattrlist")
def handle_sys_getattrlist(emu: Chomper):
    return -1


@register_syscall_handler(const.SYS_SETXATTR, "SYS_setxattr")
def handle_sys_setxattr(emu: Chomper):
    return 0


@register_syscall_handler(const.SYS_FSETXATTR, "SYS_fsetxattr")
def handle_sys_fsetxattr(emu: Chomper):
    return 0


@register_syscall_handler(const.SYS_LISTXATTR, "SYS_listxattr")
def handle_sys_listxattr(emu: Chomper):
    return 0


@register_syscall_handler(const.SYS_SHM_OPEN, "SYS_shm_open")
def handle_sys_shm_open(emu: Chomper):
    return 0x80000000


@register_syscall_handler(const.SYS_SYSCTLBYNAME, "SYS_sysctlbyname")
def handle_sys_sysctlbyname(emu: Chomper):
    name = emu.read_string(emu.get_arg(0))
    oldp = emu.get_arg(2)
    oldlenp = emu.get_arg(3)

    result = sysctlbyname(name)
    if result is None:
        emu.logger.warning(f"Unhandled sysctl command: {name}")
        return -1

    if oldp:
        if isinstance(result, ctypes.Structure):
            emu.write_bytes(oldp, struct_to_bytes(result))
        elif isinstance(result, str):
            emu.write_string(oldp, result)
        elif isinstance(result, int):
            emu.write_u64(oldp, result)

    if oldlenp:
        if isinstance(result, ctypes.Structure):
            emu.write_u32(oldlenp, ctypes.sizeof(result))
        elif isinstance(result, str):
            emu.write_u32(oldlenp, len(result))
        elif isinstance(result, int):
            emu.write_u32(oldlenp, 8)

    return 0


@register_syscall_handler(const.SYS_GETTID, "SYS_gettid")
def handle_sys_gettid(emu: Chomper):
    return emu.os.tid


@register_syscall_handler(const.SYS_IDENTITYSVC, "SYS_identitysvc")
def handle_sys_identitysvc(emu: Chomper):
    raise_permission_denied()

    return 0


@register_syscall_handler(const.SYS_PSYNCH_MUTEXWAIT, "SYS_psynch_mutexwait")
def handle_sys_psynch_mutexwait(emu: Chomper):
    return 0


@register_syscall_handler(const.SYS_PROCESS_POLICY, "SYS_process_policy")
def handle_sys_process_policy(emu: Chomper):
    return 0


@register_syscall_handler(const.SYS_ISSETUGID, "SYS_issetugid")
def handle_sys_issetugid(emu: Chomper):
    return 0


@register_syscall_handler(const.SYS_PTHREAD_SIGMASK, "SYS_pthread_sigmask")
def handle_sys_pthread_sigmask(emu: Chomper):
    return 0


@register_syscall_handler(const.SYS_SEMWAIT_SIGNAL, "SYS_semwait_signal")
@register_syscall_handler(
    const.SYS_SEMWAIT_SIGNAL_NOCANCEL, "SYS_semwait_signal_nocancel"
)
def handle_sys_semwait_signal(emu: Chomper):
    raise SystemOperationFailed("Wait signal", SyscallError.EXT1)


@register_syscall_handler(const.SYS_PROC_INFO, "SYS_proc_info")
def handle_sys_proc_info(emu: Chomper):
    pid = emu.get_arg(1)
    flavor = emu.get_arg(2)
    buffer = emu.get_arg(4)

    if pid != emu.ios_os.pid:
        raise_permission_denied()

    emu.logger.info(f"pid={pid}, flavor={flavor}")

    if flavor == const.PROC_PIDTBSDINFO:
        bsd_info = ProcBsdinfo(
            pbi_pid=emu.ios_os.pid,
            pbi_ppid=1,
            pbi_uid=emu.ios_os.uid,
            pbi_gid=emu.ios_os.gid,
        )
        result = struct_to_bytes(bsd_info)
    elif flavor == const.PROC_PIDPATHINFO:
        emu.write_string(buffer, emu.ios_os.executable_path)
        result = emu.ios_os.executable_path.encode("utf-8")
    elif flavor == const.PROC_PIDT_SHORTBSDINFO:
        bsd_short_info = ProcBsdshortinfo(
            pbsi_pid=emu.ios_os.pid,
            pbsi_ppid=1,
            pbsi_uid=emu.ios_os.uid,
            pbsi_gid=emu.ios_os.gid,
        )
        result = struct_to_bytes(bsd_short_info)
    elif flavor == const.PROC_PIDUNIQIDENTIFIERINFO:
        uniq_identifier_info = ProcUniqidentifierinfo()
        result = struct_to_bytes(uniq_identifier_info)
    else:
        emu.logger.warning("Unhandled proc_info call")
        return 0

    emu.write_bytes(buffer, result)
    return len(result)


@register_syscall_handler(const.SYS_STAT64, "SYS_stat64")
def handle_sys_stat64(emu: Chomper):
    path = emu.read_string(emu.get_arg(0))
    stat = emu.get_arg(1)

    emu.write_bytes(stat, emu.os.stat(path))

    return 0


@register_syscall_handler(const.SYS_FSTAT64, "SYS_fstat64")
def handle_sys_fstat64(emu: Chomper):
    fd = emu.get_arg(0)
    stat = emu.get_arg(1)

    emu.write_bytes(stat, emu.os.fstat(fd))

    return 0


@register_syscall_handler(const.SYS_LSTAT64, "SYS_lstat64")
def handle_sys_lstat64(emu: Chomper):
    path = emu.read_string(emu.get_arg(0))
    stat = emu.get_arg(1)

    emu.write_bytes(stat, emu.os.lstat(path))

    return 0


@register_syscall_handler(const.SYS_GETDIRENTRIES64, "SYS_getdirentries64")
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


@register_syscall_handler(const.SYS_STATFS64, "SYS_statfs64")
def handle_sys_statfs64(emu: Chomper):
    path = emu.read_string(emu.get_arg(0))
    statfs = emu.get_arg(1)

    emu.write_bytes(statfs, emu.os.statfs(path))

    return 0


@register_syscall_handler(const.SYS_FSTATFS64, "SYS_fstatfs64")
def handle_sys_fstatfs64(emu: Chomper):
    fd = emu.get_arg(0)
    statfs = emu.get_arg(1)

    emu.write_bytes(statfs, emu.os.fstatfs(fd))

    return 0


@register_syscall_handler(const.SYS_FSSTAT64, "SYS_fsstat64")
def handle_sys_fsstat64(emu: Chomper):
    statfs = emu.get_arg(0)
    if not statfs:
        return 1

    emu.write_bytes(statfs, emu.os.statfs("/"))

    return 0


@register_syscall_handler(const.SYS_BSDTHREAD_CREATE, "SYS_bsdthread_create")
def handle_sys_bsdthread_create(emu: Chomper):
    emu.logger.warning("Emulator ignored a thread create reqeust.")
    emu.log_backtrace()

    # start_routine = emu.get_arg(0)
    # arg = emu.get_arg(1)
    #
    # emu.set_arg(0, arg)
    # emu.call_address(start_routine)

    return 0


@register_syscall_handler(const.SYS_KQUEUE, "SYS_kqueue")
def handle_sys_kqueue(emu: Chomper):
    return -1


@register_syscall_handler(const.SYS_LCHOWN, "SYS_lchown")
def handle_sys_lchown(emu: Chomper):
    path = emu.read_string(emu.get_arg(0))
    uid = emu.get_arg(1)
    gid = emu.get_arg(2)

    emu.os.lchown(path, uid, gid)

    return 0


@register_syscall_handler(const.SYS_WORKQ_OPEN, "SYS_workq_open")
def handle_sys_workq_open(emu: Chomper):
    return 0


@register_syscall_handler(const.SYS_WORKQ_KERNRETURN, "SYS_workq_kernreturn")
def handle_sys_workq_kernreturn(emu: Chomper):
    return 0


@register_syscall_handler(const.SYS_KEVENT_QOS, "SYS_kevent_qos")
def handle_sys_kevent_qos(emu: Chomper):
    return 0


@register_syscall_handler(const.SYS_KEVENT_ID, "SYS_kevent_id")
def handle_sys_kevent_id(emu: Chomper):
    return 0


@register_syscall_handler(const.SYS_MAC_SYSCALL, "SYS_mac_syscall")
def handle_sys_mac_syscall(emu: Chomper):
    cmd = emu.read_string(emu.get_arg(0))
    emu.logger.info(f"Received a mac syscall command: {cmd}")

    if cmd == "Sandbox":
        pass
    else:
        emu.logger.warning(f"Unhandled mac syscall command: {cmd}")

    return 0


@register_syscall_handler(const.SYS_PERSONA, "SYS_persona")
def handle_sys_persona(emu: Chomper):
    return 0


@register_syscall_handler(const.SYS_GETENTROPY, "SYS_getentropy")
def handle_sys_getentropy(emu: Chomper):
    buffer = emu.get_arg(0)
    size = emu.get_arg(1)

    rand_bytes = bytes([random.randint(0, 255) for _ in range(size)])
    emu.write_bytes(buffer, rand_bytes)

    return 0


@register_syscall_handler(const.SYS_NECP_OPEN, "SYS_necp_open")
def handle_necp_open(emu: Chomper):
    return -1


@register_syscall_handler(const.SYS_GUARDED_OPEN_NP, "SYS_guarded_open_np")
def handle_sys_guarded_open_np(emu: Chomper):
    path = emu.read_string(emu.get_arg(0))
    flags = emu.get_arg(3)
    mode = emu.get_arg(4)

    return emu.os.open(path, flags, mode)


@register_syscall_handler(const.SYS_GUARDED_CLOSE_NP, "SYS_guarded_close_np")
def handle_sys_guarded_close_np(emu: Chomper):
    fd = emu.get_arg(0)

    emu.os.close(fd)

    return 0


@register_syscall_handler(const.SYS_GETATTRLISTBULK, "SYS_getattrlistbulk")
def handle_sys_getattrlistbulk(emu: Chomper):
    return 0


@register_syscall_handler(const.SYS_CLONEFILEAT, "SYS_clonefileat")
def handle_sys_clonefileat(emu: Chomper):
    src_dir_fd = to_signed(emu.get_arg(0), 4)
    src_path = emu.read_string(emu.get_arg(1))
    dst_dir_fd = to_signed(emu.get_arg(2), 4)
    dst_path = emu.read_string(emu.get_arg(3))

    emu.ios_os.clonefileat(src_dir_fd, src_path, dst_dir_fd, dst_path)

    return 0


@register_syscall_handler(const.SYS_OPENAT, "SYS_openat")
@register_syscall_handler(const.SYS_OPENAT_NOCANCEL, "SYS_openat_nocancel")
def handle_sys_openat(emu: Chomper):
    dir_fd = to_signed(emu.get_arg(0), 4)
    path = emu.read_string(emu.get_arg(1))
    flags = emu.get_arg(2)
    mode = emu.get_arg(3)

    return emu.os.openat(dir_fd, path, flags, mode)


@register_syscall_handler(const.SYS_FACCESSAT, "SYS_faccessat")
def handle_sys_faccessat(emu: Chomper):
    dir_fd = to_signed(emu.get_arg(0), 4)
    path = emu.read_string(emu.get_arg(1))
    mode = emu.get_arg(2)

    if not emu.os.faccessat(dir_fd, path, mode):
        return -1

    return 0


@register_syscall_handler(const.SYS_FCHMODAT, "SYS_fchmodat")
def handle_sys_fchmodat(emu: Chomper):
    dir_fd = to_signed(emu.get_arg(0), 4)
    path = emu.read_string(emu.get_arg(1))
    mode = emu.get_arg(2)

    emu.os.fchmodat(dir_fd, path, mode)

    return 0


@register_syscall_handler(const.SYS_FCHOWNAT, "SYS_fchownat")
def handle_sys_fchownat(emu: Chomper):
    dir_fd = to_signed(emu.get_arg(0), 4)
    path = emu.read_string(emu.get_arg(1))
    uid = emu.get_arg(2)
    gid = emu.get_arg(3)

    emu.os.fchownat(dir_fd, path, uid, gid)

    return 0


@register_syscall_handler(const.SYS_FSTATAT64, "SYS_fstatat64")
def handle_sys_fstatat64(emu: Chomper):
    dir_fd = to_signed(emu.get_arg(0), 4)
    path = emu.read_string(emu.get_arg(1))
    stat = emu.get_arg(2)

    emu.write_bytes(stat, emu.os.fstatat(dir_fd, path))

    return 0


@register_syscall_handler(const.SYS_RENAMEAT, "SYS_renameat")
def handle_sys_renameat(emu: Chomper):
    src_fd = emu.get_arg(0)
    old = emu.read_string(emu.get_arg(1))
    dst_fd = emu.get_arg(2)
    new = emu.read_string(emu.get_arg(3))

    emu.os.renameat(src_fd, old, dst_fd, new)

    return 0


@register_syscall_handler(const.SYS_LINKAT, "SYS_linkat")
def handle_sys_linkat(emu: Chomper):
    src_dir_fd = to_signed(emu.get_arg(0), 4)
    src_path = emu.read_string(emu.get_arg(1))
    dst_dir_fd = to_signed(emu.get_arg(2), 4)
    dst_path = emu.read_string(emu.get_arg(3))

    emu.os.linkat(src_dir_fd, src_path, dst_dir_fd, dst_path)

    return 0


@register_syscall_handler(const.SYS_UNLINKAT, "SYS_unlinkat")
def handle_sys_unlinkat(emu: Chomper):
    dir_fd = to_signed(emu.get_arg(0), 4)
    path = emu.read_string(emu.get_arg(1))

    emu.os.unlinkat(dir_fd, path)

    return 0


@register_syscall_handler(const.SYS_READLINKAT, "SYS_readlinkat")
def handle_sys_readlinkat(emu: Chomper):
    dir_fd = to_signed(emu.get_arg(0), 4)
    path = emu.read_string(emu.get_arg(1))

    emu.os.readlinkat(dir_fd, path)

    return 0


@register_syscall_handler(const.SYS_SYMLINKAT, "SYS_symlinkat")
def handle_sys_symlinkat(emu: Chomper):
    src_dir_fd = to_signed(emu.get_arg(0), 4)
    src_path = emu.read_string(emu.get_arg(1))
    dst_dir_fd = to_signed(emu.get_arg(2), 4)
    dst_path = emu.read_string(emu.get_arg(3))

    emu.os.symlinkat(src_dir_fd, src_path, dst_dir_fd, dst_path)

    return 0


@register_syscall_handler(const.SYS_MKDIRAT, "SYS_mkdirat")
def handle_sys_mkdirat(emu: Chomper):
    dir_fd = to_signed(emu.get_arg(0), 4)
    path = emu.read_string(emu.get_arg(1))
    mode = emu.get_arg(2)

    emu.os.mkdirat(dir_fd, path, mode)

    return 0


@register_syscall_handler(const.SYS_BSDTHREAD_CTL, "SYS_bsdthread_ctl")
def handle_sys_bsdthread_ctl(emu: Chomper):
    return 0


@register_syscall_handler(const.SYS_GUARDED_PWRITE_NP, "SYS_guarded_pwrite_np")
def handle_sys_guarded_pwrite_np(emu: Chomper):
    fd = emu.get_arg(0)
    buf = emu.get_arg(2)
    size = emu.get_arg(3)
    offset = emu.get_arg(4)

    return emu.os.pwrite(fd, buf, size, offset)


@register_syscall_handler(const.SYS_ULOCK_WAIT, "SYS_ulock_wait")
def handle_sys_ulock_wait(emu: Chomper):
    return 0


@register_syscall_handler(
    const.SYS_TERMINATE_WITH_PAYLOAD, "SYS_terminate_with_payload"
)
def handle_terminate_with_payload(emu: Chomper):
    payload = emu.get_arg(5)
    msg = emu.read_string(payload)

    emu.log_backtrace()

    raise ProgramTerminated("terminate with payload: %s" % msg)


@register_syscall_handler(const.SYS_ABORT_WITH_PAYLOAD, "SYS_abort_with_payload")
def handle_abort_with_payload(emu: Chomper):
    payload = emu.get_arg(4)
    msg = emu.read_string(payload)

    emu.log_backtrace()

    raise ProgramTerminated("abort with payload: %s" % msg)


@register_syscall_handler(const.SYS_OS_FAULT_WITH_PAYLOAD, "SYS_os_fault_with_payload")
def handle_os_fault_with_payload(emu: Chomper):
    payload = emu.get_arg(2)
    msg = emu.read_string(payload)

    emu.log_backtrace()

    raise ProgramTerminated("OS fault with payload: %s" % msg)


@register_syscall_handler(const.SYS_PREADV, "SYS_preadv")
@register_syscall_handler(const.SYS_PREADV_NOCANCEL, "SYS_preadv_nocancel")
def handle_sys_preadv(emu: Chomper):
    fd = emu.get_arg(0)
    iov = emu.get_arg(1)
    iovcnt = emu.get_arg(2)
    offset = emu.get_arg(3)

    pos = emu.os.lseek(fd, 0, os.SEEK_CUR)
    emu.os.lseek(fd, offset, os.SEEK_SET)

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

    emu.os.lseek(fd, pos, os.SEEK_SET)

    return result


@register_syscall_handler(const.MACH_ABSOLUTE_TIME_TRAP, "MACH_ABSOLUTE_TIME_TRAP")
def handle_mach_absolute_time_trap(emu: Chomper):
    return int(time.time_ns() % (3600 * 10**9))


@register_syscall_handler(
    const.KERNELRPC_MACH_VM_ALLOCATE_TRAP, "KERNELRPC_MACH_VM_ALLOCATE_TRAP"
)
def handle_kernelrpc_mach_vm_allocate_trap(emu: Chomper):
    address = emu.get_arg(1)
    size = emu.get_arg(2)

    mem = emu.memory_manager.alloc(size)
    emu.write_bytes(mem, bytes(size))

    emu.write_pointer(address, mem)

    return 0


@register_syscall_handler(
    const.KERNELRPC_MACH_VM_PURGABLE_CONTROL_TRAP,
    "KERNELRPC_MACH_VM_PURGABLE_CONTROL_TRAP",
)
def handle_kernelrpc_mach_vm_purgable_control_trap(emu: Chomper):
    return 0


@register_syscall_handler(
    const.KERNELRPC_MACH_VM_DEALLOCATE_TRAP, "KERNELRPC_MACH_VM_DEALLOCATE_TRAP"
)
def handle_kernelrpc_mach_vm_deallocate_trap(emu: Chomper):
    mem = emu.get_arg(1)

    emu.memory_manager.free(mem)

    return 0


@register_syscall_handler(
    const.KERNELRPC_MACH_VM_PROTECT_TRAP, "KERNELRPC_MACH_VM_PROTECT_TRAP"
)
def handle_kernelrpc_mach_vm_protect_trap(emu: Chomper):
    return 0


@register_syscall_handler(
    const.KERNELRPC_MACH_VM_MAP_TRAP, "KERNELRPC_MACH_VM_MAP_TRAP"
)
def handle_kernelrpc_mach_vm_map_trap(emu: Chomper):
    address = emu.get_arg(1)
    size = emu.get_arg(2)

    mem = emu.memory_manager.alloc(size)
    emu.write_pointer(address, mem)

    return 0


@register_syscall_handler(
    const.KERNELRPC_MACH_PORT_ALLOCATE_TRAP, "KERNELRPC_MACH_PORT_ALLOCATE_TRAP"
)
def handle_kernelrpc_mach_port_allocate_trap(emu: Chomper):
    name = emu.get_arg(2)

    port = emu.ios_os.mach_port_construct()
    emu.write_u32(name, port)

    return 0


@register_syscall_handler(
    const.KERNELRPC_MACH_PORT_DEALLOCATE_TRAP, "KERNELRPC_MACH_PORT_DEALLOCATE_TRAP"
)
def handle_kernelrpc_mach_port_deallocate_trap(emu: Chomper):
    name = emu.get_arg(1)

    emu.ios_os.mach_port_destruct(name)

    return 0


@register_syscall_handler(
    const.KERNELRPC_MACH_PORT_MOD_REFS_TRAP, "KERNELRPC_MACH_PORT_MOD_REFS_TRAP"
)
def handle_kernelrpc_mach_port_mod_refs_trap(emu: Chomper):
    return 0


@register_syscall_handler(
    const.KERNELRPC_MACH_PORT_INSERT_MEMBER_TRAP,
    "KERNELRPC_MACH_PORT_INSERT_MEMBER_TRAP",
)
def handle_kernelrpc_mach_port_insert_member_trap(emu: Chomper):
    return 0


@register_syscall_handler(
    const.KERNELRPC_MACH_PORT_CONSTRUCT_TRAP, "KERNELRPC_MACH_PORT_CONSTRUCT_TRAP"
)
def handle_kernelrpc_mach_port_construct_trap(emu: Chomper):
    name = emu.get_arg(3)

    port = emu.ios_os.mach_port_construct()
    emu.write_u32(name, port)

    return 0


@register_syscall_handler(
    const.KERNELRPC_MACH_PORT_DESTRUCT_TRAP, "KERNELRPC_MACH_PORT_DESTRUCT_TRAP"
)
def handle_kernelrpc_mach_port_destruct_trap(emu: Chomper):
    name = emu.get_arg(1)

    emu.ios_os.mach_port_destruct(name)

    return 0


@register_syscall_handler(const.MACH_REPLY_PORT_TRAP, "MACH_REPLY_PORT_TRAP")
def handle_mach_reply_port_trap(emu: Chomper):
    return emu.ios_os.MACH_PORT_REPLY


@register_syscall_handler(const.THREAD_SELF_TRAP, "THREAD_SELF_TRAP")
def handle_thread_self_trap(emu: Chomper):
    return emu.ios_os.MACH_PORT_THREAD


@register_syscall_handler(const.TASK_SELF_TRAP, "TASK_SELF_TRAP")
def handle_task_self_trap(emu: Chomper):
    return emu.ios_os.MACH_PORT_TASK


@register_syscall_handler(const.HOST_SELF_TRAP, "HOST_SELF_TRAP")
def handle_host_self_trap(emu: Chomper):
    return emu.ios_os.MACH_PORT_HOST


@register_syscall_handler(const.MACH_MSG_TRAP, "MACH_MSG_TRAP")
def handle_mach_msg_trap(emu: Chomper):
    msg = emu.get_arg(0)
    option = emu.get_arg(1)
    send_size = emu.get_arg(2)
    rcv_size = emu.get_arg(3)
    rcv_name = emu.get_arg(4)
    timeout = emu.get_arg(5)
    notify = emu.get_arg(6)

    return emu.ios_os.mach_msg(
        msg,
        option,
        send_size,
        rcv_size,
        rcv_name,
        timeout,
        notify,
    )


@register_syscall_handler(const.SEMAPHORE_SIGNAL_TRAP, "SEMAPHORE_SIGNAL_TRAP")
def handle_semaphore_signal_trap(emu: Chomper):
    semaphore = emu.get_arg(0)
    return emu.ios_os.semaphore_signal(semaphore)


@register_syscall_handler(const.SEMAPHORE_WAIT_TRAP, "SEMAPHORE_WAIT_TRAP")
def handle_semaphore_wait_trap(emu: Chomper):
    semaphore = emu.get_arg(0)

    emu.logger.info("Waiting semaphore...")
    return emu.ios_os.semaphore_wait(semaphore)


@register_syscall_handler(
    const.KERNELRPC_MACH_PORT_GUARD_TRAP, "KERNELRPC_MACH_PORT_GUARD_TRAP"
)
def handle_kernelrpc_mach_port_guard_trap(emu: Chomper):
    return 0


@register_syscall_handler(const.MAP_FD_TRAP, "MAP_FD_TRAP")
def handle_map_fd_trap(emu: Chomper):
    activity_id = emu.get_arg(2)

    emu.write_u64(activity_id, random.getrandbits(64))

    return 0


@register_syscall_handler(
    const.THREAD_GET_SPECIAL_REPLY_PORT, "THREAD_GET_SPECIAL_REPLY_PORT"
)
def handle_thread_get_special_reply_port(emu: Chomper):
    return emu.ios_os.MACH_PORT_REPLY


@register_syscall_handler(
    const.HOST_CREATE_MACH_VOUCHER_TRAP, "HOST_CREATE_MACH_VOUCHER_TRAP"
)
def handle_host_create_mach_voucher_trap(emu: Chomper):
    return 0


@register_syscall_handler(
    const.KERNELRPC_MACH_PORT_TYPE_TRAP, "KERNELRPC_MACH_PORT_TYPE_TRAP"
)
def handle_kernelrpc_mach_port_type_trap(emu: Chomper):
    ptype = emu.get_arg(2)

    value = 0
    value |= const.MACH_PORT_TYPE_SEND
    value |= const.MACH_PORT_TYPE_RECEIVE

    emu.write_u32(ptype, value)

    return 0


@register_syscall_handler(
    const.KERNELRPC_MACH_PORT_REQUEST_NOTIFICATION_TRAP,
    "KERNELRPC_MACH_PORT_REQUEST_NOTIFICATION_TRAP",
)
def handle_kernelrpc_mach_port_request_notification_trap(emu: Chomper):
    return 0


@register_syscall_handler(const.MACH_TIMEBASE_INFO_TRAP, "MACH_TIMEBASE_INFO_TRAP")
def handle_mach_timebase_info_trap(emu: Chomper):
    info = emu.get_arg(0)

    emu.write_u32(info, 1)
    emu.write_u32(info + 4, 1)

    return 0


@register_syscall_handler(const.MK_TIMER_CREATE_TRAP, "MK_TIMER_CREATE_TRAP")
def handle_mk_timer_create_trap(emu: Chomper):
    return emu.ios_os.MACH_PORT_TIMER


@register_syscall_handler(const.MK_TIMER_ARM, "MK_TIMER_ARM")
def handle_mk_timer_arm(emu: Chomper):
    return 0
