from __future__ import annotations

import ctypes
import os
import random
import time
from functools import wraps
from typing import Dict, Optional, TYPE_CHECKING

import plistlib
from unicorn import arm64_const, UcError

from chomper.exceptions import SystemOperationFailed, ProgramTerminated
from chomper.os.base import SyscallError
from chomper.typing import SyscallHandleCallable
from chomper.utils import (
    to_signed,
    int_to_bytes,
    struct_to_bytes,
    float_to_bytes,
    read_struct,
)

from . import const
from .structs import (
    Rusage,
    MachMsgHeaderT,
    MachMsgBodyT,
    MachMsgPortDescriptorT,
    MachMsgOolDescriptorT,
    MachTimespec,
    VmRegionBasicInfo64,
)
from .sysctl import sysctl, sysctlbyname

if TYPE_CHECKING:
    from chomper.core import Chomper


SYSCALL_ERRORS = {
    SyscallError.EPERM: (const.EPERM, "EPERM"),
    SyscallError.ENOENT: (const.ENOENT, "ENOENT"),
    SyscallError.EBADF: (const.EBADF, "EBADF"),
    SyscallError.EACCES: (const.EACCES, "EACCES"),
    SyscallError.EEXIST: (const.EEXIST, "EEXIST"),
    SyscallError.ENOTDIR: (const.ENOTDIR, "ENOTDIR"),
    SyscallError.EXT1: (60, "EXT1"),
}

syscall_handlers: Dict[int, SyscallHandleCallable] = {}
syscall_names: Dict[int, str] = {}


def get_syscall_handlers() -> Dict[int, SyscallHandleCallable]:
    """Get the default system call handlers."""
    return syscall_handlers.copy()


def get_syscall_name(syscall_no: int) -> Optional[str]:
    """Get name of the system call."""
    return syscall_names.get(syscall_no)


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


def permission_denied():
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
    permission_denied()

    return 0


@register_syscall_handler(const.SYS_FCHFLAGS, "SYS_fchflags")
def handle_sys_fchflags(emu: Chomper):
    permission_denied()

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
    return 1


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


@register_syscall_handler(const.SYS_ADJTIME, "SYS_adjtime")
def handle_sys_adjtime(emu: Chomper):
    permission_denied()

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
    permission_denied()

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
        permission_denied()

    if flavor == 3:
        emu.write_string(buffer, emu.ios_os.program_path.split("/")[-1])
    elif flavor == 11:
        emu.write_string(buffer, emu.ios_os.program_path)

    return 0


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
    msg_ptr = emu.get_arg(0)
    msg = read_struct(emu, msg_ptr, MachMsgHeaderT)

    msg_id = msg.msgh_id
    remote_port = msg.msgh_remote_port

    option = emu.get_arg(1)

    emu.logger.info(
        "Received a mach msg: msg_id=%s, remote_port=%s, option=%s",
        msg_id,
        remote_port,
        hex(option),
    )

    if remote_port == emu.ios_os.MACH_PORT_HOST:
        if msg_id == 412:  # host_get_special_port
            # node = emu.read_s32(msg_ptr + 0x20)
            which_port = emu.read_s32(msg_ptr + 0x24)

            msg_header = MachMsgHeaderT(
                msgh_bits=const.MACH_MSGH_BITS_COMPLEX,
                msgh_size=40,
                msgh_remote_port=0,
                msgh_local_port=0,
                msgh_voucher_port=0,
                msgh_id=512,
            )

            msg_body = MachMsgBodyT(
                msgh_descriptor_count=1,
            )

            if which_port == const.HOST_PORT:
                port = emu.ios_os.MACH_PORT_HOST
            else:
                port = emu.ios_os.MACH_PORT_NULL

            port_descriptor = MachMsgPortDescriptorT(
                name=port,
                disposition=const.MACH_MSG_TYPE_MOVE_SEND,
                type=const.MACH_MSG_PORT_DESCRIPTOR,
            )

            emu.write_bytes(
                msg_ptr,
                struct_to_bytes(msg_header)
                + struct_to_bytes(msg_body)
                + struct_to_bytes(port_descriptor),
            )

            return const.KERN_SUCCESS
    elif remote_port == emu.ios_os.MACH_PORT_TASK:
        if msg_id == 3405:  # task_info
            flavor = emu.read_s32(msg_ptr + 0x20)
            task_info_out_cnt = emu.read_s32(msg_ptr + 0x24)

            emu.logger.info(f"flavor={flavor}, task_info_out_cnt={task_info_out_cnt}")

            if flavor == const.TASK_AUDIT_TOKEN:
                msg_header = MachMsgHeaderT(
                    msgh_bits=0,
                    msgh_size=72,
                    msgh_remote_port=0,
                    msgh_local_port=0,
                    msgh_voucher_port=0,
                    msgh_id=3505,
                )

                msg_body = MachMsgBodyT(
                    msgh_descriptor_count=0,
                )

                audit_token = [0, 0, 0, 0, 0, emu.ios_os.pid, 0, 1]

                emu.write_bytes(
                    msg_ptr,
                    struct_to_bytes(msg_header)
                    + struct_to_bytes(msg_body)
                    + int_to_bytes(0, 8)
                    + int_to_bytes(task_info_out_cnt, 4)
                    + b"".join([int_to_bytes(value, 4) for value in audit_token]),
                )

                return const.KERN_SUCCESS
        elif msg_id == 3409:  # task_get_special_port
            which_port = emu.read_s32(msg_ptr + 0x20)

            msg_header = MachMsgHeaderT(
                msgh_bits=const.MACH_MSGH_BITS_COMPLEX,
                msgh_size=40,
                msgh_remote_port=0,
                msgh_local_port=0,
                msgh_voucher_port=0,
                msgh_id=3509,
            )

            msg_body = MachMsgBodyT(
                msgh_descriptor_count=1,
            )

            if which_port == const.TASK_BOOTSTRAP_PORT:
                port = emu.ios_os.MACH_PORT_BOOTSTRAP
            else:
                port = emu.ios_os.MACH_PORT_NULL

            port_descriptor = MachMsgPortDescriptorT(
                name=port,
                disposition=const.MACH_MSG_TYPE_MOVE_SEND,
                type=const.MACH_MSG_PORT_DESCRIPTOR,
            )

            emu.write_bytes(
                msg_ptr,
                struct_to_bytes(msg_header)
                + struct_to_bytes(msg_body)
                + struct_to_bytes(port_descriptor),
            )

            return const.KERN_SUCCESS
        elif msg_id == 3418:  # semaphore_create
            # policy = emu.read_s32(msg_ptr + 0x20)
            value = emu.read_s32(msg_ptr + 0x24)

            semaphore = emu.ios_os.semaphore_create(value)

            msg_header = MachMsgHeaderT(
                msgh_bits=const.MACH_MSGH_BITS_COMPLEX,
                msgh_size=40,
                msgh_remote_port=0,
                msgh_local_port=0,
                msgh_voucher_port=0,
                msgh_id=3518,
            )

            msg_body = MachMsgBodyT(
                msgh_descriptor_count=1,
            )

            port_descriptor = MachMsgPortDescriptorT(
                name=semaphore,
                disposition=const.MACH_MSG_TYPE_MOVE_SEND,
                type=const.MACH_MSG_PORT_DESCRIPTOR,
            )

            emu.write_bytes(
                msg_ptr,
                struct_to_bytes(msg_header)
                + struct_to_bytes(msg_body)
                + struct_to_bytes(port_descriptor),
            )

            return const.KERN_SUCCESS
        elif msg_id == 4808:  # vm_read_overwrite
            address = emu.read_u64(msg_ptr + 0x20)
            size = emu.read_u32(msg_ptr + 0x28)
            data = emu.read_u64(msg_ptr + 0x30)

            emu.logger.info(f"address={hex(address)}, size={size}, data={hex(data)}")

            try:
                read_data = emu.read_bytes(address, size)
                out_size = len(read_data)
                emu.write_bytes(data, read_data)
            except UcError:
                emu.logger.warning("vm_read_overwrite failed: invalid address")
                return const.KERN_INVALID_ADDRESS

            msg_header = MachMsgHeaderT(
                msgh_bits=0,
                msgh_size=44,
                msgh_remote_port=0,
                msgh_local_port=0,
                msgh_voucher_port=0,
                msgh_id=4908,
            )

            msg_body = MachMsgBodyT(
                msgh_descriptor_count=0,
            )

            emu.write_bytes(
                msg_ptr,
                struct_to_bytes(msg_header)
                + struct_to_bytes(msg_body)
                + int_to_bytes(0, 8)
                + int_to_bytes(out_size, 8),
            )

            return const.KERN_SUCCESS
        elif msg_id == 4813:  # _kernelrpc_vm_remap
            target_address = emu.read_u64(msg_ptr + 0x30)
            size = emu.read_u32(msg_ptr + 0x38)
            mask = emu.read_u64(msg_ptr + 0x40)
            flags = emu.read_u32(msg_ptr + 0x48)
            src_address = emu.read_u64(msg_ptr + 0x4C)
            copy = emu.read_u32(msg_ptr + 0x54)

            emu.logger.info(
                f"target_address={hex(target_address)}, size={size}, mask={mask}, "
                f"flags={hex(flags)}, src_address={hex(src_address)}, copy={copy}"
            )

            if not target_address:
                target_address = emu.create_buffer(size)

            read_data = emu.read_bytes(src_address, size)
            emu.write_bytes(target_address, read_data)

            msg_header = MachMsgHeaderT(
                msgh_bits=0,
                msgh_size=52,
                msgh_remote_port=0,
                msgh_local_port=0,
                msgh_voucher_port=0,
                msgh_id=4913,
            )

            msg_body = MachMsgBodyT(
                msgh_descriptor_count=0,
            )

            emu.write_bytes(
                msg_ptr,
                struct_to_bytes(msg_header)
                + struct_to_bytes(msg_body)
                + int_to_bytes(0, 8)
                + int_to_bytes(target_address, 8)
                + int_to_bytes(0, 4)
                + int_to_bytes(0, 4),
            )

            return const.KERN_SUCCESS
        elif msg_id == 4816:  # vm_region_64
            address = emu.read_u64(msg_ptr + 0x20)
            flavor = emu.read_s32(msg_ptr + 0x28)
            count = emu.read_u32(msg_ptr + 0x2C)

            emu.logger.info(f"address={hex(address)}, flavor={flavor}, count={count}")

            if flavor == const.VM_REGION_BASIC_INFO_64:
                for start, end, prop in emu.uc.mem_regions():
                    if start <= address < end:
                        out_address = start
                        size = end - start
                        break
                else:
                    emu.logger.warning("vm_region_64 failed: invalid address")
                    return const.KERN_INVALID_ADDRESS

                out_count = ctypes.sizeof(VmRegionBasicInfo64) // 4
                object_name = 0

                info = VmRegionBasicInfo64(
                    protection=const.VM_PROT_DEFAULT,
                    max_protection=const.VM_PROT_DEFAULT,
                    inheritance=0,
                    shared=0,
                    reserved=0,
                    offset=0,
                    behavior=0,
                    user_wired_count=0,
                )

                msg_header = MachMsgHeaderT(
                    msgh_bits=const.MACH_MSGH_BITS_COMPLEX,
                    msgh_size=(68 + out_count * 4),
                    msgh_remote_port=0,
                    msgh_local_port=0,
                    msgh_voucher_port=0,
                    msgh_id=4916,
                )

                msg_body = MachMsgBodyT(
                    msgh_descriptor_count=1,
                )

                port_descriptor = MachMsgPortDescriptorT(
                    name=object_name,
                    disposition=const.MACH_MSG_TYPE_MOVE_SEND,
                    type=const.MACH_MSG_PORT_DESCRIPTOR,
                )

                emu.write_bytes(
                    msg_ptr,
                    struct_to_bytes(msg_header)
                    + struct_to_bytes(msg_body)
                    + struct_to_bytes(port_descriptor)
                    + int_to_bytes(0, 8)
                    + int_to_bytes(out_address, 8)
                    + int_to_bytes(size, 8)
                    + int_to_bytes(out_count, 4)
                    + struct_to_bytes(info),
                )

                return const.KERN_SUCCESS
        elif msg_id == 8000:  # task_restartable_ranges_register
            return const.KERN_RESOURCE_SHORTAGE
    elif remote_port == emu.ios_os.MACH_PORT_BOOTSTRAP:
        if msg_id == 1073741824:  # _xpc_pipe_mach_msg
            msg_header = MachMsgHeaderT(
                msgh_bits=0,
                msgh_size=0,
                msgh_remote_port=0,
                msgh_local_port=0,
                msgh_voucher_port=0,
                msgh_id=0x20000000,
            )

            msg_body = MachMsgBodyT(
                msgh_descriptor_count=0,
            )

            emu.write_bytes(
                msg_ptr, struct_to_bytes(msg_header) + struct_to_bytes(msg_body)
            )

            return const.KERN_SUCCESS
    elif remote_port == emu.ios_os.MACH_PORT_CLOCK:
        if msg_id == 1000:  # clock_get_time
            msg_header = MachMsgHeaderT(
                msgh_bits=0,
                msgh_size=44,
                msgh_remote_port=0,
                msgh_local_port=0,
                msgh_voucher_port=0,
                msgh_id=1100,
            )

            msg_body = MachMsgBodyT(
                msgh_descriptor_count=1,
            )

            time_ns = time.time_ns()
            cur_time = MachTimespec.from_time_ns(time_ns)

            emu.write_bytes(
                msg_ptr,
                struct_to_bytes(msg_header)
                + struct_to_bytes(msg_body)
                + int_to_bytes(0, 8)
                + struct_to_bytes(cur_time),
            )

            return const.KERN_SUCCESS
    elif remote_port == emu.ios_os.MACH_PORT_NOTIFICATION_CENTER:
        return const.KERN_SUCCESS
    elif remote_port == emu.ios_os.MACH_PORT_CA_RENDER_SERVER:
        if msg_id == 40231:  # _CASGetDisplays
            displays_prop = [
                {
                    "kCADisplayId": 1,
                    "kCADisplayName": "LCD",
                    "kCADisplayDeviceName": "primary",
                }
            ]
            displays_data = plistlib.dumps(displays_prop, fmt=plistlib.FMT_BINARY)

            displays_buf = emu.create_buffer(len(displays_data))
            emu.write_bytes(displays_buf, displays_data)

            msg_header = MachMsgHeaderT(
                msgh_bits=const.MACH_MSGH_BITS_COMPLEX,
                msgh_size=56,
                msgh_remote_port=0,
                msgh_local_port=0,
                msgh_voucher_port=0,
                msgh_id=40331,
            )

            msg_body = MachMsgBodyT(
                msgh_descriptor_count=1,
            )

            ool_descriptor = MachMsgOolDescriptorT(
                address=displays_buf,
                deallocate=0,
                copy=0,
                disposition=0,
                type=const.MACH_MSG_OOL_DESCRIPTOR,
                size=len(displays_data),
            )

            emu.write_bytes(
                msg_ptr,
                struct_to_bytes(msg_header)
                + struct_to_bytes(msg_body)
                + struct_to_bytes(ool_descriptor)
                + int_to_bytes(0, 8)
                + int_to_bytes(len(displays_data), 4),
            )

            return const.KERN_SUCCESS
    elif remote_port == emu.ios_os.MACH_PORT_BKS_HID_SERVER:
        if msg_id == 6000050:  # _BKSHIDGetCurrentDisplayBrightness
            msg_header = MachMsgHeaderT(
                msgh_bits=0,
                msgh_size=40,
                msgh_remote_port=0,
                msgh_local_port=0,
                msgh_voucher_port=0,
                msgh_id=6000150,
            )

            msg_body = MachMsgBodyT(
                msgh_descriptor_count=1,
            )

            brightness = 0.4

            emu.write_bytes(
                msg_ptr,
                struct_to_bytes(msg_header)
                + struct_to_bytes(msg_body)
                + int_to_bytes(0, 8)
                + float_to_bytes(brightness),
            )

            return const.KERN_SUCCESS

    # xpc message to com.apple.commcenter.cupolicy.xpc
    if msg_id == 268435456:
        return const.KERN_SUCCESS

    emu.logger.warning("Unhandled mach msg, returning KERN_RESOURCE_SHORTAGE")
    return const.KERN_RESOURCE_SHORTAGE


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
