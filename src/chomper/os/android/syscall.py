from __future__ import annotations

import os
from typing import Callable

from chomper.exceptions import SystemOperationFailed, ProgramTerminated
from chomper.os.posix import SyscallError
from chomper.os.syscall import BaseSyscallHandler
from chomper.utils import to_signed

from . import const


SYSCALL_ERRORS = {
    SyscallError.EPERM: (const.EPERM, "EPERM"),
    SyscallError.ENOENT: (const.ENOENT, "ENOENT"),
    SyscallError.EBADF: (const.EBADF, "EBADF"),
    SyscallError.EACCES: (const.EACCES, "EACCES"),
    SyscallError.EFAULT: (const.EFAULT, "EFAULT"),
    SyscallError.EEXIST: (const.EEXIST, "EEXIST"),
    SyscallError.ENOTDIR: (const.ENOTDIR, "ENOTDIR"),
    SyscallError.EINVAL: (const.EINVAL, "EINVAL"),
    SyscallError.EMFILE: (const.EMFILE, "EMFILE"),
}


class AndroidSyscallHandler(BaseSyscallHandler):
    """Handle Android system calls."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        names = {
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
            const.NR_PRCTL: "NR_prctl",
            const.NR_GETTIMEOFDAY: "NR_gettimeofday",
            const.NR_GETPID: "NR_getpid",
            const.NR_GETPPID: "NR_getppid",
            const.NR_GETUID: "NR_getuid",
            const.NR_GETEUID: "NR_geteuid",
            const.NR_GETEGID: "NR_getegid",
            const.NR_MUNMAP: "NR_munmap",
            const.NR_MMAP: "NR_mmap",
            const.NR_CLOCK_ADJTIME: "NR_clock_adjtime",
        }

        handlers = {
            const.NR_GETCWD: self._handle_nr_getcwd,
            const.NR_FCNTL: self._handle_nr_fcntl,
            const.NR_IOCTL: self._handle_nr_ioctl,
            const.NR_MKDIRAT: self._handle_nr_mkdirat,
            const.NR_UNLINKAT: self._handle_nr_unlinkat,
            const.NR_SYMLINKAT: self._handle_nr_symlinkat,
            const.NR_LINKAT: self._handle_nr_linkat,
            const.NR_RENAMEAT: self._handle_nr_renameat,
            const.NR_FACCESSAT: self._handle_nr_faccessat,
            const.NR_CHDIR: self._handle_nr_chdir,
            const.NR_FCHDIR: self._handle_nr_fchdir,
            const.NR_FCHMOD: self._handle_nr_fchmod,
            const.NR_FCHMODAT: self._handle_nr_fchmodat,
            const.NR_FCHOWNAT: self._handle_nr_fchownat,
            const.NR_FCHOWN: self._handle_nr_fchown,
            const.NR_OPENAT: self._handle_nr_openat,
            const.NR_CLOSE: self._handle_nr_close,
            const.NR_GETDENTS64: self._handle_nr_getdents64,
            const.NR_LSEEK: self._handle_nr_lseek,
            const.NR_READ: self._handle_nr_read,
            const.NR_WRITE: self._handle_nr_write,
            const.NR_READV: self._handle_nr_readv,
            const.NR_WRITEV: self._handle_nr_writev,
            const.NR_PREAD64: self._handle_nr_pread64,
            const.NR_PREADV64: self._handle_nr_preadv64,
            const.NR_READLINKAT: self._handle_nr_readlinkat,
            const.NR_FSTATAT: self._handle_nr_fstatat,
            const.NR_FSTAT: self._handle_nr_fstat,
            const.NR_FSYNC: self._handle_nr_fsync,
            const.NR_EXIT_GROUP: self._handle_nr_exit_group,
            const.NR_NANOSLEEP: self._handle_nr_nanosleep,
            const.NR_CLOCK_SETTIME: self._handle_nr_clock_settime,
            const.NR_CLOCK_GETTIME: self._handle_nr_clock_gettime,
            const.NR_CLOCK_GETRES: self._handle_nr_clock_getres,
            const.NR_CLOCK_NANOSLEEP: self._handle_nr_clock_nanosleep,
            const.NR_SETRESGID: self._handle_nr_setresgid,
            const.NR_GETPGID: self._handle_nr_getpgid,
            const.NR_PRCTL: self._handle_nr_prctl,
            const.NR_GETTIMEOFDAY: self._handle_nr_gettimeofday,
            const.NR_GETPID: self._handle_nr_getpid,
            const.NR_GETPPID: self._handle_nr_getppid,
            const.NR_GETUID: self._handle_nr_getuid,
            const.NR_GETEUID: self._handle_nr_geteuid,
            const.NR_GETEGID: self._handle_nr_getegid,
            const.NR_MUNMAP: self._handle_nr_munmap,
            const.NR_MMAP: self._handle_nr_mmap,
            const.NR_CLOCK_ADJTIME: self._handle_nr_clock_adjtime,
        }

        self._names.update(names)
        self._handlers.update(handlers)

    def _syscall_wrapper(self, handler: Callable):
        retval = -1
        error_type = None

        try:
            retval = handler()
        except (FileNotFoundError, PermissionError):
            error_type = SyscallError.ENOENT
        except FileExistsError:
            error_type = SyscallError.EEXIST
        except UnicodeDecodeError:
            error_type = SyscallError.EPERM
        except OSError:
            error_type = SyscallError.EINVAL
        except SystemOperationFailed as e:
            error_type = e.error_type

        if error_type in SYSCALL_ERRORS:
            error_no, error_name = SYSCALL_ERRORS[error_type]

            self.emu.logger.info(f"Set errno {error_name}({error_no})")
            self.emu.os.set_errno(error_no)

        return retval

    def _handle_nr_getcwd(self):
        buf = self.emu.get_arg(0)

        self.emu.write_string(buf, self.emu.os.getcwd())

        return 0

    def _handle_nr_fcntl(self):
        fd = self.emu.get_arg(0)
        cmd = self.emu.get_arg(1)
        arg = self.emu.get_arg(2)

        return self.emu.os.fcntl(fd, cmd, arg)

    def _handle_nr_ioctl(self):
        fd = self.emu.get_arg(0)
        req = self.emu.get_arg(1)

        inout = req & ~((0x3FFF << 16) | 0xFF00 | 0xFF)
        group = (req >> 8) & 0xFF
        num = req & 0xFF
        length = (req >> 16) & 0x3FFF

        self.emu.logger.info(
            f"Received an ioctl request: fd={fd}, inout={hex(inout)}, "
            f"group='{chr(group)}', num={num}, length={length}"
        )

        self.emu.logger.warning("ioctl request not processed")
        return 0

    def _handle_nr_mkdirat(self):
        dir_fd = to_signed(self.emu.get_arg(0), 4)
        path = self.emu.read_string(self.emu.get_arg(1))
        mode = self.emu.get_arg(2)

        self.emu.os.mkdirat(dir_fd, path, mode)

        return 0

    def _handle_nr_unlinkat(self):
        dir_fd = to_signed(self.emu.get_arg(0), 4)
        path = self.emu.read_string(self.emu.get_arg(1))

        self.emu.os.unlinkat(dir_fd, path)

        return 0

    def _handle_nr_symlinkat(self):
        src_dir_fd = to_signed(self.emu.get_arg(0), 4)
        src_path = self.emu.read_string(self.emu.get_arg(1))
        dst_dir_fd = to_signed(self.emu.get_arg(2), 4)
        dst_path = self.emu.read_string(self.emu.get_arg(3))

        self.emu.os.symlinkat(src_dir_fd, src_path, dst_dir_fd, dst_path)

        return 0

    def _handle_nr_linkat(self):
        src_dir_fd = to_signed(self.emu.get_arg(0), 4)
        src_path = self.emu.read_string(self.emu.get_arg(1))
        dst_dir_fd = to_signed(self.emu.get_arg(2), 4)
        dst_path = self.emu.read_string(self.emu.get_arg(3))

        self.emu.os.linkat(src_dir_fd, src_path, dst_dir_fd, dst_path)

        return 0

    def _handle_nr_renameat(self):
        src_fd = self.emu.get_arg(0)
        old = self.emu.read_string(self.emu.get_arg(1))
        dst_fd = self.emu.get_arg(2)
        new = self.emu.read_string(self.emu.get_arg(3))

        self.emu.os.renameat(src_fd, old, dst_fd, new)

        return 0

    def _handle_nr_faccessat(self):
        dir_fd = to_signed(self.emu.get_arg(0), 4)
        path = self.emu.read_string(self.emu.get_arg(1))
        mode = self.emu.get_arg(2)

        if not self.emu.os.faccessat(dir_fd, path, mode):
            return -1

        return 0

    def _handle_nr_chdir(self):
        path = self.emu.read_string(self.emu.get_arg(0))

        self.emu.os.chdir(path)

        return 0

    def _handle_nr_fchdir(self):
        fd = self.emu.get_arg(0)

        self.emu.os.fchdir(fd)

        return 0

    def _handle_nr_fchmod(self):
        fd = self.emu.get_arg(0)
        mode = self.emu.get_arg(1)

        self.emu.os.fchmod(fd, mode)

        return 0

    def _handle_nr_fchmodat(self):
        dir_fd = to_signed(self.emu.get_arg(0), 4)
        path = self.emu.read_string(self.emu.get_arg(1))
        mode = self.emu.get_arg(2)

        self.emu.os.fchmodat(dir_fd, path, mode)

        return 0

    def _handle_nr_fchownat(self):
        dir_fd = to_signed(self.emu.get_arg(0), 4)
        path = self.emu.read_string(self.emu.get_arg(1))
        uid = self.emu.get_arg(2)
        gid = self.emu.get_arg(3)

        self.emu.os.fchownat(dir_fd, path, uid, gid)

        return 0

    def _handle_nr_fchown(self):
        fd = self.emu.get_arg(0)
        uid = self.emu.get_arg(1)
        gid = self.emu.get_arg(2)

        self.emu.os.fchown(fd, uid, gid)

        return 0

    def _handle_nr_openat(self):
        dir_fd = to_signed(self.emu.get_arg(0), 4)
        path = self.emu.read_string(self.emu.get_arg(1))
        flags = self.emu.get_arg(2)
        mode = self.emu.get_arg(3)

        return self.emu.os.openat(dir_fd, path, flags, mode)

    def _handle_nr_close(self):
        fd = self.emu.get_arg(0)

        self.emu.os.close(fd)

        return 0

    def _handle_nr_getdents64(self):
        fd = self.emu.get_arg(0)
        buf = self.emu.get_arg(1)
        buf_size = self.emu.get_arg(2)

        result = self.emu.android_os.getdents(fd)
        if result is None:
            return 0

        if buf_size < len(result):
            return 0

        self.emu.write_bytes(buf, result[:buf_size])

        return len(result)

    def _handle_nr_lseek(self):
        fd = self.emu.get_arg(0)
        offset = self.emu.get_arg(1)
        whence = self.emu.get_arg(2)

        offset = to_signed(offset, 8)

        return self.emu.os.lseek(fd, offset, whence)

    def _handle_nr_read(self):
        fd = self.emu.get_arg(0)
        buf = self.emu.get_arg(1)
        size = self.emu.get_arg(2)

        data = self.emu.os.read(fd, size)
        self.emu.write_bytes(buf, data)

        return len(data)

    def _handle_nr_write(self):
        fd = self.emu.get_arg(0)
        buf = self.emu.get_arg(1)
        size = self.emu.get_arg(2)

        return self.emu.os.write(fd, buf, size)

    def _handle_nr_readv(self):
        fd = self.emu.get_arg(0)
        iov = self.emu.get_arg(1)
        iovcnt = self.emu.get_arg(2)

        result = 0

        for _ in range(iovcnt):
            iov_base = self.emu.read_pointer(iov)
            iov_len = self.emu.read_u64(iov + 8)

            data = self.emu.os.read(fd, iov_len)
            self.emu.write_bytes(iov_base, data)

            result += len(data)

            if len(data) != iov_len:
                break

            iov += 16

        return result

    def _handle_nr_writev(self):
        fd = self.emu.get_arg(0)
        iov = self.emu.get_arg(1)
        iovcnt = self.emu.get_arg(2)

        result = 0

        for _ in range(iovcnt):
            iov_base = self.emu.read_pointer(iov)
            iov_len = self.emu.read_u64(iov + 8)

            write_len = self.emu.os.write(fd, iov_base, iov_len)
            result += write_len

            if write_len != iov_len:
                break

            iov += 16

        return result

    def _handle_nr_pread64(self):
        fd = self.emu.get_arg(0)
        buf = self.emu.get_arg(1)
        size = self.emu.get_arg(2)
        offset = self.emu.get_arg(3)

        data = self.emu.os.pread(fd, size, offset)
        self.emu.write_bytes(buf, data)

        return len(data)

    def _handle_nr_preadv64(self):
        fd = self.emu.get_arg(0)
        iov = self.emu.get_arg(1)
        iovcnt = self.emu.get_arg(2)
        offset = self.emu.get_arg(3)

        pos = self.emu.os.lseek(fd, 0, os.SEEK_CUR)
        self.emu.os.lseek(fd, offset, os.SEEK_SET)

        result = 0

        for _ in range(iovcnt):
            iov_base = self.emu.read_pointer(iov)
            iov_len = self.emu.read_u64(iov + 8)

            data = self.emu.os.read(fd, iov_len)
            self.emu.write_bytes(iov_base, data)

            result += len(data)

            if len(data) != iov_len:
                break

            iov += 16

        self.emu.os.lseek(fd, pos, os.SEEK_SET)

        return result

    def _handle_nr_readlinkat(self):
        dir_fd = to_signed(self.emu.get_arg(0), 4)
        path = self.emu.read_string(self.emu.get_arg(1))

        self.emu.os.readlinkat(dir_fd, path)

        return 0

    def _handle_nr_fstatat(self):
        dir_fd = to_signed(self.emu.get_arg(0), 4)
        path = self.emu.read_string(self.emu.get_arg(1))
        stat = self.emu.get_arg(2)

        self.emu.write_bytes(stat, self.emu.os.fstatat(dir_fd, path))

        return 0

    def _handle_nr_fstat(self):
        fd = self.emu.get_arg(0)
        stat = self.emu.get_arg(1)

        self.emu.write_bytes(stat, self.emu.os.fstat(fd))

        return 0

    def _handle_nr_fsync(self):
        fd = self.emu.get_arg(0)

        self.emu.os.fsync(fd)

        return 0

    def _handle_nr_exit_group(self):
        status = self.emu.get_arg(0)

        raise ProgramTerminated("Program terminated with status: %s" % status)

    @staticmethod
    def _handle_nr_nanosleep():
        return 0

    @staticmethod
    def _handle_nr_clock_settime():
        return 0

    def _handle_nr_clock_gettime(self):
        timespec = self.emu.get_arg(1)

        result = self.emu.android_os.clock_gettime()
        self.emu.write_bytes(timespec, result)

        return 0

    def _handle_nr_clock_getres(self):
        timespec = self.emu.get_arg(1)

        result = self.emu.android_os.clock_getres()
        self.emu.write_bytes(timespec, result)

        return 0

    @staticmethod
    def _handle_nr_clock_nanosleep():
        return 0

    def _handle_nr_setresgid(self):
        self.emu.os.raise_permission_denied()

        return 0

    def _handle_nr_getpgid(self):
        pid = self.emu.get_arg(0)

        if pid != 0:
            self.emu.os.raise_permission_denied()

        return 1

    @staticmethod
    def _handle_nr_prctl():
        return 0

    def _handle_nr_gettimeofday(self):
        tv = self.emu.get_arg(0)

        result = self.emu.os.gettimeofday()
        self.emu.write_bytes(tv, result)

        return 0

    def _handle_nr_getpid(self):
        return self.emu.os.getpid()

    @staticmethod
    def _handle_nr_getppid():
        return 1

    def _handle_nr_getuid(self):
        return self.emu.os.getuid()

    def _handle_nr_geteuid(self):
        return self.emu.os.getuid()

    @staticmethod
    def _handle_nr_getegid():
        return 1

    def _handle_nr_munmap(self):
        addr = self.emu.get_arg(0)

        self.emu.os.munmap(addr)

        return 0

    def _handle_nr_mmap(self):
        length = self.emu.get_arg(1)
        fd = to_signed(self.emu.get_arg(4), 4)
        offset = self.emu.get_arg(5)

        return self.emu.os.mmap(length, fd, offset)

    @staticmethod
    def _handle_nr_clock_adjtime():
        return 0
