from __future__ import annotations

import os
import posixpath
import random
import sys
import shutil
import time
from abc import ABC
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Type, TYPE_CHECKING

from chomper.exceptions import SystemOperationFailed
from chomper.log import get_logger
from chomper.utils import log_call, safe_join, to_signed

from .device import DeviceFile, NullDevice, RandomDevice, UrandomDevice

if TYPE_CHECKING:
    from chomper.core import Chomper


class SyscallError(Enum):
    EPERM = 1
    ENOENT = 2
    EBADF = 3
    EACCES = 4
    EEXIST = 5
    ENOTDIR = 6


class BaseOs(ABC):
    """Base operating system class.

    Args:
        emu: The emulator instance.
        rootfs_path: As the root directory of the mapping file system.
    """

    DIR_FD_START = 10000
    MAX_OPEN_DIR_NUM = 10000

    DEV_FD_START = 20000
    MAX_OPEN_DEV_NUM = 10000

    AT_FDCWD: Optional[int] = None

    def __init__(self, emu: Chomper, rootfs_path: Optional[str] = None):
        self.emu = emu
        self.logger = get_logger(__name__)

        self.rootfs_path = rootfs_path

        self._working_dir = "/"

        self._path_map: Dict[str, str] = {}

        self._symbolic_links: Dict[str, str] = {}

        # Virtual directory file descriptors
        self._dir_fds: Dict[int, str] = {}

        # Record the relationship between fd and file path,
        # used by fcntl with command F_GETPATH.
        self._fd_path_map: Dict[int, str] = {}

        if sys.stdin.isatty():
            self.stdin = sys.stdin.fileno()
        else:
            self.stdin = None

        self.stdout = sys.stdout.fileno()
        self.stderr = sys.stderr.fileno()

        self.pid = random.randint(10000, 20000)
        self.uid = random.randint(10000, 20000)

        self._devices: Dict[str, Type[DeviceFile]] = {}

        # Virtual device file descriptors
        self._dev_fds: Dict[int, str] = {}

        self._dev_map: Dict[int, DeviceFile] = {}

    def get_working_dir(self) -> str:
        """Get current working directory."""
        return self._working_dir

    def set_working_dir(self, path: str):
        """Set current working directory.

        Raises:
            ValueError: If working directory is not valid.
        """
        if not path.startswith("/"):
            raise SystemOperationFailed(
                "Working directory must be an absolute path", SyscallError.ENOTDIR
            )

        self._working_dir = path

    def _resolve_link(self, path: str, src_list: Optional[List[str]] = None) -> str:
        if src_list is None:
            src_list = sorted(
                self._symbolic_links.keys(),
                key=lambda t: len(t),
                reverse=True,
            )
        for src in src_list:
            dst = self._symbolic_links[src]
            if path.startswith(src):
                path = path.replace(src, dst.rstrip("/"), 1)
                path = self._resolve_link(
                    path,
                    src_list=[t for t in src_list if t != src],
                )
                break
        return path

    def _get_absolute_path(self, path: str) -> str:
        """Convert a path to absolute path."""
        if path == ".":
            path = self._working_dir
        elif path == "..":
            path = Path(self._working_dir).parent.as_posix()

        path = self._resolve_link(path)

        if not path.startswith("/"):
            relative_path = os.path.join(self._working_dir, path)
        else:
            relative_path = path

        return relative_path

    def _get_real_path(self, path: str) -> str:
        """Mapping a path used by emulated programs to a real path.

        Raises:
            RuntimeError: If `rootfs_path` not set
            ValueError: If unsafe path pass in.
        """
        if not self.rootfs_path:
            raise RuntimeError("Root directory not set")

        absolute_path = self._get_absolute_path(path)

        forwarding_path = self._path_map.get(absolute_path)
        if forwarding_path:
            self.logger.info(f"Forward path '{path}' -> '{forwarding_path}'")
            return forwarding_path

        full_path = safe_join(self.rootfs_path, absolute_path[1:])
        if full_path is None:
            raise ValueError(f"Unsafe path: {path}")

        self.logger.info(f"Map path '{path}' -> '{full_path}'")
        return full_path

    def forward_path(self, src_path: str, dst_path: str):
        """Forward all access to `src_path` to `dst_path`."""
        self._path_map[src_path] = dst_path

    def set_symbolic_link(self, src_path: str, dst_path: str):
        """Set a symbolic link to specified path."""
        self._symbolic_links[src_path] = dst_path

    def _gen_dir_fd(self, path: str) -> int:
        """Generate a virtual directory file descriptor.

        On Windows, unable to obtain a file descriptor for a directory.
        """
        for index in range(1, self.MAX_OPEN_DIR_NUM + 1):
            dir_fd = self.DIR_FD_START + index
            if dir_fd not in self._dir_fds:
                self._dir_fds[dir_fd] = self._get_absolute_path(path)
                return dir_fd
        return 0

    def get_dir_path(self, fd: int) -> Optional[str]:
        if fd not in self._dir_fds:
            return None

        return self._dir_fds[fd]

    @staticmethod
    def _construct_stat64(st: os.stat_result) -> bytes:
        """Construct stat64 struct based on `stat_result`."""
        return NotImplemented

    @staticmethod
    def _construct_dev_stat64() -> bytes:
        """Construct stat64 struct for device file."""
        return NotImplemented

    @staticmethod
    def _construct_statfs64() -> bytes:
        """Construct statfs64 struct."""
        return NotImplemented

    def _check_fd(self, fd: int):
        """Check file descriptor.

        Raises:
            BadFileDescriptor: If bad file descriptor.
        """
        if fd in (self.stdin, self.stdout, self.stderr):
            return

        if fd not in self._fd_path_map:
            raise SystemOperationFailed(
                f"Bad file descriptor: {fd}", SyscallError.EBADF
            )

    @staticmethod
    def _prepare_flags(flags: int) -> int:
        """Create flags that will be actually passed into functions of the os module.

        On Windows, the meaning of flags is different with Unix-like operating systems.
        """
        _flags = 0

        access_mode = flags & 3
        if access_mode == 0:
            _flags |= os.O_RDONLY
        elif access_mode == 1:
            _flags |= os.O_WRONLY
        elif access_mode == 2:
            _flags |= os.O_RDWR

        if flags & 0x8:
            _flags |= os.O_APPEND
        if flags & 0x200:
            _flags |= os.O_CREAT
        if flags & 0x400:
            _flags |= os.O_TRUNC
        if flags & 0x800:
            _flags |= os.O_EXCL

        if sys.platform == "win32":
            _flags |= os.O_BINARY

        return _flags

    def _resolve_dir_fd(self, dir_fd: int, path: str) -> str:
        """Returns the full path constructed by combining with `dir_fd`."""
        if path.startswith("/"):
            return path
        elif self.AT_FDCWD is not None and dir_fd == to_signed(self.AT_FDCWD, size=4):
            return posixpath.join(self._working_dir, path)
        elif dir_fd in self._dir_fds:
            return posixpath.join(self._dir_fds[dir_fd], path)
        raise SystemOperationFailed(
            f"Bad file descriptor: {dir_fd}", SyscallError.EBADF
        )

    def _gen_dev_fd(self, path: str) -> int:
        """Generate a virtual device file descriptor."""
        for index in range(1, self.MAX_OPEN_DEV_NUM + 1):
            dev_fd = self.DEV_FD_START + index
            if dev_fd not in self._dev_fds:
                self._dev_fds[dev_fd] = self._get_absolute_path(path)
                return dev_fd
        return 0

    def mount_device(self, path: str, dev_cls: Type[DeviceFile]):
        """Mount device file to virtual file system."""
        self._devices[path] = dev_cls

    def unmount_device(self, path: str):
        """Unmount device file."""
        del self._devices[path]

    @property
    def errno(self) -> int:
        """Get the value of `errno`."""
        return 0

    @errno.setter
    def errno(self, value: int):
        """Set the value of `errno`."""
        pass

    def _open(self, path: str, flags: int, mode: int) -> int:
        real_path = self._get_real_path(path)
        flags = self._prepare_flags(flags)

        if os.path.isdir(real_path):
            return self._gen_dir_fd(path)

        if path in self._devices:
            fd = self._gen_dev_fd(path)
            self._dev_map[fd] = self._devices[path]()
            self._fd_path_map[fd] = self._get_absolute_path(path)
            return fd

        fd = os.open(real_path, flags, mode)
        self._fd_path_map[fd] = self._get_absolute_path(path)
        return fd

    def _link(self, src_path: str, dst_path: str):
        self.set_symbolic_link(src_path, dst_path)

    def _symlink(self, src_path: str, dst_path: str):
        self.set_symbolic_link(src_path, dst_path)

    @staticmethod
    def _unlink(path: str):
        exist = os.path.exists(path)
        if not exist:
            raise SystemOperationFailed(f"No such file: {path}", SyscallError.ENOENT)
        raise SystemOperationFailed(
            f"Banned file deletion: {path}", SyscallError.EACCES
        )

    def _readlink(self, path: str) -> Optional[str]:
        return self._symbolic_links.get(path)

    def _access(self, path: str, mode: int) -> bool:
        real_path = self._get_real_path(path)
        return os.access(real_path, mode)

    def _stat(self, path: str) -> bytes:
        real_path = self._get_real_path(path)
        return self._construct_stat64(os.stat(real_path))

    def _rename(self, old: str, new: str):
        old = self._get_real_path(old)
        new = self._get_real_path(new)

        try:
            os.rename(old, new)
        except PermissionError:
            shutil.copy(old, new)

    def _mkdir(self, path: str, mode: int):
        real_path = self._get_real_path(path)
        os.mkdir(real_path, mode)

    def _chmod(self, path: str, mode: int):
        pass

    def _chdir(self, path: str):
        self.set_working_dir(path)

    def _chown(self, path: str, uid: int, gid: int):
        pass

    @log_call
    def read(self, fd: int, size: int) -> bytes:
        self._check_fd(fd)

        if fd in self._dev_fds:
            device = self._dev_map[fd]
            if not device.readable():
                raise SystemOperationFailed("Not support read", SyscallError.EBADF)
            result = device.read(size)
            if result is None:
                return b""
            return result

        return os.read(fd, size)

    @log_call
    def write(self, fd: int, buf: int, size: int) -> int:
        self._check_fd(fd)

        data = self.emu.read_bytes(buf, size)

        if fd in self._dev_fds:
            device = self._dev_map[fd]
            if not device.writable():
                raise SystemOperationFailed("Not support write", SyscallError.EBADF)
            result = device.write(data)
            if result is None:
                return 0
            return result

        return os.write(fd, data)

    @log_call
    def open(self, path: str, flags: int, mode: int) -> int:
        return self._open(path, flags, mode)

    @log_call
    def openat(self, dir_fd: int, path: str, flags: int, mode: int) -> int:
        path = self._resolve_dir_fd(dir_fd, path)
        return self._open(path, flags, mode)

    @log_call
    def close(self, fd: int) -> int:
        if fd in self._dir_fds:
            del self._dir_fds[fd]
            return 0
        elif fd in self._dev_fds:
            del self._dev_fds[fd]
            del self._dev_map[fd]
            del self._fd_path_map[fd]
            return 0

        self._check_fd(fd)

        del self._fd_path_map[fd]
        os.close(fd)
        return 0

    @log_call
    def link(self, src_path: str, dst_path: str):
        if not src_path.startswith("/"):
            src_path = posixpath.join(self._working_dir, src_path)
        if not dst_path.startswith("/"):
            dst_path = posixpath.join(self._working_dir, dst_path)

        self._link(src_path, dst_path)

    @log_call
    def linkat(self, src_dir_fd: int, src_path: str, dst_dir_fd: int, dst_path: str):
        src_path = self._resolve_dir_fd(src_dir_fd, src_path)
        dst_path = self._resolve_dir_fd(dst_dir_fd, dst_path)

        self._link(src_path, dst_path)

    @log_call
    def symlink(self, src_path: str, dst_path: str):
        if not src_path.startswith("/"):
            src_path = posixpath.join(self._working_dir, src_path)
        if not dst_path.startswith("/"):
            dst_path = posixpath.join(self._working_dir, dst_path)

        self._symlink(src_path, dst_path)

    @log_call
    def symlinkat(self, src_dir_fd: int, src_path: str, dst_dir_fd: int, dst_path: str):
        src_path = self._resolve_dir_fd(src_dir_fd, src_path)
        dst_path = self._resolve_dir_fd(dst_dir_fd, dst_path)

        self._symlink(src_path, dst_path)

    @log_call
    def unlink(self, path: str):
        self._unlink(path)

    @log_call
    def unlinkat(self, dir_fd: int, path: str):
        path = self._resolve_dir_fd(dir_fd, path)
        return self._unlink(path)

    @log_call
    def access(self, path: str, mode: int) -> bool:
        return self._access(path, mode)

    @log_call
    def faccessat(self, dir_fd: int, path: str, mode: int) -> bool:
        path = self._resolve_dir_fd(dir_fd, path)
        return self._access(path, mode)

    @log_call
    def readlink(self, path: str) -> Optional[str]:
        return self._readlink(path)

    @log_call
    def readlinkat(self, dir_fd: int, path: str) -> Optional[str]:
        path = self._resolve_dir_fd(dir_fd, path)
        return self._readlink(path)

    @log_call
    def lseek(self, fd: int, offset: int, whence: int) -> int:
        self._check_fd(fd)

        if fd in self._dev_fds:
            device = self._dev_map[fd]
            if not device.seekable():
                raise SystemOperationFailed("Not support seek", SyscallError.EBADF)
            return device.seek(offset, whence)

        return os.lseek(fd, offset, whence)

    @log_call
    def stat(self, path: str) -> bytes:
        real_path = self._get_real_path(path)
        return self._construct_stat64(os.stat(real_path))

    @log_call
    def fstat(self, fd: int) -> bytes:
        if fd in self._dir_fds:
            path = self._dir_fds[fd]
            return self.stat(path)

        self._check_fd(fd)

        if fd in self._dev_fds:
            return self._construct_dev_stat64()

        return self._construct_stat64(os.fstat(fd))

    @log_call
    def fstatat(self, dir_fd: int, path: str) -> bytes:
        path = self._resolve_dir_fd(dir_fd, path)
        return self._stat(path)

    @log_call
    def lstat(self, path: str) -> bytes:
        real_path = self._get_real_path(path)
        return self._construct_stat64(os.lstat(real_path))

    @log_call
    def statfs(self, path: str) -> bytes:
        if path:
            pass
        return self._construct_statfs64()

    @log_call
    def fstatfs(self, fd: int) -> bytes:
        if fd:
            pass
        return self._construct_statfs64()

    @log_call
    def fsync(self, fd: int):
        self._check_fd(fd)

        os.fsync(fd)

    @log_call
    def rename(self, old: str, new: str):
        self._rename(old, new)

    @log_call
    def renameat(self, src_fd: int, old: str, dst_fd: int, new: str):
        old = self._resolve_dir_fd(src_fd, old)
        new = self._resolve_dir_fd(dst_fd, new)

        return self._rename(old, new)

    @log_call
    def mkdir(self, path: str, mode: int):
        self._mkdir(path, mode)

    @log_call
    def mkdirat(self, dir_fd: int, path: str, mode: int):
        path = self._resolve_dir_fd(dir_fd, path)
        self._mkdir(path, mode)

    @log_call
    def rmdir(self, path: str):
        real_path = self._get_real_path(path)
        exist = os.path.exists(real_path)

        if not exist:
            raise SystemOperationFailed(
                f"No such directory: {real_path}", SyscallError.ENOENT
            )

        raise SystemOperationFailed(
            f"Banned directory deletion: {path}", SyscallError.EACCES
        )

    @log_call
    def pread(self, fd: int, size: int, offset: int) -> bytes:
        self._check_fd(fd)

        pos = os.lseek(fd, 0, os.SEEK_CUR)
        os.lseek(fd, offset, os.SEEK_SET)

        data = os.read(fd, size)

        os.lseek(fd, pos, os.SEEK_SET)

        return data

    @log_call
    def chmod(self, path: str, mode: int):
        self._chmod(path, mode)

    @log_call
    def fchmod(self, fd: int, mode: int):
        pass

    @log_call
    def fchmodat(self, dir_fd: int, path: str, mode: int):
        path = self._resolve_dir_fd(dir_fd, path)
        self._chmod(path, mode)

    @log_call
    def chdir(self, path: str):
        self._chdir(path)

    @log_call
    def fchdir(self, fd: int):
        if fd not in self._dir_fds:
            raise SystemOperationFailed(f"Not a directory: {fd}", SyscallError.ENOTDIR)

        self._chdir(self._dir_fds[fd])

    @log_call
    def chown(self, path: str, uid: int, gid: int):
        self._chown(path, uid, gid)

    @log_call
    def fchown(self, fd: int, uid: int, gid: int):
        pass

    @log_call
    def fchownat(self, dir_fd: int, path: str, uid: int, gid: int):
        path = self._resolve_dir_fd(dir_fd, path)
        self._chown(path, uid, gid)

    @log_call
    def lchown(self, path: str, uid: int, gid: int):
        self._chown(path, uid, gid)

    @log_call
    def gettimeofday(self) -> bytes:
        time_ns = time.time_ns()

        # seconds
        result = (time_ns // (10**9)).to_bytes(8, "little", signed=False)
        # microseconds
        result += (time_ns % (10**9) // 10**3).to_bytes(8, "little", signed=False)

        return result

    def _construct_environ(self, text: str) -> int:
        """Construct the structure that contains environment variables."""
        lines = text.split("\n")

        size = self.emu.arch.addr_size * (len(lines) + 1)
        buffer = self.emu.create_buffer(size)

        for index, line in enumerate(lines):
            address = buffer + self.emu.arch.addr_size * index
            self.emu.write_pointer(address, self.emu.create_string(line))

        self.emu.write_pointer(buffer + size - self.emu.arch.addr_size, 0)

        return buffer

    def _setup_devices(self):
        """Setup device files."""
        self.mount_device("/dev/null", NullDevice)
        self.mount_device("/dev/random", RandomDevice)
        self.mount_device("/dev/urandom", UrandomDevice)

    def initialize(self):
        """Initialize environment."""
        pass
