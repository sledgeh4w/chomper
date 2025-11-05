from __future__ import annotations

import os
import posixpath
import socket
import sys
import shutil
import time
from abc import ABC
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Type, TYPE_CHECKING

from chomper.exceptions import SystemOperationFailed
from chomper.log import get_logger
from chomper.utils import log_call, safe_join, to_signed

from .device import DeviceFile
from .handle import HandleManager

if TYPE_CHECKING:
    from chomper.core import Chomper


class SyscallError(Enum):
    EPERM = 1
    ENOENT = 2
    EBADF = 3
    EACCES = 4
    EEXIST = 5
    ENOTDIR = 6

    EXT1 = 1000


class FdType(Enum):
    FILE = 1
    DIR = 2
    DEV = 3
    SOCK = 4


class PosixOs(ABC):
    """Provide POSIX interface.

    Args:
        emu: The emulator instance.
        rootfs_path: As the root directory of the mapping file system.
    """

    FEATURE_SOCKET_ENABLE = False

    FD_START_VALUE = 1
    FD_MAX_NUM = 10000

    AT_FDCWD: int

    AF_UNIX = 1
    AF_INET = 2

    SOCK_STREAM = 1

    IPPROTO_IP = 0
    IPPROTO_ICMP = 1

    F_GETFL = 3
    F_GETPATH = 50

    def __init__(self, emu: Chomper, rootfs_path: Optional[str] = None):
        self.emu = emu
        self.logger = get_logger(__name__)

        self.rootfs_path = rootfs_path

        # Current working directory
        self._working_dir = "/"

        # Forward path
        self._path_map: Dict[str, str] = {}

        # File descriptor
        self._file_manager = HandleManager(
            start_value=self.FD_START_VALUE,
            max_num=self.FD_MAX_NUM,
        )

        # Device file
        self._devices: Dict[str, Type[DeviceFile]] = {}

        # Symbolic link
        self._symbolic_links: Dict[str, str] = {}

        # Standard I/O
        if sys.stdin.isatty():
            self._stdin_fd = self._new_fd(FdType.FILE, real_fd=sys.stdin.fileno())
        else:
            self._stdin_fd = 0

        self._stdout_fd = self._new_fd(FdType.FILE, real_fd=sys.stdout.fileno())
        self._stderr_fd = self._new_fd(FdType.FILE, real_fd=sys.stderr.fileno())

    def get_errno(self) -> int:
        """Get the `errno`."""
        raise NotImplementedError("get_errno")

    def set_errno(self, value: int):
        """Set the `errno`."""
        raise NotImplementedError("set_errno")

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
        """Recursively resolve symbolic links in the path to their real paths."""
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
        """Forward all access from `src_path` to `dst_path`."""
        self._path_map[src_path] = os.path.abspath(dst_path)

    def set_symbolic_link(self, src_path: str, dst_path: str):
        """Set a symbolic link to specified path."""
        self._symbolic_links[src_path] = dst_path

    def _new_fd(self, fd_type: FdType, **kwargs) -> int:
        """Create a new file descriptor."""
        if fd_type not in (value for value in FdType):
            return 0

        fd = self._file_manager.new()
        if not fd:
            return 0

        self._file_manager.set_prop(fd, "type", fd_type)

        for key, value in kwargs.items():
            self._file_manager.set_prop(fd, key, value)

        return fd

    def _is_file_fd(self, fd: int) -> bool:
        return self._file_manager.get_prop(fd, "type") == FdType.FILE

    def _is_dir_fd(self, fd: int) -> bool:
        return self._file_manager.get_prop(fd, "type") == FdType.DIR

    def _is_dev_fd(self, fd: int) -> bool:
        return self._file_manager.get_prop(fd, "type") == FdType.DEV

    def _is_sock_fd(self, fd: int) -> bool:
        return self._file_manager.get_prop(fd, "type") == FdType.SOCK

    def _get_fd_real_fd(self, fd: int) -> int:
        real_fd = self._file_manager.get_prop(fd, "real_fd")

        assert isinstance(real_fd, int)

        return real_fd

    def _get_fd_path(self, fd: int) -> str:
        path = self._file_manager.get_prop(fd, "path")

        assert isinstance(path, str)

        return path

    def _get_fd_device(self, fd: int) -> DeviceFile:
        device = self._file_manager.get_prop(fd, "device")

        assert isinstance(device, DeviceFile)

        return device

    def _get_fd_sock(self, fd: int) -> socket.socket:
        sock = self._file_manager.get_prop(fd, "sock")

        assert isinstance(sock, socket.socket)

        return sock

    def _device_read(self, fd: int, size: int) -> bytes:
        device = self._get_fd_device(fd)
        if not device.readable():
            raise SystemOperationFailed("Not support read", SyscallError.EBADF)

        result = device.read(size)
        if result is None:
            return b""

        return result

    def _device_write(self, fd: int, data: bytes) -> int:
        device = self._get_fd_device(fd)
        if not device.writable():
            raise SystemOperationFailed("Not support write", SyscallError.EBADF)

        result = device.write(data)
        if result is None:
            return 0

        return result

    def _device_seek(self, fd: int, offset: int, whence: int) -> int:
        device = self._get_fd_device(fd)
        if not device.seekable():
            raise SystemOperationFailed("Not support seek", SyscallError.EBADF)

        return device.seek(offset, whence)

    def _check_fd(self, fd: int):
        """Check file descriptor.

        Raises:
            BadFileDescriptor: If bad file descriptor.
        """
        if not self._file_manager.validate(fd):
            raise SystemOperationFailed(
                f"Bad file descriptor: {fd}", SyscallError.EBADF
            )

    @staticmethod
    def _resolve_flags(flags: int) -> int:
        """Create flags that will be actually passed into the host machine.

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
        elif dir_fd == to_signed(self.AT_FDCWD, size=4):
            return posixpath.join(self._working_dir, path)
        else:
            dir_path = self._get_fd_path(dir_fd)
            return posixpath.join(dir_path, path)

    def _resolve_path(self, path: str) -> str:
        if path.startswith("/"):
            return path
        return posixpath.join(self._working_dir, path)

    def mount_device(self, path: str, dev_cls: Type[DeviceFile]):
        """Mount device file to virtual file system."""
        self._devices[path] = dev_cls

    def unmount_device(self, path: str):
        """Unmount device file."""
        del self._devices[path]

    def _create_environ(self, text: str) -> int:
        """Create the structure that contains environment variables."""
        lines = text.split("\n")

        size = self.emu.arch.addr_size * (len(lines) + 1)
        buffer = self.emu.create_buffer(size)

        for index, line in enumerate(lines):
            address = buffer + self.emu.arch.addr_size * index
            self.emu.write_pointer(address, self.emu.create_string(line))

        self.emu.write_pointer(buffer + size - self.emu.arch.addr_size, 0)

        return buffer

    def _create_stat(self, st: os.stat_result) -> bytes:
        raise NotImplementedError("_create_stat")

    def _create_device_stat(self) -> bytes:
        raise NotImplementedError("_create_device_stat")

    def _create_statfs(self) -> bytes:
        raise NotImplementedError("_create_statfs")

    def _open(self, path: str, flags: int, mode: int) -> int:
        real_path = self._get_real_path(path)
        flags = self._resolve_flags(flags)
        absolute_path = self._get_absolute_path(path)

        if os.path.isdir(real_path):
            return self._new_fd(FdType.DIR, path=absolute_path)

        if path in self._devices:
            device = self._devices[path]()
            return self._new_fd(
                FdType.DEV,
                path=absolute_path,
                device=device,
            )

        real_fd = os.open(real_path, flags, mode)
        return self._new_fd(
            FdType.FILE,
            path=absolute_path,
            real_fd=real_fd,
        )

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
        return self._create_stat(os.stat(real_path))

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

        if self._is_dev_fd(fd):
            return self._device_read(fd, size)

        real_fd = self._get_fd_real_fd(fd)
        return os.read(real_fd, size)

    @log_call
    def write(self, fd: int, buf: int, size: int) -> int:
        self._check_fd(fd)

        data = self.emu.read_bytes(buf, size)

        if self._is_dev_fd(fd):
            return self._device_write(fd, data)

        real_fd = self._get_fd_real_fd(fd)
        return os.write(real_fd, data)

    @log_call
    def open(self, path: str, flags: int, mode: int) -> int:
        return self._open(path, flags, mode)

    @log_call
    def openat(self, dir_fd: int, path: str, flags: int, mode: int) -> int:
        path = self._resolve_dir_fd(dir_fd, path)
        return self._open(path, flags, mode)

    @log_call
    def close(self, fd: int) -> int:
        self._check_fd(fd)

        if self._is_sock_fd(fd):
            sock = self._get_fd_sock(fd)
            sock.close()

        if self._is_file_fd(fd):
            real_fd = self._get_fd_real_fd(fd)
            os.close(real_fd)

        self._file_manager.free(fd)

        return 0

    @log_call
    def link(self, src_path: str, dst_path: str):
        src_path = self._resolve_path(src_path)
        dst_path = self._resolve_path(dst_path)

        self._link(src_path, dst_path)

    @log_call
    def linkat(self, src_dir_fd: int, src_path: str, dst_dir_fd: int, dst_path: str):
        src_path = self._resolve_dir_fd(src_dir_fd, src_path)
        dst_path = self._resolve_dir_fd(dst_dir_fd, dst_path)

        self._link(src_path, dst_path)

    @log_call
    def symlink(self, src_path: str, dst_path: str):
        src_path = self._resolve_path(src_path)
        dst_path = self._resolve_path(dst_path)

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

        if self._is_dev_fd(fd):
            return self._device_seek(fd, offset, whence)

        real_fd = self._get_fd_real_fd(fd)
        return os.lseek(real_fd, offset, whence)

    @log_call
    def stat(self, path: str) -> bytes:
        return self._stat(path)

    @log_call
    def fstat(self, fd: int) -> bytes:
        self._check_fd(fd)

        if self._is_dir_fd(fd):
            path = self._get_fd_path(fd)
            return self._stat(path)

        if self._is_dev_fd(fd):
            return self._create_device_stat()

        real_fd = self._get_fd_real_fd(fd)
        return self._create_stat(os.fstat(real_fd))

    @log_call
    def fstatat(self, dir_fd: int, path: str) -> bytes:
        path = self._resolve_dir_fd(dir_fd, path)
        return self._stat(path)

    @log_call
    def lstat(self, path: str) -> bytes:
        return self._stat(path)

    @log_call
    def statfs(self, path: str) -> bytes:
        if path:
            pass
        return self._create_statfs()

    @log_call
    def fstatfs(self, fd: int) -> bytes:
        if fd:
            pass
        return self._create_statfs()

    @log_call
    def fsync(self, fd: int):
        self._check_fd(fd)
        real_fd = self._get_fd_real_fd(fd)

        os.fsync(real_fd)

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
        real_fd = self._get_fd_real_fd(fd)

        pos = os.lseek(real_fd, 0, os.SEEK_CUR)
        os.lseek(real_fd, offset, os.SEEK_SET)

        data = os.read(real_fd, size)

        os.lseek(real_fd, pos, os.SEEK_SET)

        return data

    @log_call
    def pwrite(self, fd: int, buf: int, size: int, offset: int) -> int:
        self._check_fd(fd)

        data = self.emu.read_bytes(buf, size)

        if self._is_dev_fd(fd):
            return self._device_write(fd, data)

        real_fd = self._get_fd_real_fd(fd)

        pos = os.lseek(real_fd, 0, os.SEEK_CUR)
        os.lseek(real_fd, offset, os.SEEK_SET)

        result = os.write(real_fd, data)

        os.lseek(real_fd, pos, os.SEEK_SET)

        return result

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
    def getcwd(self) -> str:
        return self.get_working_dir()

    @log_call
    def chdir(self, path: str):
        self._chdir(path)

    @log_call
    def fchdir(self, fd: int):
        if self._is_dev_fd(fd):
            raise SystemOperationFailed(f"Not a directory: {fd}", SyscallError.ENOTDIR)

        self._chdir(self._get_fd_path(fd))

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

    @log_call
    def socket(self, domain: int, sock_type: int, protocol: int) -> int:
        if not self.FEATURE_SOCKET_ENABLE:
            return -1

        domain_map = {
            self.AF_INET: socket.AF_INET,
        }

        type_map = {
            self.SOCK_STREAM: socket.SOCK_STREAM,
        }

        protocol_map = {
            self.IPPROTO_IP: socket.IPPROTO_IP,
            self.IPPROTO_ICMP: socket.IPPROTO_ICMP,
        }

        # Unix sockets
        if domain == self.AF_UNIX:
            return self._new_fd(FdType.SOCK)

        if (
            domain not in domain_map
            or sock_type not in type_map
            or protocol not in protocol_map
        ):
            return -1

        domain = domain_map[domain]
        sock_type = type_map[sock_type]
        protocol = protocol_map[protocol]

        sock = socket.socket(domain, sock_type, protocol)

        return self._new_fd(FdType.SOCK, sock=sock)

    @log_call
    def connect(self, sock: int, address: int, address_len: int) -> int:
        if not self.FEATURE_SOCKET_ENABLE:
            return -1

        family = self.emu.read_u8(address + 1)
        if family == self.AF_UNIX:
            path = self.emu.read_string(address + 2)
            if path == "/var/run/mDNSResponder":
                return 0
        elif family == self.AF_INET:
            pass
        else:
            self.logger.warning("Unsupported protocol family: %s", family)
            return -1

        return -1

    @log_call
    def socketpair(
        self, domain: int, sock_type: int, protocol: int
    ) -> Optional[Tuple[int, int]]:
        if not self.FEATURE_SOCKET_ENABLE:
            return None

        read_fd = self._new_fd(FdType.SOCK)
        write_fd = self._new_fd(FdType.SOCK)

        return read_fd, write_fd

    @log_call
    def getsockopt(
        self,
        sock: int,
        level: int,
        option_name: int,
        option_value: int,
        option_len: int,
    ) -> int:
        return 0

    @log_call
    def setsockopt(
        self,
        sock: int,
        level: int,
        option_name: int,
        option_value: int,
        option_len: int,
    ) -> int:
        return 0

    @log_call
    def sendto(
        self,
        sock: int,
        buffer: int,
        length: int,
        flags: int,
        dest_addr: int,
        dest_len: int,
    ) -> int:
        if not self.FEATURE_SOCKET_ENABLE:
            return -1

        data = self.emu.read_bytes(buffer, length)
        return len(data)

    @log_call
    def sendmsg(self, sock: int, buffer: int, flags: int) -> int:
        if not self.FEATURE_SOCKET_ENABLE:
            return -1

        msg_iov = self.emu.read_pointer(buffer + 16)
        msg_iovlen = self.emu.read_s64(buffer + 24)

        result = 0

        for index in range(msg_iovlen):
            offset = msg_iov + index * 48

            # iov_base = self.emu.read_pointer(offset)
            iov_len = self.emu.read_u64(offset + 8)

            # data = self.emu.read_bytes(iov_base, index)
            result += iov_len

        return result

    @log_call
    def recvfrom(
        self,
        sock: int,
        buffer: int,
        length: int,
        flags: int,
        address: int,
        address_len: int,
    ) -> int:
        if not self.FEATURE_SOCKET_ENABLE:
            return -1

        self.emu.write_bytes(buffer, b"\x00" * length)
        return length

    @log_call
    def fcntl(self, fd: int, cmd: int, arg: int) -> int:
        if cmd == self.F_GETFL:
            if fd in (self._stdin_fd,):
                return os.O_RDONLY
            elif fd in (self._stdout_fd, self._stderr_fd):
                return os.O_WRONLY
        elif cmd == self.F_GETPATH:
            path = self._get_fd_path(fd)
            if path:
                self.emu.write_string(arg, path)
        else:
            self.emu.logger.warning(f"Unhandled fcntl command: {cmd}")

        return 0
