from __future__ import annotations

import abc
import copy
import ctypes
import os
import posixpath
import socket
import sys
import shutil
import time
from abc import ABC
from pathlib import Path
from typing import Dict, List, Optional, overload, Tuple, Type, TYPE_CHECKING, TypeVar

from chomper.loader import BaseLoader
from chomper.exceptions import SystemOperationFailed
from chomper.feature import Feature
from chomper.log import get_logger
from chomper.utils import log_call, safe_join, struct_to_bytes, to_signed

from .device import DeviceFile
from .error import SyscallError
from .file import FileProperty, FdEntry, FileEntry, DirEntry, DeviceEntry, SocketEntry
from .handle import HandleManager
from .syscall import BaseSyscallHandler

if TYPE_CHECKING:
    from chomper.core import Chomper


FdEntryT = TypeVar("FdEntryT", bound=FdEntry)


class PosixOs(ABC):
    """Provide POSIX interface.

    Args:
        emu: The emulator instance.
        rootfs_path: As the root directory of the mapping file system.
    """

    FD_START_VALUE = 1
    FD_MAX_NUM = 10000

    AT_FDCWD: int

    AF_UNIX = 1
    AF_INET = 2
    AF_INET6 = 30

    SOCK_STREAM = 1

    IPPROTO_IP = 0
    IPPROTO_ICMP = 1
    IPPROTO_TCP = 6

    SHUT_RD = 0
    SHUT_WR = 1
    SHUT_RDWR = 2

    F_GETFL = 3
    F_GETLK = 7
    F_SETLK = 8
    F_GETPATH = 50

    F_UNLCK = 2

    def __init__(self, emu: Chomper, rootfs_path: Optional[str] = None):
        self.emu = emu
        self.logger = get_logger(__name__)

        self.rootfs_path = rootfs_path

        # Current working directory
        self._working_dir = "/"

        # Forward path
        self._path_map: Dict[str, str] = {}

        # File descriptor
        self._fds: HandleManager[FdEntry] = HandleManager(
            start_value=self.FD_START_VALUE,
            max_num=self.FD_MAX_NUM,
        )

        # Device file
        self._devices: Dict[str, Type[DeviceFile]] = {}

        # Symbolic link
        self._symbolic_links: Dict[str, str] = {}

        # Standard I/O
        if sys.stdin.isatty():
            self._stdin_fd = self._new_fd(
                FileEntry(real_fd=sys.stdin.fileno(), path="/dev/null")
            )
        else:
            self._stdin_fd = 0

        self._stdout_fd = self._new_fd(
            FileEntry(real_fd=sys.stdout.fileno(), path="/dev/null")
        )
        self._stderr_fd = self._new_fd(
            FileEntry(real_fd=sys.stderr.fileno(), path="/dev/null")
        )

        # Mapping files
        self._mapping_files: Dict[int, str] = {}

        self._file_properties: List[FileProperty] = []

    @property
    @abc.abstractmethod
    def loader(self) -> BaseLoader:
        """Executable file loader."""
        pass

    @property
    @abc.abstractmethod
    def syscall_handler(self) -> BaseSyscallHandler:
        """System calls handler."""
        pass

    @abc.abstractmethod
    def get_errno(self) -> int:
        """Get the `errno`."""
        pass

    @abc.abstractmethod
    def set_errno(self, value: int):
        """Set the `errno`."""
        pass

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

        path = posixpath.abspath(path)
        resolved_path = self._resolve_link(path)

        if not resolved_path.startswith("/"):
            absolute_path = os.path.join(self._working_dir, resolved_path)
        else:
            absolute_path = resolved_path

        return absolute_path

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

    @staticmethod
    def raise_permission_denied():
        raise SystemOperationFailed("No permission", SyscallError.EPERM)

    def _new_fd(self, entry: FdEntry) -> int:
        """Create a new file descriptor."""
        fd = self._fds.new(entry)
        if fd is None:
            raise SystemOperationFailed("Too many open files", SyscallError.EMFILE)

        return fd

    @overload
    def _get_fd_entry(self, fd: int) -> FdEntry:
        pass

    @overload
    def _get_fd_entry(self, fd: int, entry_cls: Type[FdEntryT]) -> FdEntryT:
        pass

    def _get_fd_entry(
        self,
        fd: int,
        entry_cls: Optional[Type[FdEntry]] = None,
    ) -> FdEntry:
        if entry_cls is None:
            entry_cls = FdEntry

        entry = self._fds.get_as(fd, entry_cls)
        if entry is None:
            raise SystemOperationFailed(
                f"Bad file descriptor: {fd}", SyscallError.EBADF
            )

        return entry

    @staticmethod
    @abc.abstractmethod
    def _resolve_flags(flags: int) -> int:
        pass

    def _resolve_dir_fd(self, dir_fd: int, path: str) -> str:
        """Returns the full path constructed by combining with `dir_fd`."""
        if path.startswith("/"):
            return path
        elif dir_fd == to_signed(self.AT_FDCWD, size=4):
            return posixpath.join(self._working_dir, path)
        else:
            entry = self._get_fd_entry(dir_fd, DirEntry)
            return posixpath.join(entry.path, path)

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

    def mount_devices(self, dev_map: Dict[str, Type[DeviceFile]]):
        """Mount multiple files"""
        for path, dev_cls in dev_map.items():
            self.mount_device(path, dev_cls)

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

    def _make_stat(self, st: Optional[os.stat_result]) -> ctypes.Structure:
        raise NotImplementedError

    def _make_statfs(self, path: str) -> ctypes.Structure:
        raise NotImplementedError

    def _get_file_property(self, path: str) -> Optional[FileProperty]:
        for prop in self._file_properties:
            if path == prop.path:
                return prop

        # Recursively get parent directory properties
        if path != "/":
            dir_path = posixpath.dirname(path)
            return self._get_file_property(dir_path)

        return None

    def add_file_property(self, prop: FileProperty):
        self._file_properties.append(prop)

    def _check_dir_writeable(self, path: str):
        absolute_path = self._get_absolute_path(path)
        dir_path = posixpath.dirname(absolute_path)

        file_prop = self._get_file_property(dir_path)
        if not file_prop or not file_prop.is_dir or not file_prop.writeable:
            self.raise_permission_denied()

    @abc.abstractmethod
    def getuid(self) -> int:
        pass

    @abc.abstractmethod
    def getgid(self) -> int:
        pass

    @abc.abstractmethod
    def getpid(self) -> int:
        pass

    @abc.abstractmethod
    def getpgid(self) -> int:
        pass

    def _open(self, path: str, flags: int, mode: int) -> int:
        real_path = self._get_real_path(path)
        flags = self._resolve_flags(flags)
        absolute_path = self._get_absolute_path(path)

        if os.path.isdir(real_path):
            return self._new_fd(DirEntry(path=absolute_path))

        if path in self._devices:
            device = self._devices[path]()
            return self._new_fd(DeviceEntry(path=absolute_path, device=device))

        # Check file creation permissions
        if flags & os.O_CREAT:
            self._check_dir_writeable(path)

        real_fd = os.open(real_path, flags, mode)
        return self._new_fd(FileEntry(path=absolute_path, real_fd=real_fd))

    def _close(self, fd: int):
        entry = self._get_fd_entry(fd, FdEntry)
        entry.close()

        self._fds.free(fd)

    def _link(self, src_path: str, dst_path: str):
        self._check_dir_writeable(dst_path)

        self.set_symbolic_link(src_path, dst_path)

    def _symlink(self, src_path: str, dst_path: str):
        self._check_dir_writeable(dst_path)

        self.set_symbolic_link(src_path, dst_path)

    def _unlink(self, path: str):
        self._check_dir_writeable(path)

        real_path = self._get_real_path(path)

        exist = os.path.exists(real_path)
        if not exist:
            raise SystemOperationFailed(
                f"No such file: {real_path}", SyscallError.ENOENT
            )

        os.remove(real_path)

    def _readlink(self, path: str) -> Optional[str]:
        return self._symbolic_links.get(path)

    def _access(self, path: str, mode: int) -> bool:
        real_path = self._get_real_path(path)
        return os.access(real_path, mode)

    def _stat(self, path: str) -> bytes:
        real_path = self._get_real_path(path)
        st = self._make_stat(os.stat(real_path))
        return struct_to_bytes(st)

    def _rename(self, old: str, new: str):
        self._check_dir_writeable(new)

        real_old = self._get_real_path(old)
        real_new = self._get_real_path(new)

        # On Windows, a file cannot be deleted before its file descriptor is closed.
        if sys.platform == "win32":
            for fd, _ in self._fds.items():
                entry = self._fds.get_as(fd, FileEntry)
                if entry and entry.path == self._get_absolute_path(old):
                    os.close(entry.real_fd)

        try:
            os.rename(real_old, real_new)
        except PermissionError:
            shutil.copy(real_old, real_new)

    def _mkdir(self, path: str, mode: int):
        self._check_dir_writeable(path)

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
        entry = self._get_fd_entry(fd, FdEntry)
        return entry.read(size)

    @log_call
    def write(self, fd: int, buf: int, size: int) -> int:
        entry = self._get_fd_entry(fd, FdEntry)
        data = self.emu.read_bytes(buf, size)

        return entry.write(data)

    @log_call
    def open(self, path: str, flags: int, mode: int) -> int:
        return self._open(path, flags, mode)

    @log_call
    def openat(self, dir_fd: int, path: str, flags: int, mode: int) -> int:
        path = self._resolve_dir_fd(dir_fd, path)
        return self._open(path, flags, mode)

    @log_call
    def close(self, fd: int) -> int:
        self._close(fd)

        return 0

    @log_call
    def dup(self, fd: int) -> int:
        entry = self._get_fd_entry(fd, FdEntry)

        new_fd = self._fds.new(copy.copy(entry))
        if new_fd is None:
            raise SystemOperationFailed("Too many open files", SyscallError.EMFILE)

        return new_fd

    @log_call
    def dup2(self, old_fd: int, new_fd: int):
        entry = self._get_fd_entry(old_fd, FdEntry)

        if old_fd == new_fd:
            return

        if self._fds.validate(new_fd):
            self._close(new_fd)

        result = self._fds.new(copy.copy(entry), value=new_fd)
        if result is None:
            raise SystemOperationFailed(
                f"Bad file descriptor: {new_fd}", SyscallError.EBADF
            )

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
    def symlinkat(self, src_path: str, dst_dir_fd: int, dst_path: str):
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
        entry = self._get_fd_entry(fd, FdEntry)
        return entry.seek(offset, whence)

    @log_call
    def stat(self, path: str) -> bytes:
        return self._stat(path)

    @log_call
    def fstat(self, fd: int) -> bytes:
        entry = self._get_fd_entry(fd, FdEntry)

        if isinstance(entry, DirEntry):
            return self._stat(entry.path)
        elif isinstance(entry, DeviceEntry):
            st = self._make_stat(None)
            return struct_to_bytes(st)
        elif isinstance(entry, FileEntry):
            st = self._make_stat(os.fstat(entry.real_fd))
            return struct_to_bytes(st)
        else:
            return b""

    @log_call
    def fstatat(self, dir_fd: int, path: str) -> bytes:
        path = self._resolve_dir_fd(dir_fd, path)
        return self._stat(path)

    @log_call
    def lstat(self, path: str) -> bytes:
        return self._stat(path)

    @log_call
    def statfs(self, path: str) -> bytes:
        st = self._make_statfs(path)
        return struct_to_bytes(st)

    @log_call
    def fstatfs(self, fd: int) -> bytes:
        entry = self._get_fd_entry(fd)

        st = self._make_statfs(entry.path)
        return struct_to_bytes(st)

    @log_call
    def fsync(self, fd: int):
        entry = self._get_fd_entry(fd, FdEntry)

        if isinstance(entry, FileEntry):
            os.fsync(entry.real_fd)

    @log_call
    def rename(self, old: str, new: str):
        self._rename(old, new)

    @log_call
    def renameat(self, src_dir_fd: int, old: str, dst_dir_fd: int, new: str):
        old = self._resolve_dir_fd(src_dir_fd, old)
        new = self._resolve_dir_fd(dst_dir_fd, new)

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

        self._check_dir_writeable(path)

        os.rmdir(real_path)

    def _pread(self, fd: int, size: int, offset: int) -> bytes:
        entry = self._get_fd_entry(fd, FileEntry)

        pos = os.lseek(entry.real_fd, 0, os.SEEK_CUR)
        os.lseek(entry.real_fd, offset, os.SEEK_SET)

        data = os.read(entry.real_fd, size)

        os.lseek(entry.real_fd, pos, os.SEEK_SET)

        return data

    @log_call
    def pread(self, fd: int, size: int, offset: int) -> bytes:
        return self._pread(fd, size, offset)

    @log_call
    def pwrite(self, fd: int, buf: int, size: int, offset: int) -> int:
        entry = self._get_fd_entry(fd, FdEntry)

        data = self.emu.read_bytes(buf, size)

        if isinstance(entry, DeviceEntry):
            return entry.write(data)
        elif isinstance(entry, FileEntry):
            pos = os.lseek(entry.real_fd, 0, os.SEEK_CUR)
            os.lseek(entry.real_fd, offset, os.SEEK_SET)

            result = os.write(entry.real_fd, data)

            os.lseek(entry.real_fd, pos, os.SEEK_SET)

            return result
        else:
            return 0

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
        entry = self._get_fd_entry(fd, FdEntry)

        if not isinstance(entry, DirEntry):
            raise SystemOperationFailed(f"Not a directory: {fd}", SyscallError.ENOTDIR)

        self._chdir(entry.path)

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
        if not Feature.SOCKET_ENABLED:
            self.raise_permission_denied()

        domain_map = {
            self.AF_INET: socket.AF_INET,
            self.AF_INET6: socket.AF_INET6,
        }

        type_map = {
            self.SOCK_STREAM: socket.SOCK_STREAM,
        }

        protocol_map = {
            self.IPPROTO_IP: socket.IPPROTO_IP,
            self.IPPROTO_ICMP: socket.IPPROTO_ICMP,
            self.IPPROTO_TCP: socket.IPPROTO_TCP,
        }

        # Unix sockets
        if domain == self.AF_UNIX:
            return self._new_fd(SocketEntry())

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

        return self._new_fd(SocketEntry(sock=sock))

    def _read_inet_host(self, address: int) -> Tuple[str, int]:
        port_n = self.emu.read_u16(address + 2)
        host_bytes = self.emu.read_bytes(address + 4, 4)

        port = socket.ntohs(port_n)
        host = socket.inet_ntoa(host_bytes)

        return host, port

    def _read_inet64_host(self, address: int) -> Tuple[str, int]:
        port_n = self.emu.read_u16(address + 2)
        host_bytes = self.emu.read_bytes(address + 8, 16)

        port = socket.ntohs(port_n)
        host = socket.inet_ntop(socket.AF_INET6, host_bytes)

        return host, port

    @log_call
    def connect(self, sock: int, address: int, address_len: int) -> int:
        if not Feature.SOCKET_ENABLED:
            self.raise_permission_denied()

        entry = self._get_fd_entry(sock, SocketEntry)

        family = self.emu.read_u8(address + 1)
        if family == self.AF_UNIX:
            path = self.emu.read_string(address + 2)
            if path == "/var/run/mDNSResponder":
                entry.family = family
                entry.path = path
                return 0
        elif family in (self.AF_INET, self.AF_INET6):
            entry.family = family

            if family == self.AF_INET6:
                host, port = self._read_inet64_host(address)
            else:
                host, port = self._read_inet_host(address)

            self.logger.info(
                f"Establishing socket connection: host={host}, port={port}"
            )

            entry.inner_sock.connect((host, port))

            return 0
        else:
            self.logger.warning("Unsupported protocol family: %s", family)

        return -1

    @log_call
    def bind(self, sock: int, address: int, address_len: int) -> int:
        if not Feature.SOCKET_ENABLED:
            self.raise_permission_denied()

        entry = self._get_fd_entry(sock, SocketEntry)

        family = self.emu.read_u8(address + 1)
        if family in (self.AF_INET, self.AF_INET6):
            entry.family = family

            if family == self.AF_INET6:
                host, port = self._read_inet64_host(address)
            else:
                host, port = self._read_inet_host(address)

            self.logger.info(f"Bind socket to: host={host}, port={port}")

            entry.inner_sock.bind((host, port))

            return 0
        else:
            self.logger.warning("Unsupported protocol family: %s", family)

        return -1

    @log_call
    def listen(self, sock: int, backlog: int) -> int:
        if not Feature.SOCKET_ENABLED:
            self.raise_permission_denied()

        entry = self._get_fd_entry(sock, SocketEntry)
        entry.inner_sock.listen(backlog)

        return 0

    @log_call
    def socketpair(
        self,
        domain: int,
        sock_type: int,
        protocol: int,
    ) -> Optional[Tuple[int, int]]:
        if not Feature.SOCKET_ENABLED:
            return None

        read_fd = self._fds.new(SocketEntry(family=domain))
        write_fd = self._fds.new(SocketEntry(family=domain))

        if read_fd is None or write_fd is None:
            return None

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
        if not Feature.SOCKET_ENABLED:
            self.raise_permission_denied()

        entry = self._get_fd_entry(sock, SocketEntry)
        data = self.emu.read_bytes(buffer, length)

        if entry.family == self.AF_UNIX:
            return len(data)

        entry.inner_sock.send(data)

        return len(data)

    @log_call
    def sendmsg(self, sock: int, buffer: int, flags: int) -> int:
        if not Feature.SOCKET_ENABLED:
            self.raise_permission_denied()

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
        if not Feature.SOCKET_ENABLED:
            self.raise_permission_denied()

        entry = self._get_fd_entry(sock, SocketEntry)

        if entry.family == self.AF_UNIX:
            return 0

        recv_bytes = entry.inner_sock.recv(length)
        self.emu.write_bytes(buffer, recv_bytes)

        return len(recv_bytes)

    def _fd_set_count(self, fd_set: int) -> int:
        """Get the number of members in `fd_set`."""
        raw_bytes = self.emu.read_bytes(fd_set, 128)
        count = 0

        for byte in raw_bytes:
            count += bin(byte).count("1")

        return count

    @log_call
    def select(
        self,
        nfds: int,
        readfds: int,
        writefds: int,
        errorfds: int,
        timeout: int,
    ) -> int:
        if not Feature.SOCKET_ENABLED:
            self.raise_permission_denied()

        count = 0

        # Make all descriptors ready

        if readfds:
            count += self._fd_set_count(readfds)

        if writefds:
            count += self._fd_set_count(writefds)

        if errorfds:
            count += self._fd_set_count(errorfds)

        return count

    @log_call
    def shutdown(self, sock: int, how: int):
        if not Feature.SOCKET_ENABLED:
            self.raise_permission_denied()

        shut_map = {
            self.SHUT_RD: socket.SHUT_RD,
            self.SHUT_WR: socket.SHUT_WR,
            self.SHUT_RDWR: socket.SHUT_RDWR,
        }

        entry = self._get_fd_entry(sock, SocketEntry)

        if how not in shut_map:
            raise SystemOperationFailed("Invalid argument", SyscallError.EINVAL)

        entry.inner_sock.shutdown(shut_map[how])

    def _make_sockaddr_in(self, address: str, port: int) -> ctypes.Structure:
        raise NotImplementedError

    @log_call
    def getpeername(self, sock: int) -> bytes:
        if not Feature.SOCKET_ENABLED:
            self.raise_permission_denied()

        entry = self._get_fd_entry(sock, SocketEntry)

        address, port = entry.inner_sock.getpeername()
        st = self._make_sockaddr_in(address, port)

        return struct_to_bytes(st)

    @log_call
    def getsockname(self, sock: int) -> bytes:
        if not Feature.SOCKET_ENABLED:
            self.raise_permission_denied()

        entry = self._get_fd_entry(sock, SocketEntry)

        address, port = entry.inner_sock.getsockname()
        st = self._make_sockaddr_in(address, port)

        return struct_to_bytes(st)

    def _make_flock(self, lock_type: int) -> ctypes.Structure:
        raise NotImplementedError

    @log_call
    def fcntl(self, fd: int, cmd: int, arg: int) -> int:
        if cmd == self.F_GETFL:
            if fd in (self._stdin_fd,):
                return os.O_RDONLY
            elif fd in (self._stdout_fd, self._stderr_fd):
                return os.O_WRONLY
            return os.O_RDWR
        elif cmd == self.F_GETLK:
            st = self._make_flock(self.F_UNLCK)
            self.emu.write_bytes(arg, struct_to_bytes(st))
        elif cmd == self.F_SETLK:
            pass
        elif cmd == self.F_GETPATH:
            entry = self._get_fd_entry(fd)
            if entry.path:
                self.emu.write_string(arg, entry.path)
        else:
            self.emu.logger.warning(f"Unhandled fcntl command: {cmd}")

        return 0

    @log_call
    def ftruncate(self, fd: int, length: int):
        entry = self._get_fd_entry(fd, FileEntry)

        os.ftruncate(entry.real_fd, length)

    @log_call
    def utimes(self, path: str, times: Optional[Tuple[float, float]]):
        real_path = self._get_real_path(path)

        os.utime(real_path, times)

    @log_call
    def futimes(self, fd: int, times: Optional[Tuple[float, float]]):
        entry = self._get_fd_entry(fd)
        real_path = self._get_real_path(entry.path)

        os.utime(real_path, times)

    @log_call
    def mmap(self, length: int, fd: int, offset: int) -> int:
        addr = self.emu.create_buffer(length)

        if fd != -1:
            entry = self._get_fd_entry(fd)

            chunk_size = 1024 * 1024
            content = b""

            while True:
                chunk = self.read(fd, chunk_size)
                if not chunk:
                    break
                content += chunk

            self.emu.write_bytes(addr, content[offset:])

            self._mapping_files[addr] = entry.path

        return addr

    @log_call
    def munmap(self, addr: int):
        if addr not in self._mapping_files:
            raise SystemOperationFailed(
                f"Invalid address: {hex(addr)}", SyscallError.EINVAL
            )

        self.emu.free(addr)
        del self._mapping_files[addr]

    @log_call
    def msync(self, addr: int, length: int):
        if addr not in self._mapping_files:
            raise SystemOperationFailed(
                f"Invalid address: {hex(addr)}", SyscallError.EINVAL
            )

        path = self._mapping_files[addr]
        real_path = self._get_real_path(path)

        data = self.emu.read_bytes(addr, length)

        with open(real_path, "wb") as f:
            f.write(data)

    @log_call
    def mlock(self, addr: int, length: int):
        pass

    @log_call
    def munlock(self, addr: int, length: int):
        pass

    @log_call
    def mlockall(self, flags: int):
        pass
