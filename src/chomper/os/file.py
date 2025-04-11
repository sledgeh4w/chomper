from __future__ import annotations

import ctypes
import os
import posixpath
import shutil
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, TYPE_CHECKING

from chomper.exceptions import FileNotExist, FileBadDescriptor, FilePermissionDenied
from chomper.log import get_logger
from chomper.utils import struct2bytes, log_call, safe_join

from .structs import Stat64, Statfs64, Timespec, Dirent

if TYPE_CHECKING:
    from chomper.core import Chomper


class FileSystem:
    """Provide file system access interface.

    All system calls related to files from emulated programs must access real files
    through this class.

    Args:
        emu: The emulator instance.
        rootfs_path: As the root directory of the mapping file system.
    """

    MAX_OPEN_DIR_NUM = 10000

    def __init__(self, emu: Chomper, rootfs_path: Optional[str]):
        self.emu = emu
        self.logger = get_logger(__name__)

        self.rootfs_path = rootfs_path
        self.working_dir = ""

        self.path_map: Dict[str, str] = {}

        self.symbolic_links: Dict[str, str] = {}

        # Iterate over files in a directory, used by opendir and readdir.
        self.dir_entry_iterators: Dict[int, Any] = {}
        self.dir_entry_buffers: Dict[int, List[int]] = {}

        self.dir_fds: Dict[int, str] = {}

        # Record the relationship between fd and file path,
        # used by fcntl with command F_GETPATH.
        self.fd_path_map: Dict[int, str] = {}

        if sys.stdin.isatty():
            self.stdin_fd = sys.stdin.fileno()
        else:
            self.stdin_fd = None

        self.stdout_fd = sys.stdout.fileno()
        self.stderr_fd = sys.stderr.fileno()

    def set_working_dir(self, path: str):
        """Set current working directory.

        Raises:
            ValueError: If working directory is not valid.
        """
        if not path.startswith("/"):
            raise ValueError("Working directory must be an absolute path")

        self.working_dir = path

    def resolve_link(self, path: str) -> str:
        src_list = sorted(
            self.symbolic_links.keys(),
            key=lambda t: len(t),
            reverse=True,
        )
        for src in src_list:
            dst = self.symbolic_links[src]
            if path.startswith(src):
                path = path.replace(src, dst.rstrip("/"), 1)
                path = self.resolve_link(path)
                break
        return path

    def get_absolute_path(self, path: str) -> str:
        """Convert a path to absolute path."""
        if path == ".":
            path = self.working_dir
        elif path == "..":
            path = Path(self.working_dir).parent.as_posix()

        path = self.resolve_link(path)

        if not path.startswith("/"):
            relative_path = os.path.join(self.working_dir, path)
        else:
            relative_path = path

        return relative_path

    def get_real_path(self, path: str) -> str:
        """Mapping a path used by emulated programs to a real path.

        Raises:
            RuntimeError: If `rootfs_path` not set
            ValueError: If unsafe path pass in.
        """
        if not self.rootfs_path:
            raise RuntimeError("Root directory not set")

        absolute_path = self.get_absolute_path(path)

        forwarding_path = self.path_map.get(absolute_path)
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
        self.path_map[src_path] = dst_path

    def set_symbolic_link(self, src_path: str, dst_path: str):
        """Set a symbolic link to specified path."""
        self.symbolic_links[src_path] = dst_path

    def get_dir_fd(self, path: str) -> int:
        """Generate a virtual directory file descriptor.

        On Windows, unable to obtain a file descriptor for a directory.
        """
        for index in range(1, self.MAX_OPEN_DIR_NUM + 1):
            dir_fd = 10000 + index
            if dir_fd not in self.dir_fds:
                self.dir_fds[dir_fd] = self.get_absolute_path(path)
                return dir_fd
        return 0

    @staticmethod
    def construct_stat64(st: os.stat_result) -> Stat64:
        """Construct stat64 struct based on `stat_result`."""
        if sys.platform == "win32":
            block_size = 4096

            rdev = 0
            blocks = st.st_size // (block_size // 8) + 1
            blksize = block_size
        else:
            rdev = st.st_rdev
            blocks = st.st_blocks
            blksize = st.st_blksize

        if sys.platform == "darwin":
            flags = st.st_flags
        else:
            flags = 0

        atimespec = Timespec.from_time_ns(st.st_atime_ns)
        mtimespec = Timespec.from_time_ns(st.st_mtime_ns)
        ctimespec = Timespec.from_time_ns(st.st_ctime_ns)

        return Stat64(
            st_dev=st.st_dev,
            st_mode=st.st_mode,
            st_nlink=st.st_nlink,
            st_ino=st.st_ino,
            st_uid=st.st_uid,
            st_gid=st.st_gid,
            st_rdev=rdev,
            st_atimespec=atimespec,
            st_mtimespec=mtimespec,
            st_ctimespec=ctimespec,
            st_size=st.st_size,
            st_blocks=blocks,
            st_blksize=blksize,
            st_flags=flags,
        )

    @staticmethod
    def construct_dirent(entry: os.DirEntry) -> Dirent:
        """Construct dirent struct based on `DirEntry`."""
        return Dirent(
            d_ino=entry.inode(),
            d_seekoff=0,
            d_reclen=0,
            d_namlen=len(entry.name),
            d_type=(4 if entry.is_dir() else 0),
            d_name=entry.name.encode("utf-8"),
        )

    @staticmethod
    def construct_statfs64() -> Statfs64:
        """Construct statfs64 struct."""
        return Statfs64(
            f_bsize=4096,
            f_iosize=1048576,
            f_blocks=31218501,
            f_bfree=29460883,
            f_bavail=25672822,
            f_files=1248740040,
            f_ffree=1248421957,
            f_fsid=103095992327,
            f_owner=0,
            f_type=24,
            f_flags=343986176,
            f_fssubtype=0,
            f_fstypename=b"apfs",
            f_mntonname=b"/",
            f_mntfromname=b"/dev/disk0s1s1",
        )

    def check_fd(self, fd: int):
        """Check file descriptor.

        Raises:
            BadFileDescriptor: If bad file descriptor.
        """
        if fd in (self.stdin_fd, self.stdout_fd, self.stderr_fd):
            return

        if fd not in self.fd_path_map:
            raise FileBadDescriptor(f"Bad file descriptor: {fd}")

    @staticmethod
    def prepare_flags(flags: int) -> int:
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

    def _open(self, path: str, flags: int, mode: int) -> int:
        real_path = self.get_real_path(path)
        flags = self.prepare_flags(flags)

        if os.path.isdir(real_path):
            return self.get_dir_fd(path)

        fd = os.open(real_path, flags, mode)
        self.fd_path_map[fd] = self.get_absolute_path(path)
        return fd

    @staticmethod
    def _unlink(path: str):
        exist = os.path.exists(path)
        if not exist:
            raise FileNotExist(f"No such file: {path}")
        raise FilePermissionDenied(f"Banned file deletion: {path}")

    def _access(self, path: str, mode: int) -> bool:
        real_path = self.get_real_path(path)
        return os.access(real_path, mode)

    def _stat(self, path: str) -> bytes:
        real_path = self.get_real_path(path)
        struct = self.construct_stat64(os.stat(real_path))
        return struct2bytes(struct)

    def _rename(self, old: str, new: str):
        old = self.get_real_path(old)
        new = self.get_real_path(new)

        try:
            os.rename(old, new)
        except PermissionError:
            shutil.copy(old, new)

    def _mkdir(self, path: str, mode: int):
        real_path = self.get_real_path(path)
        os.mkdir(real_path, mode)

    @log_call
    def read(self, fd: int, size: int) -> bytes:
        self.check_fd(fd)
        return os.read(fd, size)

    @log_call
    def write(self, fd: int, buf: int, size: int) -> int:
        self.check_fd(fd)
        return os.write(fd, self.emu.read_bytes(buf, size))

    @log_call
    def open(self, path: str, flags: int, mode: int) -> int:
        return self._open(path, flags, mode)

    @log_call
    def close(self, fd: int) -> int:
        if fd in self.dir_fds:
            del self.dir_fds[fd]
            return 0

        self.check_fd(fd)

        del self.fd_path_map[fd]
        os.close(fd)
        return 0

    @log_call
    def unlink(self, path: str):
        self._unlink(path)

    @log_call
    def access(self, path: str, mode: int) -> bool:
        return self._access(path, mode)

    @log_call
    def readlink(self, path: str) -> Optional[str]:
        return self.symbolic_links.get(path)

    @log_call
    def lseek(self, fd: int, offset: int, whence: int) -> int:
        self.check_fd(fd)
        return os.lseek(fd, offset, whence)

    @log_call
    def stat(self, path: str) -> bytes:
        real_path = self.get_real_path(path)
        struct = self.construct_stat64(os.stat(real_path))
        return struct2bytes(struct)

    @log_call
    def fstat(self, fd: int) -> bytes:
        if fd in self.dir_fds:
            path = self.dir_fds[fd]
            return self.stat(path)

        self.check_fd(fd)

        struct = self.construct_stat64(os.fstat(fd))
        return struct2bytes(struct)

    @log_call
    def lstat(self, path: str) -> bytes:
        real_path = self.get_real_path(path)
        struct = self.construct_stat64(os.lstat(real_path))
        return struct2bytes(struct)

    @log_call
    def statfs(self, path: str) -> bytes:
        if path:
            pass
        struct = self.construct_statfs64()
        return struct2bytes(struct)

    @log_call
    def fstatfs(self, fd: int) -> bytes:
        if fd:
            pass
        struct = self.construct_statfs64()
        return struct2bytes(struct)

    @log_call
    def opendir(self, path: str) -> int:
        real_path = self.get_real_path(path)

        if not os.path.isdir(real_path):
            return 0

        if len(self.dir_fds) >= self.MAX_OPEN_DIR_NUM:
            return 0

        for index in range(1, self.MAX_OPEN_DIR_NUM + 1):
            dir_fd = self.get_dir_fd(path)
            if dir_fd:
                dir_ptr = self.emu.create_buffer(8)
                self.emu.write_u64(dir_ptr, dir_fd)

                self.dir_entry_iterators[dir_ptr] = os.scandir(real_path)
                self.dir_entry_buffers[dir_ptr] = []

                return dir_ptr

        return 0

    @log_call
    def readdir(self, dirp: int) -> int:
        if dirp not in self.dir_entry_iterators:
            return 0

        dir_entry_iterator = self.dir_entry_iterators[dirp]

        try:
            entry = next(dir_entry_iterator)
        except StopIteration:
            return 0

        dirent = self.construct_dirent(entry)

        size = ctypes.sizeof(Dirent)
        buf = self.emu.create_buffer(size)
        self.dir_entry_buffers[dirp].append(buf)

        self.emu.write_bytes(buf, struct2bytes(dirent))

        return buf

    @log_call
    def closedir(self, dirp: int) -> int:
        if dirp not in self.dir_entry_iterators:
            return -1

        dir_fd = self.emu.read_u64(dirp)
        self.emu.free(dirp)

        for buf in self.dir_entry_buffers[dirp]:
            self.emu.free(buf)

        del self.dir_fds[dir_fd]
        del self.dir_entry_iterators[dirp]
        del self.dir_entry_buffers[dirp]

        return 0

    @log_call
    def fsync(self, fd: int):
        self.check_fd(fd)

        os.fsync(fd)

    @log_call
    def rename(self, old: str, new: str):
        self._rename(old, new)

    @log_call
    def mkdir(self, path: str, mode: int):
        self._mkdir(path, mode)

    @log_call
    def rmdir(self, path: str):
        real_path = self.get_real_path(path)
        exist = os.path.exists(real_path)

        if not exist:
            raise FileNotExist(f"No such directory: {real_path}")

        raise FilePermissionDenied(f"Banned directory deletion: {path}")

    @log_call
    def pread(self, fd: int, size: int, offset: int) -> bytes:
        self.check_fd(fd)

        pos = os.lseek(fd, 0, os.SEEK_CUR)

        os.lseek(fd, offset, os.SEEK_SET)
        data = os.read(fd, size)

        os.lseek(fd, pos, os.SEEK_SET)

        return data

    @log_call
    def openat(self, dir_fd: int, path: str, flags: int, mode: int) -> int:
        if dir_fd in self.dir_fds:
            path = posixpath.join(self.dir_fds[dir_fd], path)

        return self._open(path, flags, mode)

    @log_call
    def faccessat(self, dir_fd: int, path: str, mode: int) -> bool:
        if dir_fd in self.dir_fds:
            path = posixpath.join(self.dir_fds[dir_fd], path)

        return self._access(path, mode)

    @log_call
    def fstatat(self, dir_fd: int, path: str) -> bytes:
        if dir_fd in self.dir_fds:
            path = posixpath.join(self.dir_fds[dir_fd], path)

        return self._stat(path)

    @log_call
    def unlinkat(self, dir_fd: int, path: str):
        if dir_fd in self.dir_fds:
            path = posixpath.join(self.dir_fds[dir_fd], path)

        return self._unlink(path)

    @log_call
    def renameat(self, src_fd: int, old: str, dst_fd: int, new: str):
        if src_fd in self.dir_fds:
            old = posixpath.join(self.dir_fds[src_fd], old)
        if dst_fd in self.dir_fds:
            new = posixpath.join(self.dir_fds[dst_fd], new)

        return self._rename(old, new)

    @log_call
    def mkdirat(self, dir_fd: int, path: str, mode: int):
        if dir_fd in self.dir_fds:
            path = posixpath.join(self.dir_fds[dir_fd], path)

        self._mkdir(path, mode)
