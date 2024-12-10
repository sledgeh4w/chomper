import ctypes
import os
import sys
from os import stat_result, DirEntry
from typing import Any, Dict, List, Optional

from .log import get_logger
from .structs import Stat64, Timespec, Dirent
from .utils import struct2bytes, log_call, safe_join


class FileManager:
    """Provide file access interface.

    All system calls related to files from emulated programs must access real files
    through this class.

    Args:
        emu: The emulator instance.
        rootfs_path: As the root directory of the mapping file system.
    """

    MAX_OPEN_DIR_NUM = 10000

    def __init__(self, emu, rootfs_path: Optional[str]):
        self.emu = emu
        self.logger = get_logger(__name__)

        self.rootfs_path = rootfs_path
        self.working_dir = ""

        self.path_map: Dict[str, str] = {}

        self.symbolic_links: Dict[str, str] = {}

        self.dir_ptrs: Dict[int, Any] = {}
        self.dir_entry_buffers: Dict[int, List[int]] = {}

    def set_working_dir(self, path: str):
        """Set current working directory.

        Raises:
            ValueError: If working directory is not valid.
        """
        if not path.startswith("/"):
            raise ValueError("Working directory must be an absolute path")

        self.working_dir = path

    def resolve_link(self, path: str) -> str:
        for src, dst in self.symbolic_links.items():
            if path.startswith(src):
                path = path.replace(src, dst.rstrip("/"), 1)
                path = self.resolve_link(path)
                break
        return path

    def get_real_path(self, path: str) -> str:
        """Mapping a path used by emulated programs to a real path.

        Raises:
            RuntimeError: If `rootfs_path` not set
            ValueError: If unsafe path pass in.
        """
        if not self.rootfs_path:
            raise RuntimeError("Root directory not set")

        path = self.resolve_link(path)

        forwarding_path = self.path_map.get(path)
        if forwarding_path:
            self.logger.info(f"Forward path '{path}' -> '{forwarding_path}'")
            return forwarding_path

        if not path.startswith("/"):
            relative_path = os.path.join(self.working_dir, path)
        else:
            relative_path = path

        full_path = safe_join(self.rootfs_path, relative_path[1:])
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

    @staticmethod
    def construct_stat64(st: stat_result) -> Stat64:
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
    def construct_dirent(entry: DirEntry) -> Dirent:
        """Construct dirent struct based on `DirEntry`."""
        return Dirent(
            d_ino=entry.inode(),
            d_seekoff=0,
            d_reclen=0,
            d_namlen=len(entry.name),
            d_type=0,
            d_name=entry.name.encode("utf-8"),
        )

    @log_call
    def read(self, fd: int, size: int) -> bytes:
        return os.read(fd, size)

    @log_call
    def open(self, path: str, flags: int) -> int:
        real_path = self.get_real_path(path)
        return os.open(real_path, flags)

    @log_call
    def close(self, fd: int) -> int:
        os.close(fd)
        return 0

    @log_call
    def access(self, path: str, mode: int) -> int:
        real_path = self.get_real_path(path)
        return os.access(real_path, mode)

    @log_call
    def readlink(self, path: str) -> Optional[str]:
        return self.symbolic_links.get(path)

    @log_call
    def lseek(self, fd: int, offset: int, whence: int) -> int:
        return os.lseek(fd, offset, whence)

    @log_call
    def stat(self, path: str) -> bytes:
        real_path = self.get_real_path(path)
        struct = self.construct_stat64(os.stat(real_path))
        return struct2bytes(struct)

    @log_call
    def fstat(self, fd: int) -> bytes:
        struct = self.construct_stat64(os.fstat(fd))
        return struct2bytes(struct)

    @log_call
    def lstat(self, path: str) -> bytes:
        struct = self.construct_stat64(os.lstat(path))
        return struct2bytes(struct)

    @log_call
    def opendir(self, path: str) -> int:
        real_path = self.get_real_path(path)

        if not os.path.isdir(real_path):
            return 0

        if len(self.dir_ptrs) >= self.MAX_OPEN_DIR_NUM:
            return 0

        for index in range(1, self.MAX_OPEN_DIR_NUM + 1):
            if index not in self.dir_ptrs:
                dir_ptr = os.scandir(real_path)
                self.dir_ptrs[index] = dir_ptr
                self.dir_entry_buffers[index] = []
                return index

        return 0

    @log_call
    def readdir(self, dirp: int) -> int:
        if dirp not in self.dir_ptrs:
            return 0

        dir_ptr = self.dir_ptrs[dirp]

        try:
            entry = next(dir_ptr)
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
        if dirp not in self.dir_ptrs:
            return -1

        for buf in self.dir_entry_buffers[dirp]:
            self.emu.free(buf)

        del self.dir_ptrs[dirp]
        del self.dir_entry_buffers[dirp]

        return 0
