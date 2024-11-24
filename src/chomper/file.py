import os
import sys
from os import stat_result
from typing import Optional

from .structs import Stat64, Timespec
from .utils import struct2bytes, log_call, safe_join


class FileManager:
    """Provide file access interface.

    All system calls related to files from emulated programs must access real files
    through this class.

    Args:
        emu: The emulator instance.
        rootfs_path: As the root directory of the mapping file system.
    """

    def __init__(self, emu, rootfs_path: Optional[str]):
        self.emu = emu

        self.rootfs_path = rootfs_path
        self.working_dir = ""

    def set_working_dir(self, path: str):
        """Set current working directory.

        Raises:
            ValueError: If working directory is not valid.
        """
        if not path.startswith("/"):
            raise ValueError("Working directory must be an absolute path")

        self.working_dir = path

    def get_real_path(self, path: str) -> str:
        """Mapping a path used by emulated programs to a real path.

        Raises:
            RuntimeError: If `rootfs_path` not set
            ValueError: If unsafe path pass in.
        """
        if not self.rootfs_path:
            raise RuntimeError("Root directory not set")

        if not path.startswith("/"):
            path = os.path.join(self.working_dir, path)

        full_path = safe_join(self.rootfs_path, path[1:])
        if full_path is None:
            raise ValueError(f"Unsafe path: {path}")

        return full_path

    @staticmethod
    def construct_stat64(st: stat_result) -> Stat64:
        """Construct stat64 struct based on stat_result.

        Compatible with multiple host platforms.
        """
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
    def read(self, fd: int, size: int) -> bytes:
        return os.read(fd, size)

    @log_call
    def open(self, path: str, flags: int) -> int:
        real_path = self.get_real_path(path)
        return os.open(real_path, flags)

    @log_call
    def close(self, fd: int):
        os.close(fd)
