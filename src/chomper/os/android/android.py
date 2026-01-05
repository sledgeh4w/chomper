import ctypes
import os
import random
import sys
import time
from typing import Optional

from chomper.arch import arm64_arch
from chomper.const import TLS_ADDRESS
from chomper.exceptions import SystemOperationFailed
from chomper.loader import ELFLoader
from chomper.os.device import NullDevice, RandomDevice, UrandomDevice
from chomper.os.posix import PosixOs, SyscallError
from chomper.utils import log_call, struct_to_bytes, to_unsigned

from .hooks import get_hooks
from .structs import Dirent, Stat64, Timespec
from .syscall import get_syscall_handlers, get_syscall_names


ENVIRON_VARIABLES = """"""

# Virtual device files
DEVICES_FILES = {
    "/dev/null": NullDevice,
    "/dev/random": RandomDevice,
    "/dev/urandom": UrandomDevice,
}


class AndroidOs(PosixOs):
    """Provide Android environment."""

    AT_FDCWD = to_unsigned(-100, size=4)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.loader = ELFLoader(self.emu)

        self.uid = random.randint(10000, 20000)
        self.gid = self.uid

        self.pid = random.randint(1000, 2000)

        self.tid = self.pid

        # Used by `getdents`
        self._dir_read_offset = {}

    def get_errno(self) -> int:
        """Get the `errno`."""
        return self.emu.read_s32(TLS_ADDRESS + 0x10)

    def set_errno(self, value: int):
        """Set the `errno`."""
        self.emu.write_s32(TLS_ADDRESS + 0x10, value)

    @staticmethod
    def _create_stat(st: os.stat_result) -> bytes:
        if sys.platform == "win32":
            block_size = 4096

            rdev = 0
            blocks = st.st_size // (block_size // 8) + 1
            blksize = block_size
        else:
            rdev = st.st_rdev
            blocks = st.st_blocks
            blksize = st.st_blksize

        atim = Timespec.from_time_ns(st.st_atime_ns)
        mtim = Timespec.from_time_ns(st.st_mtime_ns)
        ctim = Timespec.from_time_ns(st.st_ctime_ns)

        st = Stat64(
            st_dev=st.st_dev,
            st_ino=st.st_ino,
            st_mode=st.st_mode,
            st_nlink=st.st_nlink,
            st_uid=st.st_uid,
            st_gid=st.st_gid,
            st_rdev=rdev,
            st_size=st.st_size,
            st_blksize=blksize,
            st_blocks=blocks,
            st_atim=atim,
            st_mtim=mtim,
            st_ctim=ctim,
        )

        return struct_to_bytes(st)

    @staticmethod
    def _create_device_stat() -> bytes:
        atim = Timespec.from_time_ns(0)
        mtim = Timespec.from_time_ns(0)
        ctim = Timespec.from_time_ns(0)

        st = Stat64(
            st_dev=0,
            st_ino=0,
            st_mode=0x2000,
            st_nlink=0,
            st_uid=0,
            st_gid=0,
            st_rdev=0,
            st_size=0,
            st_blksize=0,
            st_blocks=0,
            st_atim=atim,
            st_mtim=mtim,
            st_ctim=ctim,
        )

        return struct_to_bytes(st)

    @log_call
    def getdents(self, fd: int) -> Optional[bytes]:
        if not self._is_dir_fd(fd):
            raise SystemOperationFailed(f"Not a directory: {fd}", SyscallError.ENOTDIR)

        path = self._get_fd_path(fd)
        real_path = self._get_real_path(path)

        if fd in self._dir_read_offset:
            offset = self._dir_read_offset[fd]
        else:
            offset = 0

        dir_entries = list(os.scandir(real_path))
        if offset >= len(dir_entries):
            if fd in self._dir_read_offset:
                del self._dir_read_offset[fd]
            return None

        dir_entry = dir_entries[offset]
        self._dir_read_offset[fd] = offset + 1

        # On 64-bit architectures, dirent and linux_dirent64 are the same.
        st = Dirent(
            d_ino=dir_entry.inode(),
            d_seekoff=0,
            d_reclen=ctypes.sizeof(Dirent),
            d_type=(4 if dir_entry.is_dir() else 0),
            d_name=dir_entry.name.encode("utf-8"),
        )
        return struct_to_bytes(st)

    @log_call
    def clock_gettime(self) -> bytes:
        time_ns = time.time_ns()
        st = Timespec.from_time_ns(time_ns)
        return struct_to_bytes(st)

    @log_call
    def clock_getres(self) -> bytes:
        st = Timespec(
            tv_sec=0,
            tv_nsec=1,
        )
        return struct_to_bytes(st)

    def _setup_tls(self):
        """Initialize thread local storage (TLS)."""
        if self.emu.arch == arm64_arch:
            thread_ptr = self.emu.create_buffer(0x18)
            errno_ptr = self.emu.create_buffer(0x4)

            self.emu.write_u32(thread_ptr + 0x10, self.tid)
            self.emu.write_u32(thread_ptr + 0x14, self.pid)

            self.emu.write_pointer(TLS_ADDRESS + 0x8, thread_ptr)
            self.emu.write_pointer(TLS_ADDRESS + 0x10, errno_ptr)

    def _enable_libc(self) -> bool:
        """Attempt to load libc."""
        if not self.rootfs_path:
            return False

        if self.emu.arch == arm64_arch:
            lib_dir = "system/lib64"
        else:
            lib_dir = "system/lib"

        libc_path = os.path.join(self.rootfs_path, lib_dir, "libc.so")

        if not os.path.exists(libc_path):
            return False

        self.emu.load_module(libc_path, exec_init_array=False)
        return True

    def _create_fp(self, fd: int, mode: str, unbuffered: bool = False) -> int:
        """Wrap file descriptor to file object by calling `fdopen`."""
        with self.emu.mem_context() as ctx:
            mode_ptr = ctx.create_string(mode)

            fp = self.emu.call_symbol("fdopen", fd, mode_ptr)
            flags = self.emu.read_u32(fp + 16)

            if unbuffered:
                flags |= 0x2

            self.emu.write_u32(fp + 16, flags)
            return fp

    def _setup_standard_io(self):
        """Convert standard I/O file descriptors to FILE objects and assign them
        to target symbols.
        """
        stdin = self.emu.get_symbol("stdin")
        stdout = self.emu.get_symbol("stdout")
        stderr = self.emu.get_symbol("stderr")

        if self._stdin_fd:
            stdin_fp = self._create_fp(self._stdin_fd, "r")
            self.emu.write_pointer(stdin.address, stdin_fp)

        stdout_fp = self._create_fp(self._stdout_fd, "w", unbuffered=True)
        self.emu.write_pointer(stdout.address, stdout_fp)

        stderr_fp = self._create_fp(self._stderr_fd, "w", unbuffered=True)
        self.emu.write_pointer(stderr.address, stderr_fp)

    def _setup_environ(self):
        """Initialize global variable `environ`."""
        environ_buf = self.emu.create_buffer(8)
        self.emu.write_pointer(environ_buf, self._create_environ(ENVIRON_VARIABLES))

        environ = self.emu.get_symbol("environ")
        self.emu.write_pointer(environ.address, environ_buf)

    def initialize(self):
        # Setup hooks
        self.emu.hooks.update(get_hooks())

        # Setup syscall handles
        if self.emu.arch == arm64_arch:
            # Only compatible with arm64 now
            self.emu.syscall_handlers.update(get_syscall_handlers())
            self.emu.syscall_names.update(get_syscall_names())

        # Mount virtual device files
        self.mount_devices(DEVICES_FILES)

        self._setup_tls()

        if self._enable_libc():
            self._setup_standard_io()
            self._setup_environ()
