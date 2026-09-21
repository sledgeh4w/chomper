import os
import socket
from dataclasses import dataclass
from typing import Optional

from chomper.exceptions import SystemOperationFailed

from .device import DeviceFile
from .error import SyscallError


@dataclass
class FileProperty:
    path: str
    is_dir: bool
    readable: bool
    writeable: bool
    executable: bool


class FdEntry:
    path: str

    @staticmethod
    def _unsupported_error(operation: str) -> SystemOperationFailed:
        return SystemOperationFailed(f"Not support {operation}", SyscallError.EBADF)

    def read(self, size: int) -> bytes:
        raise self._unsupported_error("read")

    def write(self, data: bytes) -> int:
        raise self._unsupported_error("write")

    def seek(self, offset: int, whence: int) -> int:
        raise self._unsupported_error("seek")

    def close(self):
        pass


@dataclass
class FileEntry(FdEntry):
    real_fd: int
    path: str

    def read(self, size: int) -> bytes:
        return os.read(self.real_fd, size)

    def write(self, data: bytes) -> int:
        return os.write(self.real_fd, data)

    def seek(self, offset: int, whence: int):
        return os.lseek(self.real_fd, offset, whence)

    def close(self):
        try:
            os.close(self.real_fd)
        except OSError:
            pass


@dataclass
class DirEntry(FdEntry):
    path: str


@dataclass
class DeviceEntry(FdEntry):
    device: DeviceFile
    path: str

    def read(self, size: int) -> bytes:
        if not self.device.readable():
            raise self._unsupported_error("read")

        result = self.device.read(size)
        if result is None:
            return b""

        return result

    def write(self, data: bytes) -> int:
        if not self.device.writable():
            raise self._unsupported_error("write")

        result = self.device.write(data)
        if result is None:
            return 0

        return result

    def seek(self, offset: int, whence: int) -> int:
        if not self.device.seekable():
            raise self._unsupported_error("seek")

        return self.device.seek(offset, whence)


@dataclass
class SocketEntry(FdEntry):
    sock: Optional[socket.socket] = None
    family: int = 0
    path: str = ""

    @property
    def inner_sock(self) -> socket.socket:
        if self.sock is None:
            raise self._unsupported_error("socket")
        return self.sock

    def read(self, size: int) -> bytes:
        return self.inner_sock.recv(size)

    def write(self, data: bytes) -> int:
        return self.inner_sock.send(data)

    def close(self):
        if self.sock is not None:
            self.sock.close()
