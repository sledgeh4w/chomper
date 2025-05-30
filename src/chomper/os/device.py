import os
from abc import ABC
from typing import Optional


class DeviceFile(ABC):
    """Virtual device file."""

    READABLE: bool = False
    WRITEABLE: bool = False
    SEEKABLE: bool = False

    def readable(self) -> bool:
        return self.READABLE

    def writable(self) -> bool:
        return self.WRITEABLE

    def seekable(self) -> bool:
        return self.SEEKABLE

    def read(self, size: int = -1) -> Optional[bytes]:
        pass

    def write(self, data) -> Optional[int]:
        pass

    def seek(self, offset: int, whence: int = os.SEEK_SET):
        pass


class NullDevice(DeviceFile):
    READABLE = True
    WRITEABLE = True
    SEEKABLE = False

    def read(self, size: int = -1) -> Optional[bytes]:
        return b""

    def write(self, data) -> Optional[int]:
        return len(data)


class RandomDevice(DeviceFile):
    READABLE = True
    WRITEABLE = False
    SEEKABLE = False

    def read(self, size: int = -1) -> Optional[bytes]:
        if size < 0:
            size = 1024
        return os.urandom(size)


class UrandomDevice(RandomDevice):
    pass
