from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Optional, TYPE_CHECKING

from .file import FileSystem

if TYPE_CHECKING:
    from chomper.core import Chomper


class BaseOs(ABC):
    """Base operating system class."""

    def __init__(self, emu: Chomper, rootfs_path: Optional[str] = None):
        self.emu = emu
        self.rootfs_path = rootfs_path

        self.file_system = FileSystem(
            emu=emu,
            rootfs_path=rootfs_path,
        )

        self.preferences: dict
        self.device_info: dict

        self.proc_id: int
        self.proc_path: str

        self.executable_path: str

    @property
    def errno(self) -> int:
        """Get the value of errno."""
        return 0

    @errno.setter
    def errno(self, value: int):
        """Set the value of errno."""
        pass

    @abstractmethod
    def initialize(self):
        """Initialize the environment."""
        pass
