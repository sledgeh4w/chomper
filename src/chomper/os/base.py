from abc import ABC, abstractmethod
from typing import Optional


class BaseOs(ABC):
    """Base operating system class."""

    def __init__(self, emu, rootfs_path: Optional[str] = None):
        self.emu = emu
        self.rootfs_path = rootfs_path

    @abstractmethod
    def initialize(self):
        """Initialize the environment."""
        pass
