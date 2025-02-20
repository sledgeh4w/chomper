from abc import ABC, abstractmethod
from typing import Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from chomper.core import Chomper


class BaseOs(ABC):
    """Base operating system class."""

    def __init__(self, emu: "Chomper", rootfs_path: Optional[str] = None):
        self.emu = emu
        self.rootfs_path = rootfs_path

        self.preferences: dict
        self.device_info: dict

        self.proc_id: int
        self.proc_path: str

        self.executable_path: str

    @abstractmethod
    def initialize(self):
        """Initialize the environment."""
        pass
