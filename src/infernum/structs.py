from dataclasses import dataclass
from typing import List, Optional


@dataclass
class Symbol:
    """The symbol struct."""

    address: int
    name: str


@dataclass
class Module:
    """The module struct."""

    base: int
    size: int
    name: str
    symbols: List[Symbol]


@dataclass
class Location:
    """The location struct."""

    address: int
    module: Optional[Module]

    def __repr__(self):
        if not self.module:
            return f"0x{self.address}"
        return f"0x{(self.address - self.module.base):x}@{self.module.name}"


@dataclass
class BackTrace:
    """The back trace struct."""

    locations: List[Location]

    def __repr__(self):
        return str(self.locations)


@dataclass
class Pool:
    """The memory pool struct.`"""

    address: int
    size: int
    blocks: List[int]

    @property
    def block_num(self) -> int:
        return len(self.blocks)

    @property
    def block_size(self) -> int:
        return self.size // self.block_num
