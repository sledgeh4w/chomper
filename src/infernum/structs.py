from dataclasses import dataclass
from typing import List, Optional


@dataclass
class Symbol:
    """The symbol object."""

    address: int
    name: str


@dataclass
class Module:
    """The module object."""

    base: int
    size: int
    name: str
    symbols: List[Symbol]


@dataclass
class Location:
    """An address and the module containing it."""

    address: int
    module: Optional[Module]

    def __repr__(self):
        if not self.module:
            return f"0x{self.address:x}"
        return f"0x{(self.address - self.module.base):x}@{self.module.name}"


@dataclass
class Pool:
    """Relate to a black of memory mapped on Unicorn."""

    address: int
    size: int
    blocks: List[int]

    @property
    def block_num(self) -> int:
        return len(self.blocks)

    @property
    def block_size(self) -> int:
        return self.size // self.block_num


@dataclass
class Arch:
    """The arch object."""

    name: str
    reg_size: int

    reg_sp: int
    reg_fp: int
    reg_lr: int
    reg_pc: int

    reg_args: List[int]
    reg_ret: int
