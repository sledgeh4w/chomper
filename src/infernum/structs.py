from dataclasses import dataclass
from typing import Dict, List, Optional

from unicorn.unicorn import UC_HOOK_CODE_TYPE


@dataclass
class Symbol:
    address: int
    name: str
    type: str


@dataclass
class Module:

    base: int
    size: int
    name: str
    symbols: List[Symbol]


@dataclass
class Location:
    address: int
    module: Optional[Module]

    def __str__(self):
        """Show as ``0x1000@libxxx.so`` or ``0x10000``."""
        if not self.module:
            return f"0x{self.address:x}"

        offset = self.address - self.module.base

        return f"0x{offset:x}@{self.module.name}"


@dataclass
class MemoryPool:
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
    name: str
    reg_size: int

    reg_sp: int
    reg_fp: int
    reg_lr: int
    reg_pc: int

    reg_args: List[int]
    reg_ret: int

    symbol_hooks: Dict[str, UC_HOOK_CODE_TYPE]
