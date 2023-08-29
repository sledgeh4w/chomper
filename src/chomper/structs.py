from dataclasses import dataclass
from enum import Enum
from typing import List


class SymbolType(Enum):
    FUNC = 1
    OTHER = 2


@dataclass
class Symbol:
    address: int
    name: str
    type: SymbolType


@dataclass
class Module:
    base: int
    size: int
    name: str
    symbols: List[Symbol]


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
