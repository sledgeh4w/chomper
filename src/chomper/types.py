from dataclasses import dataclass
from enum import Enum
from typing import List, Optional

import lief


class SymbolType(Enum):
    FUNC = 1
    OTHER = 2


@dataclass
class Symbol:
    address: int
    name: str
    type: Optional[SymbolType] = None


@dataclass
class Binding:
    symbol: str
    address: int
    addend: int


@dataclass
class Module:
    base: int
    size: int
    name: str
    symbols: List[Symbol]
    init_array: Optional[List[int]] = None
    image_base: Optional[int] = None
    lazy_bindings: Optional[List[Binding]] = None
    binary: Optional[lief.MachO.Binary] = None
