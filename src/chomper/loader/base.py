import os
from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum
from typing import Dict, List, Optional


class SymbolType(Enum):
    UNKNOWN = 0
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
class AddressRegion:
    base: int
    size: int

    @property
    def start(self) -> int:
        return self.base

    @property
    def end(self) -> int:
        return self.base + self.size


@dataclass
class Segment:
    name: str

    file_offset: int
    file_size: int

    virtual_address: int
    virtual_size: int


@dataclass
class DyldInfo:
    image_base: int
    image_header: int
    lazy_bindings: List[Binding]
    shared_segments: List[Segment]


class Module:
    def __init__(
        self,
        path: str,
        base: int,
        size: int,
        symbols: List[Symbol],
        map_regions: List[AddressRegion],
        init_array: List[int],
        dyld_info: Optional[DyldInfo] = None,
    ):
        self._path = path
        self._base = base
        self._size = size

        self._symbols = symbols
        self._map_regions = map_regions
        self._init_array = init_array

        self._dyld_info = dyld_info

    @property
    def path(self) -> str:
        return self._path

    @property
    def name(self) -> str:
        return os.path.basename(self._path)

    @property
    def base(self) -> int:
        return self._base

    @property
    def size(self) -> int:
        return self._size

    @property
    def symbols(self) -> List[Symbol]:
        return self._symbols

    @property
    def map_regions(self) -> List[AddressRegion]:
        return self._map_regions

    @property
    def init_array(self) -> List[int]:
        return self._init_array

    @property
    def has_dyld_info(self) -> bool:
        return bool(self._dyld_info)

    @property
    def dyld_info(self) -> DyldInfo:
        assert self._dyld_info
        return self._dyld_info

    def contains(self, address: int) -> bool:
        for region in self.map_regions:
            if region.start <= address < region.end:
                return True
        return False


class BaseLoader(ABC):
    """Executable file loader."""

    def __init__(self, emu):
        self.emu = emu

    def get_symbols(self) -> Dict[str, Symbol]:
        """Get loaded symbols."""
        symbol_map = {}

        for module in self.emu.modules:
            for symbol in module.symbols:
                symbol_map[symbol.name] = symbol

        return symbol_map

    def get_lazy_bindings(self) -> Dict[str, List]:
        """Get lazy bindings."""
        bindings: Dict[str, List] = {}

        for module in self.emu.modules:
            if not module.has_dyld_info:
                continue

            for binding in module.dyld_info.lazy_bindings:
                symbol_name = binding.symbol

                if not bindings.get(symbol_name):
                    bindings[symbol_name] = []

                bindings[symbol_name].append((module, binding))

        return bindings

    def add_symbol_hooks(self, symbols: List[Symbol], trace_symbol_calls: bool = False):
        """Add hooks to target symbols."""
        for symbol in symbols:
            if symbol.type == SymbolType.OTHER:
                continue

            # Trace symbol call
            if trace_symbol_calls:
                self.emu.add_hook(
                    symbol.address,
                    self.emu.trace_symbol_call_callback,
                    user_data={"symbol": symbol},
                )

            # Hook symbol
            if self.emu.hooks.get(symbol.name):
                self.emu.logger.info(
                    f'Hook export symbol "{symbol.name}" '
                    f"at {self.emu.debug_symbol(symbol.address)}"
                )

                self.emu.add_interceptor(symbol.address, self.emu.hooks[symbol.name])

    @abstractmethod
    def load(
        self,
        module_base: int,
        module_file: str,
        trace_symbol_calls: bool = False,
    ) -> Module:
        """Load executable file."""
        pass
