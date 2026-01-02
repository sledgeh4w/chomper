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
class MachoInfo:
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
        regions: List[AddressRegion],
        init_array: List[int],
        macho_info: Optional[MachoInfo] = None,
    ):
        self._path = path
        self._base = base
        self._size = size

        self._symbols = symbols
        self._regions = regions
        self._init_array = init_array

        self._macho_info = macho_info

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
    def regions(self) -> List[AddressRegion]:
        return self._regions

    @property
    def init_array(self) -> List[int]:
        return self._init_array

    @property
    def is_macho(self) -> bool:
        return bool(self._macho_info)

    @property
    def macho_info(self) -> MachoInfo:
        assert self._macho_info
        return self._macho_info

    def contains(self, address: int) -> bool:
        for region in self.regions:
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
            if not module.is_macho:
                continue

            for binding in module.macho_info.lazy_bindings:
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
        module_file: str,
        module_base: Optional[int] = None,
        trace_symbol_calls: bool = False,
    ) -> Module:
        """Load executable file."""
        pass
