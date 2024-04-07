from dataclasses import dataclass
from enum import Enum
from typing import Dict, List, Optional, TypeVar

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


class FuncHooks:
    @classmethod
    def register(cls, emu):
        raise NotImplementedError

    @classmethod
    def hook_retval(cls, retval):
        def decorator(uc, address, size, user_data):
            return retval

        return decorator


class SyscallHandler:
    @classmethod
    def register(cls, emu):
        raise NotImplementedError


class BaseLoader:
    """Executable file loader."""

    def __init__(self, emu):
        self.emu = emu

    def get_loaded_symbols(self) -> Dict[str, Symbol]:
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
            for binding in module.lazy_bindings:
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
                message = 'Hook export symbol "{}" at {}'.format(
                    symbol.name,
                    self.emu.debug_symbol(symbol.address),
                )
                self.emu.logger.info(message)

                self.emu.add_interceptor(symbol.address, self.emu.hooks[symbol.name])

    def load(
        self,
        module_base: int,
        module_file: str,
        trace_symbol_calls: bool = False,
    ) -> Module:
        """Load executable file."""
        raise NotImplementedError


class Options:
    pass


OptionsTV = TypeVar("OptionsTV", bound=Options)


class BaseOs:
    def __init__(
        self,
        emu,
        rootfs_path: Optional[str] = None,
        options: Optional[OptionsTV] = None,
    ):
        self.emu = emu
        self.rootfs_path = rootfs_path
        self.options = options

    def initialize(self):
        pass
