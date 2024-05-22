from abc import ABC, abstractmethod
from typing import Dict, List, Optional

from .types import Module, Symbol, SymbolType


class BaseOs(ABC):
    """Base operating system class."""

    def __init__(self, emu, rootfs_path: Optional[str] = None):
        self.emu = emu
        self.rootfs_path = rootfs_path

    @abstractmethod
    def initialize(self):
        """Initialize the environment."""
        pass


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
                self.emu.logger.info(
                    'Hook export symbol "{}" at {}'.format(
                        symbol.name,
                        self.emu.debug_symbol(symbol.address),
                    )
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
