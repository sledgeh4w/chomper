import os
from typing import Dict, List, Tuple, Optional

import lief
from lief.MachO import ARM64_RELOCATION

from chomper.base import BaseLoader
from chomper.types import Module, Symbol, Binding
from chomper.utils import aligned


class MachoLoader(BaseLoader):
    """The Mach-O file loader."""

    def _map_segments(self, binary: lief.MachO.Binary, module_base: int) -> int:
        """Map all segments into memory."""
        boundary = 0

        for segment in binary.segments:
            if not segment.virtual_size:
                continue

            seg_addr = module_base + segment.virtual_address

            map_addr = aligned(seg_addr, 1024) - (1024 if seg_addr % 1024 else 0)
            map_size = aligned(seg_addr - map_addr + segment.virtual_size, 1024)

            self.emu.uc.mem_map(map_addr, map_size)
            self.emu.uc.mem_write(
                seg_addr,
                bytes(segment.content),
            )

            boundary = max(boundary, map_addr + map_size)

        return boundary - module_base

    def _load_symbols(
        self,
        binary: lief.MachO.Binary,
        module_base: int,
    ) -> List[Symbol]:
        """Get all symbols in the module."""
        symbols = []

        lazy_bindings = self.get_lazy_bindings()
        lazy_binding_set = set()

        for symbol in binary.symbols:
            if symbol.value:
                symbol_name = str(symbol.name)
                symbol_address = module_base + symbol.value

                binding_name = symbol_name.replace("$VARIANT$armv81", "")

                # Lazy bind
                if lazy_bindings.get(binding_name):
                    # Avoid duplicate bind for special case like xx$VARIANT$armv81
                    if binding_name in lazy_binding_set and binding_name == symbol_name:
                        continue

                    for module, binding in lazy_bindings[binding_name]:
                        reloc_addr = symbol_address

                        if reloc_addr:
                            addr = module.base - module.image_base + binding.address

                            value = reloc_addr + binding.addend
                            value &= 0xFFFFFFFFFFFFFFFF

                            self.emu.write_pointer(addr, value)

                    lazy_binding_set.add(binding_name)

                symbol_struct = Symbol(
                    address=symbol_address,
                    name=symbol_name,
                )
                symbols.append(symbol_struct)

        return symbols

    def _get_symbol_reloc_addr(
        self,
        symbol_map: Dict[str, Symbol],
        symbol_name: str,
    ) -> Optional[int]:
        """Get the relocation address of a symbol."""
        reloc_addr = None

        if symbol_map.get(f"{symbol_name}$VARIANT$armv81"):
            if not self.emu.hooks.get(symbol_name):
                reloc_addr = symbol_map[f"{symbol_name}$VARIANT$armv81"].address

        elif symbol_name == "___chkstk_darwin":
            if symbol_map.get(f"_{symbol_name}"):
                reloc_addr = symbol_map[f"_{symbol_name}"].address

        elif symbol_map.get(symbol_name):
            reloc_addr = symbol_map[symbol_name].address

        elif symbol_map.get(f"__platform{symbol_name}"):
            reloc_addr = symbol_map[f"__platform{symbol_name}"].address

        return reloc_addr

    def _process_symbol_relocation(
        self,
        binary: lief.MachO.Binary,
        module_base: int,
        symbols: List[Symbol],
    ) -> List[Binding]:
        """Process relocations for symbols."""
        symbol_map = self.get_symbols()
        symbol_map.update({symbol.name: symbol for symbol in symbols})

        hooks_map: Dict = {}
        lazy_bindings = []

        for binding in binary.dyld_info.bindings:
            symbol = binding.symbol
            symbol_name = str(symbol.name)

            reloc_addr = self._get_symbol_reloc_addr(symbol_map, symbol_name)

            if not reloc_addr:
                lazy_binding = Binding(
                    symbol=symbol_name,
                    address=binding.address,
                    addend=binding.addend,
                )
                lazy_bindings.append(lazy_binding)

                # Hook imports
                if self.emu.hooks.get(symbol_name):
                    if not hooks_map.get(symbol_name):
                        reloc_addr = self.emu.create_buffer(self.emu.arch.addr_size)
                        hooks_map[symbol_name] = reloc_addr

                        self.emu.add_interceptor(
                            reloc_addr, self.emu.hooks[symbol_name]
                        )

                    else:
                        reloc_addr = hooks_map[symbol_name]

                    self.emu.logger.info(
                        'Hook import symbol "{}" at 0x{:x}'.format(
                            symbol_name, symbol.binding_info.address
                        )
                    )

                else:
                    # self.emu.add_hook(
                    #     reloc_addr,
                    #     self._missing_symbol_required_callback,
                    #     user_data={"symbol_name": symbol.name},
                    # )
                    continue

            if reloc_addr:
                value = (reloc_addr + binding.addend) & 0xFFFFFFFFFFFFFFFF
                self.emu.write_pointer(module_base + binding.address, value)

        return lazy_bindings

    def _process_relocation(
        self,
        binary: lief.MachO.Binary,
        module_base: int,
        symbols: List[Symbol],
    ):
        """Process relocations base on relocation table and symbol references."""
        blocks: List[Tuple[int, int]] = []

        begin = None
        end = None

        # Merge relocation records into blocks
        for segment in binary.segments:
            for relocation in segment.relocations:
                if relocation.type != ARM64_RELOCATION.SUBTRACTOR:
                    continue

                address = module_base + relocation.address

                if not begin:
                    begin = address

                if end and address != end:
                    blocks.append((begin, end))
                    begin = address

                end = address + self.emu.arch.addr_size

        # Read and write as blocks
        for begin, end in blocks:
            values = self.emu.read_array(begin, end)
            values = map(lambda v: module_base + v, values)

            self.emu.write_array(begin, values)

        return self._process_symbol_relocation(binary, module_base, symbols)

    def _get_init_array(self, binary: lief.MachO.Binary, module_base: int):
        """Get initialization functions in section `__mod_init_func`."""
        section = binary.get_section("__mod_init_func")
        if not section:
            return []

        begin = module_base + section.virtual_address
        end = begin + section.size
        values = self.emu.read_array(begin, end)

        return [addr for addr in values if addr]

    def load(
        self,
        module_base: int,
        module_file: str,
        trace_symbol_calls: bool = False,
    ) -> Module:
        """Load Mach-O executable file from path."""
        module_name = os.path.basename(module_file)
        self.emu.logger.info(f'Load module "{module_name}"')

        binary: lief.MachO.Binary = lief.parse(module_file)  # type: ignore

        segment_addresses = [t.virtual_address for t in binary.segments]

        # Make module memory distribution more compact
        image_base = aligned(min(segment_addresses), 1024)
        module_base -= image_base

        size = self._map_segments(binary, module_base)
        symbols = self._load_symbols(binary, module_base)

        self.add_symbol_hooks(symbols, trace_symbol_calls)

        lazy_bindings = self._process_relocation(binary, module_base, symbols)
        init_array = self._get_init_array(binary, module_base)

        return Module(
            base=module_base + image_base,
            size=size - image_base,
            name=module_name,
            symbols=symbols,
            init_array=init_array,
            image_base=image_base,
            lazy_bindings=lazy_bindings,
            binary=binary,
        )
