import os
from typing import Dict, List, Tuple, Optional

import lief
from lief.MachO import ARM64_RELOCATION, RelocationFixup

from chomper.utils import aligned

from .base import BaseLoader, Module, Symbol, Binding, Segment


_ARMV81_SYMBOL_POSTFIX = "$VARIANT$armv81"


class MachoLoader(BaseLoader):
    """The Mach-O file loader."""

    def _map_segments(self, binary: lief.MachO.Binary, module_base: int) -> int:
        """Map all segments into memory."""
        mapped: List[Tuple[int, int]] = []
        boundary = 0

        for segment in binary.segments:
            if not segment.virtual_size or segment.name == "__PAGEZERO":
                continue

            seg_addr = module_base + segment.virtual_address

            map_addr = aligned(seg_addr, 1024) - (1024 if seg_addr % 1024 else 0)
            map_size = aligned(seg_addr - map_addr + segment.virtual_size, 1024)

            map_parts = []

            for mapped_start, mapped_end in mapped:
                overlap_start = max(map_addr, mapped_start)
                overlap_end = min(map_addr + map_size, mapped_end)

                if overlap_start < overlap_end:
                    if map_addr < overlap_start:
                        map_parts.append((map_addr, overlap_end - map_addr))
                    if map_addr + map_size > overlap_end:
                        map_parts.append(
                            (overlap_end, map_addr + map_size - overlap_end)
                        )
                    map_addr = -1
                    break

            if map_addr > 0:
                self.emu.uc.mem_map(map_addr, map_size)

            for map_addr, map_size in map_parts:
                self.emu.uc.mem_map(map_addr, map_size)

            self.emu.uc.mem_write(
                seg_addr,
                bytes(segment.content),
            )

            mapped.append((map_addr, map_addr + map_size))
            boundary = max(boundary, map_addr + map_size)

        return boundary - module_base

    @staticmethod
    def _get_binding_name(symbol_name: str) -> str:
        if symbol_name == "____chkstk_darwin":
            return symbol_name.replace("_", "", 1)

        return symbol_name.replace(_ARMV81_SYMBOL_POSTFIX, "")

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

                binding_name = self._get_binding_name(symbol_name)

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

                if binding_name != symbol_name:
                    symbol_struct = Symbol(
                        address=symbol_address,
                        name=binding_name,
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

        if symbol_map.get(f"{symbol_name}{_ARMV81_SYMBOL_POSTFIX}"):
            if not self.emu.hooks.get(symbol_name):
                reloc_addr = symbol_map[
                    f"{symbol_name}{_ARMV81_SYMBOL_POSTFIX}"
                ].address
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

        for binding in binary.bindings:
            if binding.segment.name in ("__TEXT",):
                continue

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
                        f'Hook import symbol "{symbol_name}" at {hex(binding.address)}'
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
                if relocation.type == ARM64_RELOCATION.SUBTRACTOR:
                    address = module_base + relocation.address

                    if not begin:
                        begin = address

                    if end and address != end:
                        blocks.append((begin, end))
                        begin = address

                    end = address + self.emu.arch.addr_size
                elif isinstance(relocation, RelocationFixup):
                    self.emu.write_pointer(
                        module_base + relocation.address,
                        module_base + relocation.target,
                    )

        if begin and end:
            blocks.append((begin, end))

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

    @staticmethod
    def _process_symbol_aliases(symbols: List[Symbol]) -> List[Symbol]:
        """Reset symbol addresses based on actual aliases."""
        symbol_map = {symbol.name: symbol for symbol in symbols}

        for name, symbol in symbol_map.items():
            if name.endswith(_ARMV81_SYMBOL_POSTFIX):
                export_name = name.replace(_ARMV81_SYMBOL_POSTFIX, "")
                if export_name not in symbol_map:
                    continue
                symbol_map[export_name].address = symbol.address

        return list(symbol_map.values())

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
        module_base -= aligned(min(segment_addresses), 1024)
        image_base = binary.imagebase

        size = self._map_segments(binary, module_base)
        symbols = self._load_symbols(binary, module_base)

        symbols = self._process_symbol_aliases(symbols)

        self.add_symbol_hooks(symbols, trace_symbol_calls)

        lazy_bindings = self._process_relocation(binary, module_base, symbols)
        init_array = self._get_init_array(binary, module_base)

        shared_segment_names = ("__OBJC_RO",)

        shared_segments = []
        for segment in binary.segments:
            if segment.name not in shared_segment_names:
                continue
            shared_segment = Segment(
                name=str(segment.name),
                file_offset=segment.file_offset,
                file_size=segment.file_size,
                virtual_address=segment.virtual_address,
                virtual_size=segment.virtual_size,
            )
            shared_segments.append(shared_segment)

        return Module(
            base=module_base + image_base,
            size=size - image_base,
            name=module_name,
            symbols=symbols,
            init_array=init_array,
            image_base=image_base,
            lazy_bindings=lazy_bindings,
            shared_segments=shared_segments,
            binary=binary,
        )
