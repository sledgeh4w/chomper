import os
from itertools import chain
from typing import Dict, List, Tuple, Optional

import lief
from lief.MachO import ARM64_RELOCATION, RelocationFixup

from chomper.utils import aligned

from .base import BaseLoader, Module, DyldInfo, Symbol, Binding, Segment, AddressRegion


_ARMV81_SYMBOL_POSTFIX = "$VARIANT$armv81"


class MachoLoader(BaseLoader):
    """The Mach-O file loader."""

    def _map_segments(
        self,
        binary: lief.MachO.Binary,
        module_base: int,
        dry_run: bool = False,
    ) -> List[AddressRegion]:
        """Map segments into memory."""
        regions: List[AddressRegion] = []

        for segment in binary.segments:
            if not segment.virtual_size or segment.name == "__PAGEZERO":
                continue

            seg_addr = module_base + segment.virtual_address

            map_addr = aligned(seg_addr, 1024) - (1024 if seg_addr % 1024 else 0)
            map_size = aligned(seg_addr - map_addr + segment.virtual_size, 1024)

            map_parts = []

            for region in regions:
                overlap_start = max(map_addr, region.base)
                overlap_end = min(map_addr + map_size, region.base + region.size)

                if overlap_start < overlap_end:
                    if map_addr < overlap_start:
                        start = map_addr
                        size = overlap_end - map_addr
                        map_parts.append((start, size))

                    if map_addr + map_size > overlap_end:
                        start = overlap_end
                        size = map_addr + map_size - overlap_end
                        map_parts.append((start, size))

                    map_addr = -1
                    break

            if map_addr >= 0:
                if not dry_run:
                    self.emu.uc.mem_map(map_addr, map_size)

                region = AddressRegion(
                    base=map_addr,
                    size=map_size,
                )
                regions.append(region)

            for map_addr, map_size in map_parts:
                if not dry_run:
                    self.emu.uc.mem_map(map_addr, map_size)

                region = AddressRegion(
                    base=map_addr,
                    size=map_size,
                )
                regions.append(region)

            if not dry_run:
                self.emu.uc.mem_write(
                    seg_addr,
                    bytes(segment.content),
                )

        return regions

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
        """Get symbols in the module."""
        symbols = []

        lazy_bindings = self.get_lazy_bindings()
        lazy_binding_set = set()

        for symbol in binary.symbols:
            if not symbol.value:
                continue

            symbol_name = str(symbol.name)
            symbol_address = module_base + symbol.value

            binding_name = self._get_binding_name(symbol_name)

            # Lazy bind
            if lazy_bindings.get(binding_name):
                # Avoid duplicate bind
                if binding_name in lazy_binding_set and binding_name == symbol_name:
                    continue

                for module, binding in lazy_bindings[binding_name]:
                    reloc_addr = symbol_address

                    if reloc_addr:
                        addr = (
                            module.base - module.dyld_info.image_base + binding.address
                        )

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
        symbol = None

        name_with_arch = f"{symbol_name}{_ARMV81_SYMBOL_POSTFIX}"
        name_with_platform = f"__platform{symbol_name}"

        if symbol_map.get(name_with_arch):
            if not self.emu.hooks.get(symbol_name):
                symbol = symbol_map[name_with_arch]
        elif symbol_name == "___chkstk_darwin":
            if symbol_map.get(f"_{symbol_name}"):
                symbol = symbol_map[f"_{symbol_name}"]
        elif symbol_map.get(symbol_name):
            symbol = symbol_map[symbol_name]
        elif symbol_map.get(name_with_platform):
            symbol = symbol_map[name_with_platform]

        return symbol.address if symbol else None

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
            values = self.emu.read_array(begin, end, signed=True)
            values = map(lambda v: module_base + v, values)

            self.emu.write_array(begin, values, signed=True)

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

    @staticmethod
    def _get_minium_seg_addr(binary: lief.MachO.Binary) -> int:
        addr_list = []

        for segment in binary.segments:
            if not segment.virtual_size or segment.name == "__PAGEZERO":
                continue

            addr_list.append(segment.virtual_address)

        return min(addr_list)

    @staticmethod
    def _has_overlap(
        regions: List[AddressRegion],
        other_regions: List[AddressRegion],
    ) -> bool:
        """Check if the two address regions overlap."""
        for region1 in regions:
            for region2 in other_regions:
                if region1.start < region2.end and region2.start < region1.end:
                    return True
        return False

    def _find_load_base(self, binary: lief.MachO.Binary) -> int:
        """Try to find the lowest address to load a module."""
        mapped_regions = list(
            chain.from_iterable((module.map_regions for module in self.emu.modules))
        )

        minium_seg_addr = self._get_minium_seg_addr(binary)
        regions = self._map_segments(
            binary,
            module_base=-minium_seg_addr,
            dry_run=True,
        )

        for mapped_region in mapped_regions:
            offset = aligned(mapped_region.end, 1024 * 1024)

            regions_with_offset = [
                AddressRegion(
                    base=region.base + offset,
                    size=region.size,
                )
                for region in regions
            ]

            if not self._has_overlap(mapped_regions, regions_with_offset):
                return offset

        return max([region.end for region in mapped_regions])

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

        if self.emu.modules:
            # Make the segments of different modules are interleaved
            module_base = self._find_load_base(binary)

        # Make module memory distribution more compact
        module_base -= aligned(self._get_minium_seg_addr(binary), 1024)

        map_regions = self._map_segments(binary, module_base)
        size = (map_regions[-1].end - module_base) if map_regions else 0

        symbols = self._load_symbols(binary, module_base)
        symbols = self._process_symbol_aliases(symbols)

        self.add_symbol_hooks(symbols, trace_symbol_calls)

        lazy_bindings = self._process_relocation(binary, module_base, symbols)
        init_array = self._get_init_array(binary, module_base)

        # Different dyld cache modules may share the same segment
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

        text_segment = binary.get_segment("__TEXT")

        image_base = binary.imagebase
        image_header = module_base + text_segment.virtual_address

        dyld_info = DyldInfo(
            image_base=image_base,
            image_header=image_header,
            lazy_bindings=lazy_bindings,
            shared_segments=shared_segments,
        )

        return Module(
            path=module_file,
            base=module_base + image_base,
            size=size - image_base,
            symbols=symbols,
            map_regions=map_regions,
            init_array=init_array,
            dyld_info=dyld_info,
        )
