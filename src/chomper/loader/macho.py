import os
from itertools import chain
from typing import Dict, List, Tuple

import lief
from lief.MachO import ARM64_RELOCATION, RelocationFixup

from chomper.utils import aligned

from .base import BaseLoader, Module, DyldInfo, Symbol, Binding, Segment, AddressRegion


class MachoLoader(BaseLoader):
    """The Mach-O file loader."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self._symbol_aliases = {}
        self._init_symbol_aliases()

    def _init_symbol_aliases(self):
        symbol_aliases = {
            "____chkstk_darwin": "___chkstk_darwin",
        }

        platform_funcs = [
            "_bzero",
            "_memccpy",
            "_memchr",
            "_memcmp",
            "_memmove",
            "_memset",
            "_memset_pattern16",
            "_memset_pattern4",
            "_memset_pattern8",
            "_strchr",
            "_strcmp",
            "_strcpy",
            "_strlcat",
            "_strlcpy",
            "_strlen",
            "_strncmp",
            "_strncpy",
            "_strnlen",
            "_strstr",
        ]

        for func in platform_funcs:
            symbol_aliases[f"__platform{func}"] = func

        self._symbol_aliases.update(symbol_aliases)

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

            address = aligned(seg_addr, 1024) - (1024 if seg_addr % 1024 else 0)
            size = aligned(seg_addr - address + segment.virtual_size, 1024)

            blocks = []

            for region in regions:
                overlap_start = max(address, region.base)
                overlap_end = min(address + size, region.base + region.size)

                if overlap_start < overlap_end:
                    if address < overlap_start:
                        start = address
                        size = overlap_end - address
                        blocks.append((start, size))

                    if address + size > overlap_end:
                        start = overlap_end
                        size = address + size - overlap_end
                        blocks.append((start, size))

                    address = -1
                    break

            # No overlap
            if address >= 0:
                blocks.append((address, size))

            for address, size in blocks:
                if not dry_run:
                    self.emu.uc.mem_map(address, size)

                region = AddressRegion(
                    base=address,
                    size=size,
                )
                regions.append(region)

            if not dry_run:
                self.emu.uc.mem_write(
                    seg_addr,
                    bytes(segment.content),
                )

        return regions

    def _get_binding_name(self, symbol_name: str) -> str:
        if symbol_name in self._symbol_aliases:
            return self._symbol_aliases[symbol_name]
        elif symbol_name.endswith("$VARIANT$armv81"):
            return symbol_name.replace("$VARIANT$armv81", "")

        return symbol_name

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
                        address = (
                            module.base - module.dyld_info.image_base + binding.address
                        )

                        value = reloc_addr + binding.addend
                        value &= 0xFFFFFFFFFFFFFFFF

                        self.emu.write_pointer(address, value)

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

            if symbol_name in symbol_map:
                reloc_addr = symbol_map[symbol_name].address
            else:
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

        return [value for value in values if value]

    def _process_symbol_aliases(self, symbols: List[Symbol]) -> List[Symbol]:
        """Reset symbol addresses based on aliases."""
        symbol_map = {symbol.name: symbol for symbol in symbols}

        for name, symbol in symbol_map.items():
            export_name = self._get_binding_name(name)
            if export_name not in symbol_map:
                continue

            symbol_map[export_name].address = symbol.address

        return list(symbol_map.values())

    @staticmethod
    def _get_lowest_address(binary: lief.MachO.Binary) -> int:
        addresses = []

        for segment in binary.segments:
            if not segment.virtual_size or segment.name == "__PAGEZERO":
                continue

            addresses.append(segment.virtual_address)

        return min(addresses)

    @staticmethod
    def _has_regions_overlap(
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
        """Find the lowest address to load a module."""
        mapped_regions = list(
            chain.from_iterable((module.regions for module in self.emu.modules))
        )
        regions = self._map_segments(
            binary,
            module_base=-self._get_lowest_address(binary),
            dry_run=True,
        )

        for mapped_region in mapped_regions:
            offset = aligned(mapped_region.end, 1024 * 1024)

            shifted_regions = [
                AddressRegion(
                    base=region.base + offset,
                    size=region.size,
                )
                for region in regions
            ]

            if not self._has_regions_overlap(mapped_regions, shifted_regions):
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
        module_base -= aligned(self._get_lowest_address(binary), 1024)

        regions = self._map_segments(binary, module_base)
        size = (regions[-1].end - module_base) if regions else 0

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
            regions=regions,
            init_array=init_array,
            dyld_info=dyld_info,
        )
