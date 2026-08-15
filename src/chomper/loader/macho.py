import os
from typing import Dict, List, Tuple, Optional

import lief
from lief.MachO import ARM64_RELOCATION, RelocationFixup, LoadCommand, DylibCommand

from chomper import const
from chomper.utils import aligned

from .base import BaseLoader, Module, MachoInfo, Symbol, Binding, Segment, AddressRegion


_SYMBOL_ALIASES = {
    "_tlv_get_addr": "__tlv_bootstrap",
}

_PLATFORM_SYMBOLS = [
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


class MachoLoader(BaseLoader):
    """The Mach-O file loader."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self._symbol_aliases = {}
        self._init_symbol_aliases()

        # Loaded symbols
        self._symbol_map = {}

    def _init_symbol_aliases(self):
        symbol_aliases = _SYMBOL_ALIASES.copy()

        for symbol in _PLATFORM_SYMBOLS:
            symbol_aliases[f"__platform{symbol}"] = symbol

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
        install_name: Optional[str],
    ) -> List[Symbol]:
        """Get symbols in the module."""
        symbols = []

        lazy_bindings = self.get_lazy_bindings()
        lazy_binding_map: Dict[Tuple[Optional[str], str], List] = {}

        # Group lazy bindings
        for module, binding in lazy_bindings:
            symbol_unique = (binding.library, binding.symbol)

            if symbol_unique not in lazy_binding_map:
                lazy_binding_map[symbol_unique] = []

            lazy_binding_map[symbol_unique].append((module, binding))

        lazy_binding_set = set()

        re_export_map = self._build_re_export_map()

        for symbol in binary.symbols:
            if (
                symbol.origin.value == symbol.ORIGIN.DYLD_EXPORT.value
                and symbol.export_info
                and symbol.export_info.alias
            ):
                symbol_name = str(symbol.name)
                alias_name = str(symbol.export_info.alias.name)

                if alias_name not in self._symbol_map:
                    continue

                symbol_address = None

                # Look up from other modules
                for module_symbol in self._symbol_map.get(alias_name, []):
                    if module_symbol.library == symbol.export_info.alias_library.name:
                        symbol_address = module_symbol.address

                if not symbol_address:
                    continue

                binding_name = str(symbol.name)
                libraries = [install_name]
            else:
                if not symbol.value:
                    continue

                symbol_name = str(symbol.name)
                symbol_address = module_base + symbol.value

                binding_name = self._get_binding_name(symbol_name)
                libraries = [install_name]

            # The target library may be re-exported by other libraries
            libraries.extend(re_export_map.get(install_name, []))  # type: ignore

            # Lazy binding symbol
            for library in libraries:
                symbol_unique = (library, binding_name)
                if symbol_unique in lazy_binding_set:
                    continue

                if lazy_binding_map.get(symbol_unique):
                    for module, binding in lazy_binding_map[symbol_unique]:
                        reloc_addr = symbol_address

                        if reloc_addr:
                            address = (
                                module.base
                                - module.macho_info.image_base
                                + binding.address
                            )

                            value = reloc_addr + binding.addend
                            value &= 0xFFFFFFFFFFFFFFFF

                            self.emu.write_pointer(address, value)

                    lazy_binding_set.add(symbol_unique)

            module_symbol = Symbol(
                address=symbol_address,
                name=symbol_name,
                library=install_name,
            )
            symbols.append(module_symbol)

            if binding_name != symbol_name:
                module_symbol = Symbol(
                    address=symbol_address,
                    name=binding_name,
                    library=install_name,
                )
                symbols.append(module_symbol)

        return symbols

    def _refresh_symbol_map(self, symbols: List[Symbol]):
        """Append the module's symbols to the loaded symbol map."""
        for symbol in symbols:
            if symbol.name not in self._symbol_map:
                self._symbol_map[symbol.name] = []

            self._symbol_map[symbol.name].append(symbol)

    def _build_re_export_map(self) -> Dict[str, List]:
        """Map re-exported libraries to their umbrella libraries."""
        re_export_map: Dict[str, List] = {}

        for module in self.emu.modules:
            for name in module.macho_info.re_export_libraries:
                if name not in re_export_map:
                    re_export_map[name] = []

                re_export_map[name].append(module.macho_info.install_name)

        return re_export_map

    def _process_symbol_relocation(
        self,
        binary: lief.MachO.Binary,
        module_base: int,
        install_name: Optional[str],
        symbols: List[Symbol],
    ) -> List[Binding]:
        """Process relocations for symbols."""
        symbol_map = self._symbol_map.copy()
        re_export_map = self._build_re_export_map()

        for symbol in symbols:
            # Construct the corresponding symbols for umbrella libraries
            for library in re_export_map.get(symbol.library, []):  # type: ignore
                new_symbol = Symbol(
                    address=symbol.address,
                    name=symbol.name,
                    type=symbol.type,
                    library=library,
                )
                symbol_map[symbol.name].append(new_symbol)

        hooks_map: Dict = {}
        lazy_bindings = []

        for binding in binary.bindings:
            if binding.segment.name in ("__TEXT",):
                continue

            symbol_name = str(binding.symbol.name)
            library_name = binding.library.name if binding.library else None

            reloc_addr = None

            # Look up loaded symbols
            if symbol_name in symbol_map:
                for exported_symbol in symbol_map[symbol_name]:
                    if not library_name or library_name == exported_symbol.library:
                        reloc_addr = exported_symbol.address
                        break

            # Fallback attempt
            if not reloc_addr and symbol_name in symbol_map:
                for exported_symbol in symbol_map[symbol_name]:
                    reloc_addr = exported_symbol.address
                    break

            if not reloc_addr:
                lazy_binding = Binding(
                    symbol=symbol_name,
                    library=library_name,
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
        install_name: Optional[str],
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

        return self._process_symbol_relocation(
            binary,
            module_base,
            install_name,
            symbols,
        )

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
    def _get_minimum_address(binary: lief.MachO.Binary) -> int:
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
        for region in regions:
            for other in other_regions:
                if region.start < other.end and other.start < region.end:
                    return True
        return False

    def _resolve_load_base(self, binary: lief.MachO.Binary) -> int:
        """Get the minimum address to load a module."""
        mapped_regions = [
            region for module in self.emu.modules for region in module.regions
        ]

        module_base = -self._get_minimum_address(binary)
        regions = self._map_segments(binary, module_base=module_base, dry_run=True)

        for mapped_region in mapped_regions:
            offset = aligned(mapped_region.end, 1024 * 1024)
            shifted_regions = []

            for region in regions:
                shifted_region = AddressRegion(
                    base=region.base + offset,
                    size=region.size,
                )
                shifted_regions.append(shifted_region)

            if not self._has_regions_overlap(mapped_regions, shifted_regions):
                return offset

        return max([region.end for region in mapped_regions])

    @staticmethod
    def _get_install_name(binary: lief.MachO.Binary) -> Optional[str]:
        """Get install name from the `LC_ID_DYLIB` command."""
        name = None

        for command in binary.commands:
            if command.command == LoadCommand.TYPE.ID_DYLIB:
                assert isinstance(command, DylibCommand)
                name = command.name

        return name

    @staticmethod
    def _get_re_export_libraries(binary: lief.MachO.Binary) -> List[str]:
        """Get re-export dylib names from `LC_REEXPORT_DYLIB` commands."""
        libraries = []

        for command in binary.commands:
            if command.command == LoadCommand.TYPE.REEXPORT_DYLIB:
                assert isinstance(command, DylibCommand)
                libraries.append(command.name)

        return libraries

    def load(
        self,
        module_file: str,
        module_base: Optional[int] = None,
        trace_symbol_calls: bool = False,
    ) -> Module:
        """Load Mach-O executable file from path."""
        module_name = os.path.basename(module_file)
        self.emu.logger.info(f'Load module "{module_name}"')

        with open(module_file, "rb") as f:
            binary: lief.MachO.Binary = lief.parse(f)  # type: ignore

        if not binary:
            raise ValueError(f"Failed to parse Mach-O file: {module_file}")

        if module_base is None:
            if self.emu.modules:
                # Make the segments of different modules are interleaved
                module_base = self._resolve_load_base(binary)
            else:
                module_base = const.MODULE_ADDRESS

            # Make module memory distribution more compact
            module_base -= aligned(self._get_minimum_address(binary), 1024)
        else:
            module_base -= binary.imagebase

        install_name = self._get_install_name(binary)
        re_export_libraries = self._get_re_export_libraries(binary)

        regions = self._map_segments(binary, module_base)
        size = (regions[-1].end - module_base) if regions else 0

        symbols = self._load_symbols(binary, module_base, install_name)
        symbols = self._process_symbol_aliases(symbols)

        self._refresh_symbol_map(symbols)
        self.add_symbol_hooks(symbols, trace_symbol_calls)

        lazy_bindings = self._process_relocation(
            binary,
            module_base,
            install_name,
            symbols,
        )
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

        macho_info = MachoInfo(
            image_base=image_base,
            image_header=image_header,
            install_name=install_name,
            lazy_bindings=lazy_bindings,
            shared_segments=shared_segments,
            re_export_libraries=re_export_libraries,
        )

        return Module(
            path=module_file,
            base=module_base + image_base,
            size=size - image_base,
            symbols=symbols,
            regions=regions,
            init_array=init_array,
            macho_info=macho_info,
        )
