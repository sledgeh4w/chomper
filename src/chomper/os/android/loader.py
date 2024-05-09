import os
from typing import Dict, List

from elftools.elf.dynamic import DynamicSegment
from elftools.elf.elffile import ELFFile
from elftools.elf.enums import ENUM_RELOC_TYPE_AARCH64, ENUM_RELOC_TYPE_ARM
from elftools.elf.relocation import Relocation

from chomper.base import BaseLoader
from chomper.types import Module, Symbol, SymbolType
from chomper.utils import aligned


class ELFLoader(BaseLoader):
    """The ELF file loader."""

    def _map_segments(self, elffile: ELFFile, module_base: int) -> int:
        """Map segment of type `LOAD` into memory."""
        boundary = 0

        for segment in elffile.iter_segments(type="PT_LOAD"):
            seg_addr = module_base + segment.header.p_vaddr

            # Because of alignment, the actual mapped address range will be larger.
            map_addr = aligned(seg_addr, 1024) - (1024 if seg_addr % 1024 else 0)
            map_size = aligned(seg_addr - map_addr + segment.header.p_memsz, 1024)

            self.emu.uc.mem_map(map_addr, map_size)
            self.emu.uc.mem_write(seg_addr, segment.data())

            boundary = max(boundary, map_addr + map_size)

        return boundary - module_base

    @staticmethod
    def _load_symbols(elffile: ELFFile, module_base: int) -> List[Symbol]:
        """Get all symbols in the module."""
        symbols = []

        for segment in elffile.iter_segments(type="PT_DYNAMIC"):
            for symbol in segment.iter_symbols():
                if symbol.entry["st_info"]["bind"] in ("STB_GLOBAL", "STB_WEAK"):
                    if symbol.entry["st_shndx"] == "SHN_UNDEF":
                        continue

                    symbol_type = (
                        SymbolType.FUNC
                        if symbol.entry["st_info"]["type"] == "STT_FUNC"
                        else SymbolType.OTHER
                    )

                    symbol_struct = Symbol(
                        address=module_base + symbol.entry["st_value"],
                        name=symbol.name,
                        type=symbol_type,
                    )
                    symbols.append(symbol_struct)

        return symbols

    def _relocate_address(
        self,
        module_base: int,
        symbol_map: Dict[str, Symbol],
        relocation: Relocation,
        segment: DynamicSegment,
    ):
        """Relocate address in the relocation table."""
        reloc_type = relocation["r_info_type"]
        reloc_offset = module_base + relocation["r_offset"]
        reloc_addr = None

        if reloc_type in (
            ENUM_RELOC_TYPE_ARM["R_ARM_ABS32"],
            ENUM_RELOC_TYPE_ARM["R_ARM_GLOB_DAT"],
            ENUM_RELOC_TYPE_ARM["R_ARM_JUMP_SLOT"],
            ENUM_RELOC_TYPE_AARCH64["R_AARCH64_ABS64"],
            ENUM_RELOC_TYPE_AARCH64["R_AARCH64_GLOB_DAT"],
            ENUM_RELOC_TYPE_AARCH64["R_AARCH64_JUMP_SLOT"],
        ):
            symbol_name = segment.get_symbol(relocation["r_info_sym"]).name

            if symbol_map.get(symbol_name):
                reloc_addr = symbol_map[symbol_name].address

            else:
                # If the symbol is missing, let it jump to a specified address and
                # the address has hooked to raise an exception with useful information.
                hook_addr = self.emu.create_buffer(self.emu.arch.addr_size)

                self.emu.add_hook(
                    hook_addr,
                    self.emu.missing_symbol_required_callback,
                    user_data={"symbol_name": symbol_name},
                )
                self.emu.write_pointer(reloc_offset, hook_addr)

        elif reloc_type in (
            ENUM_RELOC_TYPE_ARM["R_ARM_RELATIVE"],
            ENUM_RELOC_TYPE_AARCH64["R_AARCH64_RELATIVE"],
        ):
            if relocation.is_RELA():
                reloc_addr = module_base + relocation["r_addend"]

        if reloc_addr:
            self.emu.write_pointer(reloc_offset, reloc_addr)

    def _process_relocation(
        self,
        elffile: ELFFile,
        module_base: int,
        symbols: List[Symbol],
    ):
        """Process relocation tables."""
        symbol_map = self.get_symbols()
        symbol_map.update({symbol.name: symbol for symbol in symbols})

        for segment in elffile.iter_segments(type="PT_DYNAMIC"):
            for relocation_table in segment.get_relocation_tables().values():
                for relocation in relocation_table.iter_relocations():
                    self._relocate_address(module_base, symbol_map, relocation, segment)

    def _get_init_array(self, elffile: ELFFile, module_base: int) -> List[int]:
        """Get initialization functions in section `.init_array`."""
        init_funcs = []

        init_array_addr = None
        init_array_size = None

        for segment in elffile.iter_segments(type="PT_DYNAMIC"):
            for tag in segment.iter_tags():
                if tag.entry.d_tag == "DT_INIT_ARRAY":
                    init_array_addr = tag.entry.d_val

                elif tag.entry.d_tag == "DT_INIT_ARRAYSZ":
                    init_array_size = tag.entry.d_val

        if init_array_addr is not None and init_array_size is not None:
            begin = module_base + init_array_addr
            end = begin + init_array_size

            init_funcs = self.emu.read_array(begin, end)

        return init_funcs

    def load(
        self,
        module_base: int,
        module_file: str,
        trace_symbol_calls: bool = False,
    ) -> Module:
        """Load ELF library file from path."""
        with ELFFile.load_from_path(module_file) as elffile:
            module_name = os.path.basename(module_file)
            self.emu.logger.info(f'Load module "{module_name}"')

            # Map segments into memory.
            size = self._map_segments(elffile, module_base)
            symbols = self._load_symbols(elffile, module_base)

            self.add_symbol_hooks(symbols, trace_symbol_calls)

            # Process address relocation.
            self._process_relocation(elffile, module_base, symbols)

            init_array = self._get_init_array(elffile, module_base)

            return Module(
                base=module_base,
                size=size,
                name=module_name,
                symbols=symbols,
                init_array=init_array,
            )
