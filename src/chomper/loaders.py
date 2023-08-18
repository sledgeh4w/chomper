import os
import re
from typing import Dict, List, Tuple

import lief
from elftools.elf.dynamic import DynamicSegment
from elftools.elf.elffile import ELFFile
from elftools.elf.enums import ENUM_RELOC_TYPE_AARCH64, ENUM_RELOC_TYPE_ARM
from elftools.elf.relocation import Relocation
from unicorn import arm_const, arm64_const

from . import const
from .exceptions import EmulatorCrashedException
from .structs import Module, Symbol
from .utils import aligned


class BaseLoader:
    """Base executable file loader."""

    def __init__(self, emu):
        self.emu = emu

    def _get_load_base(self) -> int:
        """Get the base address to load."""
        return (
            aligned(self.emu.modules[-1].base + self.emu.modules[-1].size, 1024 * 1024)
            if self.emu.modules
            else const.MODULE_ADDRESS
        )

    def _get_symbols_map(self) -> Dict[str, Symbol]:
        symbols_map = {}

        for module in self.emu.modules:
            for symbol in module.symbols:
                symbols_map[symbol.name] = symbol

        return symbols_map

    def _trace_symbol_call_callback(self, *args):
        """Trace symbol call."""
        user_data = args[-1]
        symbol = user_data["symbol"]

        if self.emu.arch == const.ARCH_ARM:
            ret_addr = self.emu.uc.reg_read(arm_const.UC_ARM_REG_LR)
        else:
            ret_addr = self.emu.uc.reg_read(arm64_const.UC_ARM64_REG_LR)

        self.emu.logger.info(
            f"Symbol '{symbol.name}' called"
            + (f" from {self.emu.locate_address(ret_addr)}." if ret_addr else ".")
        )

    @staticmethod
    def _missing_symbol_required_callback(*args):
        """Raise an exception with information of missing symbol."""
        user_data = args[-1]
        symbol_name = user_data["symbol_name"]

        raise EmulatorCrashedException(
            f"Missing symbol '{symbol_name}' is required, "
            f"you should load the library that contains it."
        )

    def load_module(
        self,
        module_file: str,
        exec_init_array: bool = False,
        trace_symbol_calls: bool = False,
    ) -> Module:
        """Load executable file."""
        raise NotImplementedError


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
    def _get_export_symbols(elffile: ELFFile, module_base: int) -> List[Symbol]:
        """Get all export symbols in the module."""
        symbols = []

        for segment in elffile.iter_segments(type="PT_DYNAMIC"):
            for symbol in segment.iter_symbols():
                if (
                    symbol.entry["st_info"]["bind"] in ("STB_GLOBAL", "STB_WEAK")
                    and symbol.entry["st_shndx"] != "SHN_UNDEF"
                ):
                    symbols.append(
                        Symbol(
                            address=module_base + symbol.entry["st_value"],
                            name=symbol.name,
                            type=symbol.entry["st_info"]["type"],
                        )
                    )

        return symbols

    def _relocate_address(
        self,
        module_base: int,
        symbols: List[Symbol],
        relocation: Relocation,
        segment: DynamicSegment,
    ):
        """Relocate address in the relocation table."""
        reloc_type = relocation["r_info_type"]
        reloc_offset = module_base + relocation["r_offset"]
        reloc_addr = None

        symbols_map = self._get_symbols_map()

        for symbol in symbols:
            symbols_map[symbol.name] = symbol

        if reloc_type in (
            ENUM_RELOC_TYPE_ARM["R_ARM_ABS32"],
            ENUM_RELOC_TYPE_ARM["R_ARM_GLOB_DAT"],
            ENUM_RELOC_TYPE_ARM["R_ARM_JUMP_SLOT"],
            ENUM_RELOC_TYPE_AARCH64["R_AARCH64_ABS64"],
            ENUM_RELOC_TYPE_AARCH64["R_AARCH64_GLOB_DAT"],
            ENUM_RELOC_TYPE_AARCH64["R_AARCH64_JUMP_SLOT"],
        ):
            symbol_name = segment.get_symbol(relocation["r_info_sym"]).name

            if symbols_map.get(symbol_name):
                reloc_addr = symbols_map[symbol_name].address

            else:
                # If the symbol is missing, let it jump to a specified address and
                # the address has hooked to raise an exception with useful information.
                hook_addr = self.emu.create_buffer(self.emu.arch.addr_size)

                self.emu.add_hook(
                    hook_addr,
                    self._missing_symbol_required_callback,
                    user_data={"symbol_name": symbol_name},
                )
                self.emu.write_address(reloc_offset, hook_addr)

        elif reloc_type in (
            ENUM_RELOC_TYPE_ARM["R_ARM_RELATIVE"],
            ENUM_RELOC_TYPE_AARCH64["R_AARCH64_RELATIVE"],
        ):
            if relocation.is_RELA():
                reloc_addr = module_base + relocation["r_addend"]

        if reloc_addr:
            self.emu.write_address(reloc_offset, reloc_addr)

    def _process_relocation(
        self, elffile: ELFFile, module_base: int, symbols: List[Symbol]
    ):
        """Process relocation tables."""
        for segment in elffile.iter_segments(type="PT_DYNAMIC"):
            for relocation_table in segment.get_relocation_tables().values():
                for relocation in relocation_table.iter_relocations():
                    self._relocate_address(module_base, symbols, relocation, segment)

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
            for offset in range(0, init_array_size, self.emu.arch.addr_size):
                init_funcs.append(
                    self.emu.read_address(module_base + init_array_addr + offset)
                )

        return init_funcs

    def load_module(
        self,
        module_file: str,
        exec_init_array: bool = False,
        trace_symbol_calls: bool = False,
    ) -> Module:
        """Load ELF library file from path."""
        with ELFFile.load_from_path(module_file) as elffile:
            module_name = os.path.basename(module_file)
            self.emu.logger.info(f"Load module '{module_name}'.")

            base = self._get_load_base()

            # Map segments into memory.
            size = self._map_segments(elffile, base)
            symbols = self._get_export_symbols(elffile, base)

            for symbol in symbols:
                if symbol.type == "STT_FUNC":
                    # Trace symbol call
                    if trace_symbol_calls:
                        self.emu.add_hook(
                            symbol,
                            self._trace_symbol_call_callback,
                            user_data={"symbol": symbol},
                        )

                    # Hook symbol
                    if self.emu.hooks.get(symbol.name):
                        self.emu.add_interceptor(symbol, self.emu.hooks[symbol.name])

            # Process address relocation.
            self._process_relocation(elffile, base, symbols)

            init_array = self._get_init_array(elffile, base)

            return Module(
                base=base,
                size=size,
                name=module_name,
                symbols=symbols,
                init_array=init_array,
            )


class MachOLoader(BaseLoader):
    """The Mach-O file loader."""

    def _map_segments(self, binary: lief.MachO.Binary, module_base: int) -> int:
        """Map all segments into memory."""
        boundary = 0

        for segment in binary.segments:
            if not segment.file_size or not segment.virtual_size:
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

    def _get_export_symbols(
        self, binary: lief.MachO.Binary, module_base: int, trace_symbol_calls: int
    ) -> List[Symbol]:
        """Get all export symbols in the module."""
        symbols = []

        for symbol in binary.symbols:
            if not symbol.has_binding_info and symbol.value:
                symbols.append(
                    Symbol(
                        address=module_base + symbol.value,
                        name=symbol.name,
                        type="",
                    )
                )

                if trace_symbol_calls:
                    self.emu.add_hook(
                        symbols[-1],
                        self._trace_symbol_call_callback,
                        user_data={"symbol": symbols[-1]},
                    )

                # Hook exports
                if self.emu.hooks.get(symbol.name):
                    self.emu.add_interceptor(symbols[-1], self.emu.hooks[symbol.name])

        return symbols

    def _process_relocation(self, binary: lief.MachO.Binary, module_base: int):
        """Process relocations base on relocation table and symbol
        cross-references."""
        symbols_map = self._get_symbols_map()

        blocks: List[Tuple[int, int]] = []

        begin = None
        end = None

        # Merge relocation records into blocks
        for reloc in (reloc for reloc in binary.relocations if reloc.type == 1):
            addr = module_base + reloc.address

            if not begin:
                begin = addr

            if end and addr != end:
                blocks.append((begin, end))
                begin = addr

            end = addr + self.emu.arch.addr_size

        # Read and write as blocks
        for begin, end in blocks:
            content = self.emu.read_bytes(begin, end - begin)

            pointers = []
            for offset in range(0, end - begin, self.emu.arch.addr_size):
                pointers.append(
                    module_base
                    + int.from_bytes(
                        content[offset : offset + self.emu.arch.addr_size],
                        byteorder=self.emu.byteorder,
                    )
                )

            self.emu.write_bytes(
                begin,
                b"".join(
                    (
                        pointer.to_bytes(
                            self.emu.arch.addr_size, byteorder=self.emu.byteorder
                        )
                        for pointer in pointers
                    )
                ),
            )

        for symbol in binary.symbols:
            if symbol.has_binding_info:
                if symbols_map.get(symbol.name):
                    reloc_addr = symbols_map[symbol.name].address

                else:
                    reloc_addr = self.emu.create_buffer(self.emu.arch.addr_size)

                    # Hook imports
                    if self.emu.hooks.get(symbol.name):
                        self.emu.add_interceptor(
                            reloc_addr, self.emu.hooks[symbol.name]
                        )

                    else:
                        # self.emu.add_hook(
                        #     reloc_addr,
                        #     self._missing_symbol_required_callback,
                        #     user_data={"symbol_name": symbol.name},
                        # )
                        continue

                self.emu.write_address(
                    module_base + symbol.binding_info.address, reloc_addr
                )

                # There are two symbols with the same name `__platform_memmove`
                # in `libsystem_c.dylib`, and LIEF can't parse them correctly.
                if symbol.name == "__platform_memmove":
                    self.emu.write_address(
                        module_base
                        + symbol.binding_info.address
                        - self.emu.arch.addr_size,
                        reloc_addr,
                    )

        # Special handling of C standard library on iOS.
        for symbol in binary.symbols:
            if re.match(r"__libkernel_(.*)functions", symbol.name):
                addr = self.emu.read_address(module_base + symbol.value)
                self.emu.write_address(module_base + symbol.value, module_base + addr)

            elif symbol.name.startswith("__libkernel") and symbol.value:
                refs = binary.xref(symbol.value)
                for ref in refs:
                    addr = self.emu.read_address(module_base + ref)
                    self.emu.write_address(module_base + ref, module_base + addr)

            elif symbol.name in ("___locale_key", "___global_locale"):
                self.emu.write_address(module_base + symbol.value, 0)

    def _get_init_array(self, binary: lief.MachO.Binary, module_base: int):
        """Get initialization functions in section `__mod_init_func`."""
        init_funcs = []

        if binary.has_section("__mod_init_func"):
            init_func_section = binary.get_section("__mod_init_func")

            for offset in range(0, init_func_section.size, self.emu.arch.addr_size):
                init_funcs.append(
                    module_base
                    + int.from_bytes(
                        init_func_section.content[
                            offset : offset + self.emu.arch.addr_size
                        ],
                        byteorder="little",
                    )
                )

        return init_funcs

    def load_module(
        self,
        module_file: str,
        exec_init_array: bool = False,
        trace_symbol_calls: bool = False,
    ) -> Module:
        """Load Mach-O executable file from path."""
        module_name = os.path.basename(module_file)
        self.emu.logger.info(f"Load module '{module_name}'.")

        binary: lief.MachO.Binary = lief.parse(module_file)  # type: ignore

        base = self._get_load_base()
        size = self._map_segments(binary, base)
        symbols = self._get_export_symbols(binary, base, trace_symbol_calls)

        self._process_relocation(binary, base)

        init_array = self._get_init_array(binary, base)

        return Module(
            base=base,
            size=size,
            name=module_name,
            symbols=symbols,
            init_array=init_array,
        )
