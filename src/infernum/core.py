import logging
import os
import sys
from typing import Any, Dict, List, Optional, Tuple, Union

from capstone import CS_ARCH_ARM, CS_ARCH_ARM64, CS_MODE_ARM, CS_MODE_THUMB, Cs
from elftools.elf.dynamic import DynamicSegment
from elftools.elf.elffile import ELFFile
from elftools.elf.enums import ENUM_RELOC_TYPE_ARM, ENUM_RELOC_TYPE_AARCH64
from elftools.elf.relocation import Relocation
from unicorn import (
    UC_ARCH_ARM,
    UC_ARCH_ARM64,
    UC_HOOK_CODE,
    UC_MODE_ARM,
    UC_MODE_THUMB,
    Uc,
    UcError,
    arm_const,
    arm64_const,
)
from unicorn.unicorn import UC_HOOK_CODE_TYPE

from . import const
from .arch import arch_arm, arch_arm64
from .exceptions import EmulatorCrashedException, SymbolMissingException
from .log import get_logger
from .memory import MemoryManager
from .structs import Location, Module, Symbol
from .utils import aligned

if sys.version_info >= (3, 8):
    from typing import Literal
else:
    from typing_extensions import Literal


class Infernum:
    """Lightweight Android native library emulation framework.

    Args:
        arch: The arch. Support ARM and ARM64.
        logger: The logger. If ``None``, use default logger.
        on_thumb: Whether to use Thumb mode. This parameter only available on
            arch ARM.
        enable_vfp: Whether to enable vfp.
        trace_inst: Whether to trace all instructions and display
            disassemble results.
        trace_symbol_calls: Whether to trace all symbol calls.
    """

    def __init__(
        self,
        arch: int = const.ARCH_ARM64,
        logger: Optional[logging.Logger] = None,
        on_thumb: bool = True,
        enable_vfp: bool = True,
        trace_inst: bool = False,
        trace_symbol_calls: bool = True,
    ):
        self.arch = arch_arm if arch == const.ARCH_ARM else arch_arm64
        self.logger = logger or get_logger(self.__class__.__name__)

        self.on_thumb = on_thumb
        self.enable_vfp = enable_vfp
        self.trace_inst = trace_inst
        self.trace_symbol_calls = trace_symbol_calls

        self.endian = const.LITTLE_ENDIAN

        self.modules: List[Module] = []

        self.uc = self._create_uc()
        self.cs = self._create_cs()

        self.memory_manager = MemoryManager(uc=self.uc, heap_address=const.HEAP_ADDRESS)

        self._traps: List[int] = []
        self._init_trap_memory()

        self._symbol_hooks: Dict[str, UC_HOOK_CODE_TYPE] = {}
        self._init_symbol_hooks()

        self._setup_emulator()

    @property
    def _module_address_offset(self) -> int:
        """Get offset address of modules."""
        if self.modules:
            return aligned(self.modules[-1].base + self.modules[-1].size, 1024 * 1024)
        return const.MODULE_ADDRESS

    @property
    def _trap_address_offset(self) -> int:
        """Get offset address of traps."""
        if self._traps:
            return const.TRAP_ADDRESS + len(self._traps) * 4
        return const.TRAP_ADDRESS

    def _create_uc(self) -> Uc:
        """Create Unicorn instance."""
        arch = UC_ARCH_ARM if self.arch == arch_arm else UC_ARCH_ARM64
        mode = UC_MODE_THUMB if self.arch == arch_arm and self.on_thumb else UC_MODE_ARM

        return Uc(arch, mode)

    def _create_cs(self) -> Cs:
        """Create Capstone instance."""
        arch = CS_ARCH_ARM if self.arch == arch_arm else CS_ARCH_ARM64
        mode = CS_MODE_THUMB if self.arch == arch_arm and self.on_thumb else CS_MODE_ARM

        return Cs(arch, mode)

    def _init_symbol_hooks(self):
        """Initialize default symbol hooks."""
        self._symbol_hooks.update(self.arch.symbol_hooks)

    def _init_trap_memory(self):
        """Initialize trap area memory."""
        self.uc.mem_map(const.TRAP_ADDRESS, const.TRAP_SIZE)

    def _setup_stack(self):
        """Setup stack."""
        stack_addr = const.STACK_ADDRESS + const.STACK_SIZE // 2

        self.uc.mem_map(const.STACK_ADDRESS, const.STACK_SIZE)

        self.uc.reg_write(self.arch.reg_sp, stack_addr)
        self.uc.reg_write(self.arch.reg_fp, stack_addr)

    def _setup_thread_register(self):
        """Setup thread register.

        The thread register store the address of thread local storage (TLS).
        It only allocates a block of memory to TLS and does not really initialize.
        """
        self.uc.mem_map(const.TLS_ADDRESS, const.TLS_SIZE)

        if self.arch == arch_arm:
            self.uc.reg_write(
                arm_const.UC_ARM_REG_CP_REG,
                (15, 0, 0, 13, 0, 0, 3, const.TLS_ADDRESS),  # type: ignore
            )
        else:
            self.uc.reg_write(arm64_const.UC_ARM64_REG_TPIDR_EL0, const.TLS_ADDRESS)

    def _enable_vfp(self):
        """Enable vfp.

        See details:
        https://github.com/unicorn-engine/unicorn/issues/446
        """
        inst_code = (
            b"\x4f\xf4\x70\x00"  # mov.w r0, #0xf00000
            b"\x01\xee\x50\x0f"  # mcr p15, #0x0, r0, c1, c0, #0x2
            b"\xbf\xf3\x6f\x8f"  # isb sy
            b"\x4f\xf0\x80\x43"  # mov.w r3, #0x40000000
            b"\xe8\xee\x10\x3a"  # vmsr fpexc, r3
        )
        addr = const.TEMP_ADDRESS

        self.uc.mem_map(const.TEMP_ADDRESS, aligned(len(inst_code), 1024))
        self.uc.mem_write(addr, inst_code)

        self.uc.emu_start(addr | 1, addr + len(inst_code))

        self.uc.mem_unmap(const.TEMP_ADDRESS, aligned(len(inst_code), 1024))

    def _setup_emulator(self):
        """Setup emulator."""
        self._setup_stack()
        self._setup_thread_register()

        if self.arch == arch_arm and self.enable_vfp:
            self._enable_vfp()

    def _start_emulate(self, address, *args):
        """Start emulate at the specified address."""
        for index, value in enumerate(args):
            self.set_argument(index, value)

        stop_addr = 0

        # Set the value of register LR to the stop address of the emulation,
        # so that when the function returns, it will jump to this address.
        self.uc.reg_write(self.arch.reg_lr, stop_addr)
        self.uc.reg_write(self.arch.reg_pc, address)

        try:
            self.logger.info(f"Start emulate at {self.locate_address(address)}.")
            self.uc.emu_start(address, stop_addr)

        except UcError as e:
            self.logger.error("Emulator crashed.")
            address = self.uc.reg_read(self.arch.reg_pc) - 4
            inst = next(self.cs.disasm(self.read_bytes(address, 4), 0))

            # Check whether the last instruction is svc.
            if inst.mnemonic == "svc":
                raise EmulatorCrashedException(
                    f"Unhandled system call at {self.locate_address(address)}"
                )

            raise EmulatorCrashedException("Unknown reason") from e

    def _trace_inst_callback(self, uc: Uc, address: int, size: int, _: Any):
        """Trace instruction."""
        for inst in self.cs.disasm_lite(uc.mem_read(address, size), 0):
            self.logger.info(
                f"Trace at {self.locate_address(address)}: {inst[-2]} {inst[-1]}."
            )

    def _trace_symbol_call_callback(self, *args):
        """Trace symbol call."""
        user_data = args[-1]
        symbol = user_data["symbol"]
        ret_addr = self.uc.reg_read(self.arch.reg_lr)

        self.logger.info(
            f"Symbol '{symbol.name}' called"
            + (f" from {self.locate_address(ret_addr)}." if ret_addr else ".")
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

    def find_symbol(self, symbol_name: str) -> Symbol:
        """Find symbol from loaded modules.

        Raises:
            SymbolMissingException: If symbol not found.
        """
        for module in self.modules:
            for symbol in module.symbols:
                if symbol.name == symbol_name:
                    return symbol

        raise SymbolMissingException(f"{symbol_name} not found")

    def locate_address(self, address: int) -> Location:
        """Locate which module this address is in."""
        located_module = None

        for module in self.modules:
            if module.base <= address < module.base + module.size:
                located_module = module
                break

        return Location(address=address, module=located_module)

    def backtrace(self) -> List[Location]:
        """Backtrace the call stack."""
        call_stack = [self.uc.reg_read(self.arch.reg_lr)]
        fp = self.uc.reg_read(self.arch.reg_fp)

        while True:
            lr = self.read_int(fp + 8)
            fp = self.read_int(fp)
            if not fp or not lr:
                break
            call_stack.append(lr)

        return [self.locate_address(addr - 4) for addr in call_stack if addr]

    def return_call(self, retval: Optional[int] = None):
        """Return current function call."""
        if retval is not None:
            self.set_retval(retval)

        self.uc.reg_write(self.arch.reg_pc, self.uc.reg_read(self.arch.reg_lr))

    def add_hook(
        self,
        symbol_or_addr: Union[str, int],
        callback: UC_HOOK_CODE_TYPE,
        user_data: Optional[dict] = None,
        silenced: Optional[bool] = False,
    ) -> int:
        """Add hook to the emulator.

        Args:
            symbol_or_addr: The name of symbol or address to hook. If ``str``,
                this function will look for this symbol from loaded modules and
                take its value as the hook address.
            callback: The callback function, same as callback of type
                ``UC_HOOK_CODE`` in Unicorn.
            user_data: A ``dict`` that contains the data you want to pass to
                callback.
            silenced: If ``True``, do not print log.
        """
        if isinstance(symbol_or_addr, str):
            symbol = self.find_symbol(symbol_or_addr)
            hook_addr = symbol.address

            if self.arch == arch_arm:
                hook_addr = (hook_addr | 1) - 1

            if not silenced:
                self.logger.info(
                    f"Hook symbol '{symbol.name}' at {self.locate_address(hook_addr)}."
                )

        else:
            hook_addr = symbol_or_addr
            if not silenced:
                self.logger.info(f"Hook address at {self.locate_address(hook_addr)}.")

        if user_data is None:
            user_data = {}

        return self.uc.hook_add(
            UC_HOOK_CODE,
            callback,
            begin=hook_addr,
            end=hook_addr,
            user_data={"emulator": self, **user_data},
        )

    def del_hook(self, handle: int):
        """Delete hook."""
        self.uc.hook_del(handle)

    def _map_segments(self, elffile: ELFFile) -> Tuple[int, int]:
        """Map segment of type ``LOAD`` into memory."""
        base = self._module_address_offset
        boundary = 0

        for segment in elffile.iter_segments(type="PT_LOAD"):
            seg_addr = base + segment.header.p_vaddr

            # Because of alignment, the actual mapped address range will be larger.
            map_addr = aligned(seg_addr, 1024) - (1024 if seg_addr % 1024 else 0)
            map_size = aligned(seg_addr - map_addr + segment.header.p_memsz, 1024)

            self.uc.mem_map(map_addr, map_size)
            self.uc.mem_write(seg_addr, segment.data())

            boundary = max(boundary, map_addr + map_size)

        return base, boundary - base

    def _get_symbols(self, elffile: ELFFile) -> List[Symbol]:
        """Get all symbols in the module."""
        symbols = []

        for segment in elffile.iter_segments(type="PT_DYNAMIC"):
            for symbol in segment.iter_symbols():
                if (
                    symbol.entry["st_info"]["bind"] in ("STB_GLOBAL", "STB_WEAK")
                    and symbol.entry["st_shndx"] != "SHN_UNDEF"
                ):
                    symbols.append(
                        Symbol(
                            address=self._module_address_offset
                            + symbol.entry["st_value"],
                            name=symbol.name,
                            type=symbol.entry["st_info"]["type"],
                        )
                    )

        return symbols

    def _exec_init_array(self, elffile: ELFFile, module: Module):
        """Find and execute initialization functions in section ``.init_array``."""
        init_array_addr = None
        init_array_size = None

        for segment in elffile.iter_segments(type="PT_DYNAMIC"):
            for tag in segment.iter_tags():
                if tag.entry.d_tag == "DT_INIT_ARRAY":
                    init_array_addr = tag.entry.d_val
                elif tag.entry.d_tag == "DT_INIT_ARRAYSZ":
                    init_array_size = tag.entry.d_val

        if init_array_addr is not None and init_array_size is not None:
            self.logger.info("Execute initialize functions.")

            for offset in range(0, init_array_size, self.arch.reg_size // 8):
                init_func_addr = self.read_int(module.base + init_array_addr + offset)

                if init_func_addr:
                    # Execute the initialization functions.
                    self._start_emulate(init_func_addr)

    def _relocate_address(
        self, module_base: int, relocation: Relocation, segment: DynamicSegment
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

            try:
                symbol = self.find_symbol(symbol_name)
                reloc_addr = symbol.address

            except SymbolMissingException:
                # If the symbol is missing, let it jump to the trap address to
                # raise an exception with useful information.
                self.add_hook(
                    self._trap_address_offset,
                    self._missing_symbol_required_callback,
                    user_data={"symbol_name": symbol_name},
                    silenced=True,
                )
                self.write_int(reloc_offset, self._trap_address_offset)
                self._traps.append(self._trap_address_offset)

        elif reloc_type in (
            ENUM_RELOC_TYPE_ARM["R_ARM_RELATIVE"],
            ENUM_RELOC_TYPE_AARCH64["R_AARCH64_RELATIVE"],
        ):
            if relocation.is_RELA():
                reloc_addr = module_base + relocation["r_addend"]

        if reloc_addr:
            self.write_int(reloc_offset, reloc_addr)

    def _process_relocation(self, elffile: ELFFile, module_base: int):
        """Process relocation tables."""
        for segment in elffile.iter_segments(type="PT_DYNAMIC"):
            for relocation_table in segment.get_relocation_tables().values():
                for relocation in relocation_table.iter_relocations():
                    self._relocate_address(module_base, relocation, segment)

    def load_module(
        self,
        module_file: str,
        exec_init_array: bool = False,
        trace_inst: bool = False,
        trace_symbol_calls: bool = False,
    ) -> Module:
        """Load ELF library file from path.

        Args:
            module_file: The path of file to be loaded.
            exec_init_array: If ``True``, execute initialization functions recorded
                in the section ``.init_array``.
            trace_inst: If ``True``, trace instructions in this module and display
                disassemble results.
            trace_symbol_calls: If ``True``, trace symbol calls in this module.
        """
        with ELFFile.load_from_path(module_file) as elffile:
            module_name = os.path.basename(module_file)
            self.logger.info(f"Load module '{module_name}'.")

            # Map segments into memory.
            base, size = self._map_segments(elffile)
            symbols = self._get_symbols(elffile)

            module = Module(base=base, size=size, name=module_name, symbols=symbols)
            self.modules.append(module)

            for symbol in symbols:
                if symbol.type == "STT_FUNC":
                    # Trace symbol call
                    if trace_symbol_calls or self.trace_symbol_calls:
                        self.add_hook(
                            symbol.name,
                            self._trace_symbol_call_callback,
                            user_data={"symbol": symbol},
                            silenced=True,
                        )

                    # Hook symbol
                    if self._symbol_hooks.get(symbol.name):
                        self.add_hook(symbol.name, self._symbol_hooks[symbol.name])

            # Process address relocation.
            self._process_relocation(elffile, base)

            if trace_inst or self.trace_inst:
                # Trace instructions
                self.uc.hook_add(
                    UC_HOOK_CODE,
                    self._trace_inst_callback,
                    begin=module.base,
                    end=module.base + module.size,
                )

            if exec_init_array:
                # Execute initialization functions.
                self._exec_init_array(elffile, module)

            return module

    def _get_argument_holder(self, index: int) -> Tuple[bool, int]:
        """Get the register or address where the specified argument is stored.

        On arch ARM, the first four parameters are stored in the register R0-R3,
        and the rest are stored on the stack. On arch ARM64, the first eight
        parameters are stored in the register X0-X7, and the rest are stored on
        the stack.

        Returns:
            A ``tuple`` contains a ``bool`` and an ``int``, the first member
            means whether the returned is a register and the second is
            the actual register or address.
        """
        registers = self.arch.reg_args

        if index >= len(registers):
            # Read address from stack.
            offset = (index - len(registers)) * (self.arch.reg_size // 8)
            address = self.uc.reg_read(self.arch.reg_sp) + offset
            return False, address

        return True, registers[index]

    def get_argument(self, index: int) -> int:
        """Get argument with the specified index."""
        is_reg, reg_or_addr = self._get_argument_holder(index)

        if is_reg:
            return self.uc.reg_read(reg_or_addr)
        else:
            return self.read_int(reg_or_addr)

    def set_argument(self, index: int, value: int):
        """Set argument with the specified index."""
        is_reg, reg_or_addr = self._get_argument_holder(index)

        if is_reg:
            self.uc.reg_write(reg_or_addr, value)
        else:
            self.write_int(reg_or_addr, value)

    def get_retval(self) -> int:
        """Get return value."""
        return self.uc.reg_read(self.arch.reg_ret)

    def set_retval(self, value: int):
        """Set return value."""
        self.uc.reg_write(self.arch.reg_ret, value)

    def create_buffer(self, size: int) -> int:
        """Create a buffer with the size."""
        return self.memory_manager.alloc(size)

    def create_string(self, string: str) -> int:
        """Create a buffer that is initialized to the string."""
        address = self.memory_manager.alloc(len(string) + 1)
        self.write_string(address, string)

        return address

    def free(self, address: int):
        """Free memory."""
        self.memory_manager.free(address)

    def write_int(
        self,
        address: int,
        value: int,
        size: Optional[int] = None,
        endian: Optional[Literal["little", "big"]] = None,
    ):
        """Write an integer into the address."""
        if size is None:
            size = self.arch.reg_size // 8

        if endian is None:
            endian = self.endian

        self.uc.mem_write(address, value.to_bytes(size, byteorder=endian))

    def write_bytes(self, address: int, data: bytes):
        """Write bytes into the address."""
        self.uc.mem_write(address, data)

    def write_string(self, address: int, string: str):
        """Write string into the address."""
        self.uc.mem_write(address, string.encode("utf-8") + b"\x00")

    def read_int(
        self,
        address: int,
        size: Optional[int] = None,
        endian: Optional[Literal["little", "big"]] = None,
    ) -> int:
        """Read an integer from the address."""
        if size is None:
            size = self.arch.reg_size // 8

        if endian is None:
            endian = self.endian

        return int.from_bytes(self.uc.mem_read(address, size), byteorder=endian)

    def read_bytes(self, address: int, size: int) -> bytes:
        """Read bytes from the address."""
        return bytes(self.uc.mem_read(address, size))

    def read_string(self, address: int) -> str:
        """Read String from the address."""
        data = bytes()
        offset = 0

        while True:
            byte = self.read_bytes(address + offset, 1)
            if byte == b"\x00":
                break
            data += byte
            offset += 1

        return data.decode("utf-8")

    def call_symbol(self, symbol_name, *args) -> int:
        """Call function with the symbol name."""
        symbol = self.find_symbol(symbol_name)
        address = symbol.address

        self._start_emulate(address, *args)

        return self.get_retval()

    def call_address(self, address, *args) -> int:
        """Call function at the address."""
        self._start_emulate(address, *args)

        return self.get_retval()
