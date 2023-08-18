import logging
import sys
from typing import List, Optional, Tuple, Type, Union

from capstone import CS_ARCH_ARM, CS_ARCH_ARM64, CS_MODE_ARM, CS_MODE_THUMB, Cs
from unicorn import (
    UC_ARCH_ARM,
    UC_ARCH_ARM64,
    UC_HOOK_CODE,
    UC_MODE_ARM,
    UC_MODE_THUMB,
    Uc,
    UcError,
    arm64_const,
    arm_const,
)
from unicorn.unicorn import UC_HOOK_CODE_TYPE

from . import const, hooks
from .arch import arm_arch, arm64_arch
from .exceptions import EmulatorCrashedException, SymbolMissingException
from .loaders import BaseLoader, ELFLoader, MachOLoader
from .log import get_logger
from .memory import MemoryManager
from .structs import Location, Module, Symbol

if sys.version_info >= (3, 8):
    from typing import Literal
else:
    from typing_extensions import Literal


class Chomper:
    """Lightweight emulation framework for mobile platform (Android, iOS).

    This framework focused on performing encryption or decryption,
    so it doesn't provide support for JNI, Objective-C and file system.

    Args:
        arch: The architecture to emulate, support ARM and ARM64.
        mode: The emulation mode.
        loader: The executable file loader, support ELF and Mach-O.
        logger: The logger to print log.
        byteorder: Default byteorder to use.
        enable_vfp: Enable VFP extension of ARM.
        trace_instr: Print log when any instruction is executed. The emulator will
            call disassembler in real time to display the assembly instructions,
            so this will slow down the emulation.
        trace_symbol_calls: Print log when any symbol is called.
    """

    def __init__(
        self,
        arch: int = const.ARCH_ARM64,
        mode: int = const.MODE_ARM,
        loader: Type[BaseLoader] = ELFLoader,
        logger: Optional[logging.Logger] = None,
        byteorder: Literal["little", "big"] = const.LITTLE_ENDIAN,
        enable_vfp: bool = True,
        trace_instr: bool = False,
        trace_symbol_calls: bool = True,
    ):
        self._setup_arch(arch)

        self.uc = self._create_uc(arch, mode)
        self.cs = self._create_cs(arch, mode)

        self.logger = logger or get_logger(self.__class__.__name__)

        self.byteorder = byteorder
        self._trace_instr = trace_instr
        self._trace_symbol_calls = trace_symbol_calls

        self.modules: List[Module] = []

        self._loader = loader(self)

        # There are some underlying functions in libc that cannot be emulated,
        # so they need to be hooked to skip execution.
        self._init_hooks()

        self._memory_manager = MemoryManager(
            uc=self.uc,
            address=const.HEAP_ADDRESS,
            minimum_pool_size=const.MINIMUM_POOL_SIZE,
        )

        self._setup_emulator(enable_vfp=enable_vfp)

    def _setup_arch(self, arch: int):
        """Setup architecture."""
        if arch == const.ARCH_ARM:
            self.arch = arm_arch
        elif arch == const.ARCH_ARM64:
            self.arch = arm64_arch
        else:
            raise ValueError("Invalid argument arch")

    @staticmethod
    def _create_uc(arch: int, mode: int) -> Uc:
        """Create Unicorn instance."""
        arch = UC_ARCH_ARM if arch == const.ARCH_ARM else UC_ARCH_ARM64
        mode = UC_MODE_THUMB if mode == const.MODE_THUMB else UC_MODE_ARM

        return Uc(arch, mode)

    @staticmethod
    def _create_cs(arch: int, mode: int) -> Cs:
        """Create Capstone instance."""
        arch = CS_ARCH_ARM if arch == const.ARCH_ARM else CS_ARCH_ARM64
        mode = CS_MODE_THUMB if mode == const.MODE_THUMB else CS_MODE_ARM

        return Cs(arch, mode)

    def _init_hooks(self):
        """Initialize default symbol hooks."""
        self.hooks = {
            "__cxa_atexit": hooks.hook_cxa_atexit,
            "__ctype_get_mb_cur_max": hooks.hook_ctype_get_mb_cur_max,
            "arc4random": hooks.hook_arc4random,
            "clock_nanosleep": hooks.hook_nanosleep,
            "free": hooks.hook_free,
            "localeconv_l": hooks.hook_localconv_l,
            "malloc": hooks.hook_malloc,
            "nanosleep": hooks.hook_nanosleep,
            "os_unfair_lock_lock": hooks.hook_os_unfair_lock_lock,
            "os_unfair_lock_unlock": hooks.hook_os_unfair_lock_unlock,
            "pthread_mutex_lock": hooks.hook_pthread_mutex_lock,
            "pthread_mutex_unlock": hooks.hook_pthread_mutex_unlock,
        }

        # Symbols of C standard library always named start with '_' on iOS.
        if isinstance(self._loader, MachOLoader):
            self.hooks = {f"_{name}": cb for name, cb in self.hooks.items()}

    def _setup_stack(self):
        """Setup stack."""
        stack_addr = const.STACK_ADDRESS + const.STACK_SIZE // 2
        self.uc.mem_map(const.STACK_ADDRESS, const.STACK_SIZE)

        self.uc.reg_write(self.arch.reg_sp, stack_addr)
        self.uc.reg_write(self.arch.reg_fp, stack_addr)

    def _setup_thread_register(self):
        """Setup thread register.

        The thread register store the address of thread local storage (TLS).

        The function only allocates a block of memory to TLS and doesn't really
        initialize.
        """
        self.uc.mem_map(const.TLS_ADDRESS, const.TLS_SIZE)

        if isinstance(self._loader, MachOLoader):
            self.uc.reg_write(arm64_const.UC_ARM64_REG_TPIDRRO_EL0, const.TLS_ADDRESS)

        else:
            if self.arch == arm_arch:
                self.uc.reg_write(
                    arm_const.UC_ARM_REG_CP_REG,
                    (15, 0, 0, 13, 0, 0, 3, const.TLS_ADDRESS),  # type: ignore
                )

            elif self.arch == arm64_arch:
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
        addr = self.create_buffer(1024)

        self.uc.mem_write(addr, inst_code)
        self.uc.emu_start(addr | 1, addr + len(inst_code))

        self.free(addr)

    def _setup_emulator(self, enable_vfp: bool = True):
        """Setup emulator."""
        self._setup_stack()
        self._setup_thread_register()

        if self.arch == arm_arch and enable_vfp:
            self._enable_vfp()

    def _start_emulate(self, address: int, *args: int):
        """Start emulate at the specified address."""
        stop_addr = 0

        self.set_arguments(*args)

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
        """Backtrace call stack."""
        call_stack = [self.uc.reg_read(self.arch.reg_lr)]
        frame = self.uc.reg_read(self.arch.reg_fp)
        limit = 16

        for _ in range(limit - 1):
            addr = self.read_address(frame + 8)
            frame = self.read_address(frame)

            if not frame or not addr:
                break

            call_stack.append(addr)

        return [self.locate_address(addr - 4) for addr in call_stack if addr]

    def add_hook(
        self,
        symbol_or_addr: Union[int, str, Symbol],
        callback: UC_HOOK_CODE_TYPE,
        user_data: Optional[dict] = None,
    ) -> int:
        """Add hook to the emulator.

        Args:
            symbol_or_addr: The symbol name or the address to hook. If this is ``str``,
                the function will look up symbol from loaded modules and use its
                address to hook.
            callback: The callback function, same as callback of type ``UC_HOOK_CODE``
                in unicorn.
            user_data: A ``dict`` that contains the data you want to pass to the
                callback function. The ``Chomper`` instance will also be passed in
                as an emulator field.

        Raises:
            SymbolMissingException: If symbol not found.
        """
        if isinstance(symbol_or_addr, int):
            hook_addr = symbol_or_addr
            self.logger.info(f"Hook address at {self.locate_address(hook_addr)}.")

        else:
            symbol = (
                self.find_symbol(symbol_or_addr)
                if isinstance(symbol_or_addr, str)
                else symbol_or_addr
            )
            hook_addr = symbol.address

            if self.arch == arm_arch:
                hook_addr = (hook_addr | 1) - 1

            self.logger.info(
                f"Hook symbol '{symbol.name}' at {self.locate_address(hook_addr)}."
            )

        return self.uc.hook_add(
            UC_HOOK_CODE,
            callback,
            begin=hook_addr,
            end=hook_addr,
            user_data={"emu": self, **(user_data or {})},
        )

    def del_hook(self, handle: int):
        """Delete hook."""
        self.uc.hook_del(handle)

    def add_interceptor(
        self,
        symbol_or_addr: Union[Symbol, str, int],
        callback: UC_HOOK_CODE_TYPE,
        user_data: Optional[dict] = None,
    ):
        """Hook and intercept."""

        def decorator(*args):
            retval = callback(*args)

            if isinstance(retval, int):
                self.set_retval(retval)

            self.uc.reg_write(
                self.arch.reg_pc,
                self.uc.reg_read(self.arch.reg_lr),
            )

        return self.add_hook(
            symbol_or_addr=symbol_or_addr,
            callback=decorator,
            user_data=user_data,
        )

    def _trace_instr_callback(self, uc: Uc, address: int, size: int, _: dict):
        """Trace instruction."""
        for inst in self.cs.disasm_lite(uc.mem_read(address, size), 0):
            self.logger.info(
                f"Trace at {self.locate_address(address)}: {inst[-2]} {inst[-1]}."
            )

    def load_module(
        self,
        module_file: str,
        exec_init_array: bool = False,
        trace_instr: bool = False,
        trace_symbol_calls: bool = False,
    ) -> Module:
        """Load ELF library file from path.

        Args:
            module_file: The path of file to be loaded.
            exec_init_array: Execute initialization functions recorded in the section
                `.init_array` after the module loaded.
            trace_instr: Print log when the instructions in this module are executed.
                The emulator will call disassembler in real time to display the
                assembly instructions, so this will slow down the emulation.
            trace_symbol_calls: Print log when the symbols in this module are called.
        """
        module = self._loader.load_module(
            module_file=module_file,
            exec_init_array=exec_init_array,
            trace_symbol_calls=trace_symbol_calls or self._trace_symbol_calls,
        )

        self.modules.append(module)

        if trace_instr or self._trace_instr:
            # Trace instructions
            self.uc.hook_add(
                UC_HOOK_CODE,
                self._trace_instr_callback,
                begin=module.base,
                end=module.base + module.size,
            )

        if exec_init_array:
            # Execute initialization functions
            for init_func in module.init_array:
                try:
                    self.logger.info(
                        "Execute initialization function %s"
                        % self.locate_address(init_func)
                    )
                    self.call_address(init_func)

                except Exception as e:
                    self.logger.warning(
                        "Initialization function %s execute failed: %s"
                        % (self.locate_address(init_func), repr(e))
                    )

        return module

    def _get_argument_container(self, index: int) -> Tuple[bool, int]:
        """Get the register or address where the specified argument is stored.

        On arch ARM, the first four parameters are stored in the register R0-R3, and
        the rest are stored on the stack. On arch ARM64, the first eight parameters
        are stored in the register X0-X7, and the rest are stored on the stack.

        Returns:
            A ``tuple`` contains a ``bool`` and an ``int``, the first member means
            whether the returned is a register and the second is the actual register
            or address.
        """
        if index >= len(self.arch.reg_args):
            # Read address from stack.
            offset = (index - len(self.arch.reg_args)) * self.arch.addr_size
            address = self.uc.reg_read(self.arch.reg_sp) + offset
            return False, address

        return True, self.arch.reg_args[index]

    def get_argument(self, index: int) -> int:
        """Get argument with the specified index."""
        is_reg, reg_or_addr = self._get_argument_container(index)

        if is_reg:
            return self.uc.reg_read(reg_or_addr)
        else:
            return self.read_int(reg_or_addr, self.arch.addr_size)

    def get_arguments(self, num: int) -> Tuple[int, ...]:
        """Get multiple arguments at once."""
        return tuple([self.get_argument(n) for n in range(num)])

    def set_argument(self, index: int, value: int):
        """Set argument with the specified index."""
        is_reg, reg_or_addr = self._get_argument_container(index)

        if is_reg:
            self.uc.reg_write(reg_or_addr, value)
        else:
            self.write_int(reg_or_addr, value, self.arch.addr_size)

    def set_arguments(self, *args: int):
        """Set multiple arguments at once."""
        for index, value in enumerate(args):
            self.set_argument(index, value)

    def get_retval(self) -> int:
        """Get return value."""
        return self.uc.reg_read(self.arch.reg_retval)

    def set_retval(self, value: int):
        """Set return value."""
        self.uc.reg_write(self.arch.reg_retval, value)

    def create_buffer(self, size: int) -> int:
        """Create a buffer with the size."""
        return self._memory_manager.alloc(size)

    def create_string(self, string: str) -> int:
        """Create a buffer that is initialized to the string."""
        address = self._memory_manager.alloc(len(string) + 1)
        self.write_string(address, string)

        return address

    def free(self, address: int):
        """Free memory."""
        self._memory_manager.free(address)

    def write_int(
        self,
        address: int,
        value: int,
        size: int,
        byteorder: Optional[Literal["little", "big"]] = None,
    ):
        """Write an integer into the address."""
        self.uc.mem_write(
            address, value.to_bytes(size, byteorder=byteorder or self.byteorder)
        )

    def write_bytes(self, address: int, data: bytes):
        """Write bytes into the address."""
        self.uc.mem_write(address, data)

    def write_string(self, address: int, string: str):
        """Write string into the address."""
        self.uc.mem_write(address, string.encode("utf-8") + b"\x00")

    def write_address(self, address: int, value: int):
        """Write an address into the address."""
        self.write_int(address, value, self.arch.addr_size, byteorder=self.byteorder)

    def read_int(
        self,
        address: int,
        size: int,
        byteorder: Optional[Literal["little", "big"]] = None,
    ) -> int:
        """Read an integer from the address."""
        return int.from_bytes(
            self.uc.mem_read(address, size), byteorder=byteorder or self.byteorder
        )

    def read_bytes(self, address: int, size: int) -> bytes:
        """Read bytes from the address."""
        return bytes(self.uc.mem_read(address, size))

    def read_string(self, address: int) -> str:
        """Read string from the address."""
        data = bytes()
        offset = 0

        while True:
            byte = self.read_bytes(address + offset, 1)
            if byte == b"\x00":
                break

            data += byte
            offset += 1

        return data.decode("utf-8")

    def read_address(self, address: int) -> int:
        """Read an address from the address."""
        return self.read_int(address, self.arch.addr_size, byteorder=self.byteorder)

    def call_symbol(self, symbol_name: str, *args: int) -> int:
        """Call function with the symbol name."""
        symbol = self.find_symbol(symbol_name)
        address = symbol.address

        self._start_emulate(address, *args)

        return self.get_retval()

    def call_address(self, address: int, *args: int) -> int:
        """Call function at the address."""
        self._start_emulate(address, *args)

        return self.get_retval()
