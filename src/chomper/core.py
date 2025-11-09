import logging
from functools import wraps
from typing import Callable, Dict, List, Optional, Sequence, Tuple, Union

from capstone import CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_THUMB, Cs
from unicorn import (
    UC_ARCH_ARM,
    UC_ARCH_ARM64,
    UC_HOOK_CODE,
    UC_HOOK_INTR,
    UC_MODE_ARM,
    UC_MODE_THUMB,
    UC_HOOK_MEM_READ,
    UC_HOOK_MEM_WRITE,
    Uc,
    UcError,
    arm64_const,
    arm_const,
)

from . import const
from .arch import arm_arch, arm64_arch
from .context import MemoryContextManager
from .exceptions import EmulatorCrashed, SymbolMissing
from .loader import Module, Symbol
from .log import get_logger
from .memory import MemoryManager
from .objc import ObjcType
from .os import AndroidOs, IosOs
from .typing import (
    EndianType,
    ReturnType,
    HookContext,
    HookFuncCallable,
    HookMemCallable,
)
from .utils import to_signed, bytes_to_float, float_to_bytes

try:
    from capstone import CS_ARCH_AARCH64
except ImportError:
    from capstone import CS_ARCH_ARM64 as CS_ARCH_AARCH64


class Chomper:
    """Lightweight emulation framework for emulating iOS executables and libraries.

    Args:
        arch: The architecture to emulate, support ARM and ARM64.
        mode: The emulation mode.
        os_type: The os type, support Android and iOS.
        logger: The logger to print log.
        endian: Default endian to use.
        enable_vfp: Enable VFP extension of ARM.
        trace_inst: Print log when any instruction is executed. The emulator will
            call disassembler in real time to output the assembly instructions,
            so this will slow down the emulation.
        trace_symbol_calls: Print log when any symbol is called.
        trace_inst_callback: Custom instruction trace callback.
    """

    os: Union[AndroidOs, IosOs]

    def __init__(
        self,
        arch: int = const.ARCH_ARM64,
        mode: int = const.MODE_ARM,
        os_type: int = const.OS_ANDROID,
        logger: Optional[logging.Logger] = None,
        endian: EndianType = const.LITTLE_ENDIAN,
        rootfs_path: Optional[str] = None,
        enable_vfp: bool = True,
        trace_inst: bool = False,
        trace_symbol_calls: bool = False,
        trace_inst_callback: Optional[HookFuncCallable] = None,
    ):
        self._setup_arch(arch)

        self.uc = self._create_uc(arch, mode)
        self.cs = self._create_cs(arch, mode)

        self.logger = logger or get_logger(__name__)

        self.os_type = os_type
        self.endian = endian

        self._trace_inst = trace_inst
        self._trace_symbol_calls = trace_symbol_calls

        self._trace_inst_callback = trace_inst_callback

        self.modules: List[Module] = []

        self.hooks: Dict[str, Callable] = {}

        self.syscall_handlers: Dict[int, Callable] = {}
        self.syscall_names: Dict[int, str] = {}

        # Improve performance of `find_symbol`
        self._cached_modules: List[str] = []
        self._symbol_cache: Dict[str, Symbol] = {}

        self.memory_manager = MemoryManager(
            uc=self.uc,
            address=const.HEAP_ADDRESS,
            minimum_pool_size=const.MINIMUM_POOL_SIZE,
        )

        self._setup_emulator(enable_vfp=enable_vfp)
        self._setup_interrupt_handler()

        self._setup_os(os_type, rootfs_path=rootfs_path)

    @property
    def android_os(self) -> AndroidOs:
        assert isinstance(self.os, AndroidOs)
        return self.os

    @property
    def ios_os(self) -> IosOs:
        assert isinstance(self.os, IosOs)
        return self.os

    def _setup_arch(self, arch: int):
        """Setup architecture."""
        if arch == const.ARCH_ARM:
            self.arch = arm_arch
        elif arch == const.ARCH_ARM64:
            self.arch = arm64_arch
        else:
            raise ValueError("Invalid argument arch")

    def _setup_os(self, os_type: int, **kwargs):
        """Setup operating system."""
        if os_type == const.OS_ANDROID:
            self.os = AndroidOs(self, **kwargs)
        elif os_type == const.OS_IOS:
            self.os = IosOs(self, **kwargs)
        else:
            raise ValueError("Unsupported platform type")

        self.os.initialize()

    @staticmethod
    def _create_uc(arch: int, mode: int) -> Uc:
        """Create Unicorn instance."""
        arch = UC_ARCH_ARM if arch == const.ARCH_ARM else UC_ARCH_ARM64
        mode = UC_MODE_THUMB if mode == const.MODE_THUMB else UC_MODE_ARM

        uc = Uc(arch, mode)

        if arch == const.ARCH_ARM64:
            # This CPU mode supports additional instruction sets, which is particularly
            # useful for iOS emulation. For example, it includes atomic instructions
            # from ARMv8.1 and PAC instructions from ARMv8.3.
            uc.ctl_set_cpu_model(arm64_const.UC_CPU_ARM64_MAX)

        return uc

    @staticmethod
    def _create_cs(arch: int, mode: int) -> Cs:
        """Create Capstone instance."""
        arch = CS_ARCH_ARM if arch == const.ARCH_ARM else CS_ARCH_AARCH64
        mode = CS_MODE_THUMB if mode == const.MODE_THUMB else CS_MODE_ARM

        return Cs(arch, mode)

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
        self.uc.mem_map(const.TLS_ADDRESS - 1024, const.TLS_SIZE + 1024)

        if self.os_type == const.OS_IOS:
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

        with self.mem_context() as ctx:
            address = ctx.create_buffer(1024)
            self.uc.mem_write(address, inst_code)

            self.uc.emu_start(address | 1, address + len(inst_code))

    def _setup_emulator(self, enable_vfp: bool = True):
        """Setup emulator."""
        self._setup_stack()
        self._setup_thread_register()

        if self.arch == arm_arch and enable_vfp:
            self._enable_vfp()

    def _start_emulate(
        self,
        address: int,
        *args: int,
        va_list: Optional[Sequence[int]] = None,
        return_type: ReturnType = "int",
    ) -> int:
        """Start emulate at the specified address."""
        context = self.uc.context_save()
        stop_addr = self.create_buffer(8)

        self.set_args(args, va_list=va_list)

        # Set the value of register LR to the stop address of the emulation,
        # so that when the function returns, it will jump to this address.
        self.uc.reg_write(self.arch.reg_lr, stop_addr)
        self.uc.reg_write(self.arch.reg_pc, address)
        self.uc.reg_write(self.arch.reg_fp, 0)

        try:
            # self.logger.info(f"Start emulate at {self.debug_symbol(address)}")
            self.uc.emu_start(address, stop_addr)
            return self.get_retval(return_type=return_type)
        except UcError as e:
            self.crash("Unknown reason", exc=e)
        finally:
            self.uc.context_restore(context)
            self.free(stop_addr)

        # Pass type hints
        return 0

    def find_module(self, name: str) -> Optional[Module]:
        """Find module by name."""
        for module in self.modules:
            if module.name == name:
                return module
        return None

    def find_module_by_address(self, address: int) -> Optional[Module]:
        """Find module by address."""
        for module in self.modules:
            if module.contains(address):
                return module
        return None

    def find_symbol(self, name: str) -> Optional[Symbol]:
        """Find symbol by name."""
        try:
            return self.get_symbol(name)
        except SymbolMissing:
            return None

    def get_symbol(self, name: str) -> Symbol:
        """Get symbol by name.

        Raises:
            SymbolMissingException: If symbol not found.
        """
        if name in self._symbol_cache:
            return self._symbol_cache[name]

        for module in self.modules:
            if module.name in self._cached_modules:
                continue

            for symbol in module.symbols:
                self._symbol_cache[symbol.name] = symbol

                if symbol.name == name:
                    return symbol

        raise SymbolMissing(f"{name} not found")

    def debug_symbol(self, address: int) -> str:
        """Format address to `libfoo.so!0x1000`."""
        module = self.find_module_by_address(address)

        if module:
            offset = address - module.base

            if module.has_dyld_info:
                offset += module.dyld_info.image_base

            return f"{module.name}!{hex(offset)}"

        return hex(address)

    def backtrace(self) -> List[int]:
        """Backtrace call stack."""
        stack = [
            self.uc.reg_read(self.arch.reg_pc),
            self.uc.reg_read(self.arch.reg_lr) - 4,
        ]

        frame = self.uc.reg_read(self.arch.reg_fp)
        if not frame:
            return stack

        limit = 32

        for _ in range(limit - 1):
            address = self.read_pointer(frame + 8)
            frame = self.read_pointer(frame)

            if not frame or not address:
                break

            if address < const.MODULE_ADDRESS:
                continue

            stack.append(address - 4)

        return stack

    def log_backtrace(self):
        """Output backtrace log."""
        self.logger.info(
            "Backtrace: %s",
            " <- ".join([self.debug_symbol(t) for t in self.backtrace()]),
        )

    def add_hook(
        self,
        target: Union[int, str],
        callback: Optional[HookFuncCallable] = None,
        user_data: Optional[dict] = None,
        return_callback: Optional[HookFuncCallable] = None,
    ) -> int:
        """Add hook to the emulator.

        Args:
            target: The symbol name or the address to hook. If it is `str`,
                the function will look up symbol from loaded modules and use its
                address to hook.
            callback: The callback function, same as callback of type `UC_HOOK_CODE`
                in unicorn.
            user_data: A `dict` that contains the data you want to pass to the
                callback function. The `Chomper` instance will also be passed in
                as an emulator field.
            return_callback: If a function is hooked, the callback will be triggered
                upon its return.

        Raises:
            SymbolMissingException: If symbol not found.
        """
        if not callback and not return_callback:
            raise ValueError("No callback specified")

        def wrapper(uc: Uc, address: int, size: int, user_data_: HookContext):
            if callback:
                callback(uc, address, size, user_data_)

            if return_callback:
                return_addr = self.uc.reg_read(self.arch.reg_lr)

                if self.arch == arm64_arch:
                    inst_code = 0xD65F03C0  # ret
                elif self.arch == arm_arch:
                    inst_code = 0xE12FFF1E  # bx lr
                else:
                    raise EmulatorCrashed("Unsupported arch")

                buffer = self.create_buffer(4)
                self.write_u32(buffer, inst_code)

                self.uc.reg_write(self.arch.reg_lr, buffer)

                self.add_hook(
                    buffer,
                    return_wrapper,
                    user_data={"return_addr": return_addr, **(user_data or {})},
                )

        def return_wrapper(uc: Uc, address: int, size: int, user_data_: HookContext):
            assert return_callback
            return_callback(uc, address, size, user_data_)

            self.uc.reg_write(self.arch.reg_lr, user_data_["return_addr"])

        if isinstance(target, int):
            hook_addr = target
        else:
            symbol = self.get_symbol(target)
            hook_addr = symbol.address

        if self.arch == arm_arch:
            hook_addr = (hook_addr | 1) - 1

        return self.uc.hook_add(
            UC_HOOK_CODE,
            wrapper,
            begin=hook_addr,
            end=hook_addr,
            user_data={"emu": self, **(user_data or {})},
        )

    def add_mem_hook(
        self,
        hook_type: int,
        callback: HookMemCallable,
        begin: int = 1,
        end: int = 0,
        user_data: Optional[dict] = None,
    ) -> int:
        """
        Add memory access hook to the emulator.

        Args:
            hook_type: HOOK_MEM_READ or HOOK_MEM_WRITE (defined in chomper.consts)
            callback: Memory hook callback with signature:
                    (uc, access, address, size, value, user_data) -> None
            begin: Start address of memory range to hook. Default is 1.
            end: End address of memory range to hook. Default is 0 (hook all).
            user_data: Optional dictionary passed to callback. `emu` will be added
                automatically.

        Raises:
            ValueError: If hook_type is invalid.
        """
        hook_type_map = {
            const.HOOK_MEM_READ: UC_HOOK_MEM_READ,
            const.HOOK_MEM_WRITE: UC_HOOK_MEM_WRITE,
        }
        uc_hook_type = hook_type_map.get(hook_type)
        if uc_hook_type is None:
            raise ValueError("Invalid argument hook_type")

        return self.uc.hook_add(
            uc_hook_type,
            callback,
            begin=begin,
            end=end,
            user_data={"emu": self, **(user_data or {})},
        )

    def add_interceptor(
        self,
        target: Union[int, str],
        callback: HookFuncCallable,
        user_data: Optional[dict] = None,
    ) -> int:
        """Add interceptor to the emulator."""

        @wraps(callback)
        def decorator(uc: Uc, address: int, size: int, user_data_: HookContext):
            emu = user_data_["emu"]
            address = emu.uc.reg_read(emu.arch.reg_pc)

            retval = callback(uc, address, size, user_data_)

            if isinstance(retval, int):
                emu.set_retval(retval)
            elif isinstance(retval, ObjcType):
                emu.set_retval(int(retval))

            if address == emu.uc.reg_read(emu.arch.reg_pc):
                emu.uc.reg_write(emu.arch.reg_pc, emu.uc.reg_read(emu.arch.reg_lr))

        return self.add_hook(target, decorator, user_data)

    def del_hook(self, handle: int):
        """Delete hook."""
        self.uc.hook_del(handle)

    def crash(self, message: str, exc: Optional[Exception] = None):
        """Raise an emulator crashed exception and output debugging info.

        Raises:
            EmulatorCrashedException:
        """
        address = self.uc.reg_read(self.arch.reg_pc)
        self.logger.error(
            "Emulator crashed from: %s",
            " <- ".join([self.debug_symbol(t) for t in self.backtrace()]),
        )

        raise EmulatorCrashed(f"{message} at {self.debug_symbol(address)}") from exc

    def trace_symbol_call_callback(
        self, uc: Uc, address: int, size: int, user_data: dict
    ):
        """Trace symbol call."""
        symbol = user_data["symbol"]
        ret_addr = self.uc.reg_read(self.arch.reg_lr)

        if ret_addr:
            self.logger.info(
                f'Symbol "{symbol.name}" called from {self.debug_symbol(ret_addr)}'
            )
        else:
            self.logger.info(f'Symbol "{symbol.name}" called')

    def trace_inst_callback(
        self, uc: Uc, address: int, size: int, user_data: HookContext
    ):
        """Trace instruction."""
        if self._trace_inst_callback:
            self._trace_inst_callback(uc, address, size, user_data)
        else:
            inst = next(self.cs.disasm_lite(uc.mem_read(address, size), address))
            self.logger.info(
                f"Trace at {self.debug_symbol(address)}: {inst[-2]} {inst[-1]}"
            )

    @staticmethod
    def missing_symbol_required_callback(*args):
        """Raise an exception with information of missing symbol."""
        user_data = args[-1]
        symbol_name = user_data["symbol_name"]

        raise EmulatorCrashed(
            f"Missing symbol '{symbol_name}' is required, "
            f"you should load the library that contains it."
        )

    def _setup_interrupt_handler(self):
        """Setup interrupt handler."""
        self.uc.hook_add(UC_HOOK_INTR, self._interrupt_callback)

    def _interrupt_callback(self, uc: Uc, intno: int, user_data: dict):
        """Handle interrupts from emulators, such as 'svc'."""
        if intno == 2:
            self._dispatch_syscall()
            return

        self.crash(f"Unhandled interruption {intno}")

    def _dispatch_syscall(self):
        """Dispatch system calls to the registered handlers of the OS."""
        syscall_no = None
        syscall_name = None
        syscall_display = None

        if self.os_type == const.OS_IOS:
            syscall_no = to_signed(self.uc.reg_read(arm64_const.UC_ARM64_REG_W16), 4)
            syscall_name = self.syscall_names.get(syscall_no)
        elif self.os_type == const.OS_ANDROID and self.arch == arm64_arch:
            syscall_no = to_signed(self.uc.reg_read(arm64_const.UC_ARM64_REG_W8), 4)
            syscall_name = self.syscall_names.get(syscall_no)

        if syscall_no:
            syscall_display = f"'{syscall_name}'" if syscall_name else hex(syscall_no)
            from_addr = self.debug_symbol(self.uc.reg_read(self.arch.reg_pc))
            self.logger.info(f"System call {syscall_display} invoked from {from_addr}")

            syscall_handler = self.syscall_handlers.get(syscall_no)

            if syscall_handler:
                result = syscall_handler(self)
                if result is not None:
                    self.set_retval(result)
                return

        if syscall_display is not None:
            self.crash(f"Unhandled system call {syscall_display}")
        else:
            self.crash("Unhandled system call")

    def add_inst_trace(self, module: Module):
        """Add instruction trace for the module."""
        for region in module.regions:
            self.uc.hook_add(
                UC_HOOK_CODE,
                self.trace_inst_callback,
                begin=region.start,
                end=region.end,
                user_data={"emu": self},
            )

        # Ensure trace effect
        self.uc.ctl_flush_tb()  # type: ignore

    def exec_init_array(self, init_array: List[int]):
        """Execute initialization functions."""
        for init_func in init_array:
            if not init_func:
                continue

            try:
                self.logger.info(
                    f"Execute initialization function {self.debug_symbol(init_func)}"
                )
                self.call_address(init_func)
            except EmulatorCrashed as e:
                self.logger.warning(
                    f"Execute {self.debug_symbol(init_func)} failed: {repr(e)}"
                )

    def load_module(
        self,
        module_file: str,
        module_base: Optional[int] = None,
        exec_init_array: bool = True,
        exec_objc_init: bool = True,
        trace_inst: bool = False,
        trace_symbol_calls: bool = False,
    ) -> Module:
        """Load executable file from path.

        Args:
            module_file: The path of file to be loaded.
            module_base: The address for loading the module. If it is `None`,
                the loader will automatically select the address.
            exec_init_array: Execute initialization functions recorded in the section
                `.init_array` after the module loaded.
            exec_objc_init: Execute `_objc_init` function after the module loaded.
            trace_inst: Output log when the instructions in this module are executed.
                The emulator will call disassembler in real time to display the
                assembly instructions, so this will slow down the emulation.
            trace_symbol_calls: Output log when the symbols in this module are called.
        """
        if self.os_type == const.OS_IOS:
            self.ios_os.set_executable_file(module_file)

        module = self.os.loader.load(
            module_base=module_base,
            module_file=module_file,
            trace_symbol_calls=trace_symbol_calls or self._trace_symbol_calls,
        )
        self.modules.append(module)

        # Trace instructions
        if trace_inst or self._trace_inst:
            self.add_inst_trace(module)

        if exec_objc_init and self.os_type == const.OS_IOS:
            self.ios_os.init_objc(module)

        if exec_init_array and module.init_array:
            self.exec_init_array(module.init_array)

        return module

    def _get_arg_container(self, index: int) -> Tuple[bool, int]:
        """Get the register or address where the specified argument is stored.

        On arch ARM, the first four parameters are stored in the register R0-R3, and
        the rest are stored on the stack. On arch ARM64, the first eight parameters
        are stored in the register X0-X7, and the rest are stored on the stack.

        Returns:
            A `tuple` contains a `bool` and an `int`, the first member means
            whether the returned is a register and the second is the actual register
            or address.
        """
        if index >= len(self.arch.reg_args):
            # Read address from stack.
            offset = (index - len(self.arch.reg_args)) * self.arch.addr_size
            address = self.uc.reg_read(self.arch.reg_sp) + offset
            return False, address

        return True, self.arch.reg_args[index]

    def get_arg(self, index: int) -> int:
        """Get argument with the specified index."""
        is_reg, reg_or_addr = self._get_arg_container(index)

        if is_reg:
            return self.uc.reg_read(reg_or_addr)
        else:
            return self.read_int(reg_or_addr, self.arch.addr_size)

    def set_arg(self, index: int, value: int):
        """Set argument with the specified index."""
        is_reg, reg_or_addr = self._get_arg_container(index)

        if is_reg:
            self.uc.reg_write(reg_or_addr, value)
        else:
            self.write_int(reg_or_addr, value, self.arch.addr_size)

    def set_args(self, args: Sequence[int], va_list: Optional[Sequence[int]] = None):
        """Set arguments before call function.

        Args:
            args: General arguments.
            va_list: Variable number of arguments.
        """
        for index, value in enumerate(args):
            self.set_arg(index, value)

        if va_list:
            for index, value in enumerate(va_list):
                self.set_arg(self.arch.addr_size + index, value)
            self.set_arg(self.arch.addr_size + len(va_list), 0)

    def _get_retval_reg(self, return_type: ReturnType) -> int:
        if return_type == "float":
            return self.arch.reg_float_retval
        elif return_type == "double":
            return self.arch.reg_double_retval
        return self.arch.reg_retval

    def get_retval(self, return_type: ReturnType = "int") -> int:
        """Get return value."""
        reg_id = self._get_retval_reg(return_type)
        return self.uc.reg_read(reg_id)

    def set_retval(self, value: int, return_type: ReturnType = "int"):
        """Set return value."""
        reg_id = self._get_retval_reg(return_type)
        self.uc.reg_write(reg_id, value)

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

    def read_int(self, address: int, size: int, signed: bool = False) -> int:
        """Read an integer from the address."""
        return int.from_bytes(
            self.uc.mem_read(address, size),
            signed=signed,
            byteorder=self.endian,
        )

    def read_s8(self, address: int) -> int:
        """Read a signed int8 from the address."""
        return self.read_int(address, 1, True)

    def read_s16(self, address: int) -> int:
        """Read a signed int16 from the address."""
        return self.read_int(address, 2, True)

    def read_s32(self, address: int) -> int:
        """Read a signed int32 from the address."""
        return self.read_int(address, 4, True)

    def read_s64(self, address: int) -> int:
        """Read a signed int64 from the address."""
        return self.read_int(address, 8, True)

    def read_u8(self, address: int) -> int:
        """Read an unsigned int8 from the address."""
        return self.read_int(address, 1, False)

    def read_u16(self, address: int) -> int:
        """Read an unsigned int16 from the address."""
        return self.read_int(address, 2, False)

    def read_u32(self, address: int) -> int:
        """Read an unsigned int32 from the address."""
        return self.read_int(address, 4, False)

    def read_u64(self, address: int) -> int:
        """Read an unsigned int64 from the address."""
        return self.read_int(address, 8, False)

    def read_float(self, address: int) -> float:
        """Read a float from the address."""
        data = self.read_bytes(address, 4)
        return bytes_to_float(data, self.endian)

    def read_double(self, address: int) -> float:
        """Read a double from the address."""
        data = self.read_bytes(address, 8)
        return bytes_to_float(data, self.endian)

    def read_bytes(self, address: int, size: int) -> bytes:
        """Read bytes from the address."""
        return bytes(self.uc.mem_read(address, size))

    def read_string(self, address: int) -> str:
        """Read string from the address."""
        data = bytes()

        block_size = 1024
        end = b"\x00"

        try:
            while True:
                buf = self.read_bytes(address, block_size)
                if buf.find(end) != -1:
                    data += buf[: buf.index(end)]
                    break

                data += buf
                address += block_size
        except UcError:
            for i in range(block_size):
                buf = self.read_bytes(address + i, 1)
                if buf == end:
                    break

                data += buf

        return data.decode("utf-8")

    def read_pointer(self, address: int) -> int:
        """Read a pointer from the address."""
        return self.read_int(address, self.arch.addr_size)

    def read_array(
        self,
        begin: int,
        end: int,
        size: Optional[int] = None,
        signed: bool = False,
    ) -> List[int]:
        """Read an array from the address."""
        if size is None:
            size = self.arch.addr_size

        data = self.read_bytes(begin, end - begin)
        array = []

        for offset in range(0, len(data), size):
            int_bytes = data[offset : offset + size]
            value = int.from_bytes(int_bytes, byteorder=self.endian, signed=signed)
            array.append(value)

        return array

    def write_int(self, address: int, value: int, size: int, signed: bool = False):
        """Write an integer into the address."""
        self.uc.mem_write(
            address,
            value.to_bytes(size, byteorder=self.endian, signed=signed),
        )

    def write_s8(self, address: int, value: int):
        """Write a signed int8 into the address."""
        self.write_int(address, value, 1, True)

    def write_s16(self, address: int, value: int):
        """Write a signed int16 into the address."""
        self.write_int(address, value, 2, True)

    def write_s32(self, address: int, value: int):
        """Write a signed int32 into the address."""
        self.write_int(address, value, 4, True)

    def write_s64(self, address: int, value: int):
        """Write a signed int64 into the address."""
        self.write_int(address, value, 8, True)

    def write_u8(self, address: int, value: int):
        """Write an unsigned int8 into the address."""
        self.write_int(address, value, 1, False)

    def write_u16(self, address: int, value: int):
        """Write an unsigned int16 into the address."""
        self.write_int(address, value, 2, False)

    def write_u32(self, address: int, value: int):
        """Write an unsigned int32 into the address."""
        self.write_int(address, value, 4, False)

    def write_u64(self, address: int, value: int):
        """Write an unsigned int64 into the address."""
        self.write_int(address, value, 8, False)

    def write_float(self, address: int, value: float):
        """Write a float into the address."""
        data = float_to_bytes(value, self.endian, const.SINGLE_PRECISION)
        self.write_bytes(address, data)

    def write_double(self, address: int, value: float):
        """Write a double into the address."""
        data = float_to_bytes(value, self.endian, const.DOUBLE_PRECISION)
        self.write_bytes(address, data)

    def write_bytes(self, address: int, data: bytes):
        """Write bytes into the address."""
        self.uc.mem_write(address, data)

    def write_string(self, address: int, string: str):
        """Write string into the address."""
        self.uc.mem_write(address, string.encode("utf-8") + b"\x00")

    def write_pointer(self, address: int, value: int):
        """Write a pointer into the address."""
        self.write_int(address, value, self.arch.addr_size)

    def write_array(
        self,
        address: int,
        array: Sequence[int],
        size: Optional[int] = None,
        signed: bool = False,
    ):
        """Write an array into the address."""
        if size is None:
            size = self.arch.addr_size

        data = b"".join(
            value.to_bytes(size, self.endian, signed=signed) for value in array
        )
        self.write_bytes(address, data)

    def call_symbol(
        self,
        symbol_name: str,
        *args: int,
        va_list: Optional[Sequence[int]] = None,
        return_type: ReturnType = "int",
    ) -> int:
        """Call function with the symbol name."""
        self.logger.info(f'Call symbol "{symbol_name}"')

        symbol = self.get_symbol(symbol_name)
        address = symbol.address

        return self._start_emulate(
            address,
            *args,
            va_list=va_list,
            return_type=return_type,
        )

    def call_address(
        self,
        address: int,
        *args: int,
        va_list: Optional[Sequence[int]] = None,
        return_type: ReturnType = "int",
    ) -> int:
        """Call function at the address."""
        return self._start_emulate(
            address,
            *args,
            va_list=va_list,
            return_type=return_type,
        )

    def mem_context(self) -> MemoryContextManager:
        """Automatically release memory allocated through the context.

        Examples:

        ```python
        with emu.mem_context() as ctx:
            # This memory does not require manual release
            ctx.create_buffer(64)
        ```
        """
        return MemoryContextManager(self)  # type: ignore
