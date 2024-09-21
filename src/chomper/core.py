import logging
from functools import wraps
from typing import Callable, Dict, List, Optional, Tuple, Union

from capstone import CS_ARCH_ARM, CS_ARCH_ARM64, CS_MODE_ARM, CS_MODE_THUMB, Cs
from unicorn import (
    UC_ARCH_ARM,
    UC_ARCH_ARM64,
    UC_HOOK_CODE,
    UC_HOOK_INTR,
    UC_MODE_ARM,
    UC_MODE_THUMB,
    Uc,
    UcError,
    arm64_const,
    arm_const,
)

from . import const
from .arch import arm_arch, arm64_arch
from .exceptions import EmulatorCrashedException, SymbolMissingException
from .instruction import AutomicInstruction
from .memory import MemoryManager
from .types import Module, Symbol
from .log import get_logger
from .os.android import AndroidOs
from .os.ios import IosOs
from .utils import aligned


class Chomper:
    """Lightweight emulation framework for emulating iOS executables and libraries.

    Args:
        arch: The architecture to emulate, support ARM and ARM64.
        mode: The emulation mode.
        os_type: The os type, support Android and iOS.
        logger: The logger to print log.
        endian: Default endian to use.
        enable_vfp: Enable VFP extension of ARM.
        enable_objc: Enable Objective-C runtime of iOS.
        enable_ui_kit: Enable UIKit framework of iOS.
        trace_inst: Print log when any instruction is executed. The emulator will
            call disassembler in real time to output the assembly instructions,
            so this will slow down the emulation.
        trace_symbol_calls: Print log when any symbol is called.
    """

    os: Union[AndroidOs, IosOs]

    def __init__(
        self,
        arch: int = const.ARCH_ARM64,
        mode: int = const.MODE_ARM,
        os_type: int = const.OS_ANDROID,
        logger: Optional[logging.Logger] = None,
        endian: const.EndianType = const.LITTLE_ENDIAN,
        rootfs_path: Optional[str] = None,
        enable_vfp: bool = True,
        enable_objc: bool = True,
        enable_ui_kit: bool = False,
        trace_inst: bool = False,
        trace_symbol_calls: bool = False,
    ):
        self._setup_arch(arch)

        self.uc = self._create_uc(arch, mode)
        self.cs = self._create_cs(arch, mode)

        self.logger = logger or get_logger(self.__class__.__name__)

        self.os_type = os_type
        self.endian = endian

        self.enable_objc = enable_objc
        self.enable_ui_kit = enable_ui_kit

        self._trace_inst = trace_inst
        self._trace_symbol_calls = trace_symbol_calls

        self.modules: List[Module] = []

        self.hooks: Dict[str, Callable] = {}
        self.syscall_handlers: Dict[int, Callable] = {}

        self.memory_manager = MemoryManager(
            uc=self.uc,
            address=const.HEAP_ADDRESS,
            minimum_pool_size=const.MINIMUM_POOL_SIZE,
        )

        self._setup_emulator(enable_vfp=enable_vfp)
        self._setup_interrupt_handler()

        self._setup_os(os_type, rootfs_path=rootfs_path)

        self.os.initialize()

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

    def _start_emulate(self, address: int, *args: int) -> int:
        """Start emulate at the specified address."""
        context = self.uc.context_save()

        stop_addr = self.create_buffer(8)

        for index, value in enumerate(args):
            self.set_arg(index, value)

        # Set the value of register LR to the stop address of the emulation,
        # so that when the function returns, it will jump to this address.
        self.uc.reg_write(self.arch.reg_lr, stop_addr)
        self.uc.reg_write(self.arch.reg_pc, address)
        self.uc.reg_write(self.arch.reg_fp, 0)

        try:
            self.logger.info(f"Start emulate at {self.debug_symbol(address)}")
            self.uc.emu_start(address, stop_addr)

            return self.get_retval()

        except UcError as e:
            self.crash("Unknown reason", from_exc=e)

        finally:
            self.uc.context_restore(context)

            self.free(stop_addr)

        # Pass type hints
        return 0

    def find_module(self, name_or_addr: Union[str, int]) -> Optional[Module]:
        """Find module by name or address."""
        for module in self.modules:
            if isinstance(name_or_addr, str):
                if module.name == name_or_addr:
                    return module

            elif isinstance(name_or_addr, int):
                if module.base <= name_or_addr < module.base + module.size:
                    return module

        return None

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

    def debug_symbol(self, address: int) -> str:
        """Format address to `libtest.so!0x1000` or `0x10000`."""
        module = self.find_module(address)

        if module:
            offset = address - module.base + (module.image_base or 0)
            return f"{module.name}!0x{offset:x}"

        return f"0x{address:x}"

    def backtrace(self) -> List[Tuple[int, Optional[Module]]]:
        """Backtrace call stack."""
        stack = [self.uc.reg_read(self.arch.reg_pc)]
        stack += [self.uc.reg_read(self.arch.reg_lr) - 4]

        frame = self.uc.reg_read(self.arch.reg_fp)
        limit = 32

        for _ in range(limit - 1):
            address = self.read_pointer(frame + 8)
            frame = self.read_pointer(frame)

            if not frame or not address:
                break

            if address < const.MODULE_ADDRESS:
                continue

            stack.append(address - 4)

        return [(address, self.find_module(address)) for address in stack if address]

    def add_hook(
        self,
        symbol_or_addr: Union[int, str],
        callback: Callable,
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

        else:
            symbol = self.find_symbol(symbol_or_addr)
            hook_addr = symbol.address

        if self.arch == arm_arch:
            hook_addr = (hook_addr | 1) - 1

        return self.uc.hook_add(
            UC_HOOK_CODE,
            callback,
            begin=hook_addr,
            end=hook_addr,
            user_data={"emu": self, **(user_data or {})},
        )

    def add_interceptor(
        self,
        symbol_or_addr: Union[int, str],
        callback: Callable,
        user_data: Optional[dict] = None,
    ):
        """Add interceptor to the emulator."""

        @wraps(callback)
        def decorator(uc, address, size, user_data_):
            emu = user_data_["emu"]
            address = emu.uc.reg_read(emu.arch.reg_pc)

            retval = callback(uc, address, size, user_data_)

            if isinstance(retval, int):
                emu.set_retval(retval)

            if address == emu.uc.reg_read(emu.arch.reg_pc):
                emu.uc.reg_write(emu.arch.reg_pc, emu.uc.reg_read(emu.arch.reg_lr))

        return self.add_hook(symbol_or_addr, decorator, user_data)

    def del_hook(self, handle: int):
        """Delete hook."""
        self.uc.hook_del(handle)

    def crash(self, message: str, from_exc: Optional[Exception] = None):
        """Raise an emulator crashed exception and output debugging info.

        Raises:
            EmulatorCrashedException:
        """
        # Log backtrace
        trace_stack = [self.debug_symbol(t[0]) for t in self.backtrace()]
        message_ = "Backtrace: %s" % ", ".join(trace_stack)
        self.logger.info(message_)

        # Log registers
        message_ = "State: "

        for reg_index in range(31):
            reg_id = getattr(arm64_const, f"UC_ARM64_REG_X{reg_index}")
            reg_value = self.uc.reg_read(reg_id)

            if reg_index:
                message_ += ", "

            message_ += f"x{reg_index}: 0x{reg_value:016x}"

            if self.find_module(reg_value):
                message_ += f" [{self.debug_symbol(reg_value)}]"

        self.logger.info(message_)

        address = self.uc.reg_read(self.arch.reg_pc)
        message = f"{message} at {self.debug_symbol(address)}"

        if from_exc:
            raise EmulatorCrashedException(message) from from_exc

        raise EmulatorCrashedException(message)

    def trace_symbol_call_callback(
        self, uc: Uc, address: int, size: int, user_data: dict
    ):
        """Trace symbol call."""
        symbol = user_data["symbol"]

        if self.arch == arm_arch:
            ret_addr = self.uc.reg_read(arm_const.UC_ARM_REG_LR)
        else:
            ret_addr = self.uc.reg_read(arm64_const.UC_ARM64_REG_LR)

        self.logger.info(
            f'Symbol "{symbol.name}" called'
            + (f" from {self.debug_symbol(ret_addr)}" if ret_addr else "")
        )

    def trace_inst_callback(self, uc: Uc, address: int, size: int, user_data: dict):
        """Trace instruction."""
        for inst in self.cs.disasm_lite(uc.mem_read(address, size), 0):
            self.logger.info(
                f"Trace at {self.debug_symbol(address)}: {inst[-2]} {inst[-1]}"
            )

    @staticmethod
    def missing_symbol_required_callback(*args):
        """Raise an exception with information of missing symbol."""
        user_data = args[-1]
        symbol_name = user_data["symbol_name"]

        raise EmulatorCrashedException(
            f'Missing symbol "{symbol_name}" is required, '
            f"you should load the library that contains it."
        )

    def _setup_interrupt_handler(self):
        """Setup interrupt handler."""
        self.uc.hook_add(UC_HOOK_INTR, self._interrupt_callback)

    def _interrupt_callback(self, uc: Uc, intno: int, user_data: dict):
        """Handle interrupt from emulators.

        There are currently two types of interrupts that need to be actively handled,
        system calls and some unsupported instructions.
        """
        if intno == 2:
            self._dispatch_syscall()
            return

        elif intno in (1, 4):
            # Handle cpu exceptions
            address = self.uc.reg_read(self.arch.reg_pc)
            code = uc.mem_read(address, 4)

            try:
                AutomicInstruction(self, code).execute()
                self.uc.reg_write(arm64_const.UC_ARM64_REG_PC, address + 4)
                return

            except ValueError:
                pass

        self.crash("Unhandled interruption %s" % (intno,))

    def _dispatch_syscall(self):
        """Dispatch system calls to the registered handlers of the OS."""
        if self.os_type == const.OS_IOS:
            syscall_no = self.uc.reg_read(arm64_const.UC_ARM64_REG_X16)
            syscall_handler = self.syscall_handlers.get(syscall_no)

            if syscall_handler:
                result = syscall_handler(self)

                if result is not None:
                    self.set_retval(result)

                return

        self.crash("Unhandled system call")

    def add_inst_trace(self, module: Module):
        """Add instruction trace for the module."""
        self.uc.hook_add(
            UC_HOOK_CODE,
            self.trace_inst_callback,
            begin=module.base,
            end=module.base + module.size,
        )

    def exec_init_array(self, init_array: List[int]):
        """Execute initialization functions."""
        for init_func in init_array:
            if not init_func:
                continue

            try:
                self.logger.info(
                    "Execute initialization function %s" % self.debug_symbol(init_func)
                )
                self.call_address(init_func)

            except Exception as e:
                self.logger.warning(
                    "c %s execute failed: %s" % (self.debug_symbol(init_func), repr(e))
                )

    def load_module(
        self,
        module_file: str,
        exec_init_array: bool = False,
        exec_objc_init: bool = True,
        trace_inst: bool = False,
        trace_symbol_calls: bool = False,
    ) -> Module:
        """Load executable file from path.

        Args:
            module_file: The path of file to be loaded.
            exec_init_array: Execute initialization functions recorded in the section
                `.init_array` after the module loaded.
            exec_objc_init: Execute `_objc_init` function after the module loaded.
            trace_inst: Output log when the instructions in this module are executed.
                The emulator will call disassembler in real time to display the
                assembly instructions, so this will slow down the emulation.
            trace_symbol_calls: Output log when the symbols in this module are called.
        """
        if not self.modules:
            module_base = const.MODULE_ADDRESS
        else:
            prev = self.modules[-1]
            module_base = aligned(prev.base + prev.size, 1024 * 1024)

        module = self.os.loader.load(
            module_base=module_base,
            module_file=module_file,
            trace_symbol_calls=trace_symbol_calls or self._trace_symbol_calls,
        )
        self.modules.append(module)

        # Trace instructions
        if trace_inst or self._trace_inst:
            self.add_inst_trace(module)

        if exec_objc_init and isinstance(self.os, IosOs):
            self.os.init_objc(module)

        if exec_init_array:
            self.exec_init_array(module.init_array)

        return module

    def _get_arg_container(self, index: int) -> Tuple[bool, int]:
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

    def get_retval(self) -> int:
        """Get return value."""
        return self.uc.reg_read(self.arch.reg_retval)

    def set_retval(self, value: int):
        """Set return value."""
        self.uc.reg_write(self.arch.reg_retval, value)

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

    def read_s8(self, address: int):
        """Read a signed int8 from the address."""
        return self.read_int(address, 1, True)

    def read_s16(self, address: int):
        """Read a signed int16 from the address."""
        return self.read_int(address, 2, True)

    def read_s32(self, address: int):
        """Read a signed int32 from the address."""
        return self.read_int(address, 4, True)

    def read_s64(self, address: int):
        """Read a signed int64 from the address."""
        return self.read_int(address, 8, True)

    def read_u8(self, address: int):
        """Read an unsigned int8 from the address."""
        return self.read_int(address, 1, False)

    def read_u16(self, address: int):
        """Read an unsigned int16 from the address."""
        return self.read_int(address, 2, False)

    def read_u32(self, address: int):
        """Read an unsigned int32 from the address."""
        return self.read_int(address, 4, False)

    def read_u64(self, address: int):
        """Read an unsigned int64 from the address."""
        return self.read_int(address, 8, False)

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
                address += 1

        return data.decode("utf-8")

    def read_pointer(self, address: int) -> int:
        """Read a pointer from the address."""
        return self.read_int(address, self.arch.addr_size)

    def read_array(self, begin: int, end: int, size: Optional[int] = None) -> List[int]:
        """Read an array from the address."""
        if size is None:
            size = self.arch.addr_size

        data = self.read_bytes(begin, end - begin)
        array = []

        for offset in range(0, len(data), size):
            int_bytes = data[offset : offset + size]
            value = int.from_bytes(int_bytes, byteorder=self.endian)

            array.append(value)

        return array

    def write_int(self, address: int, value: int, size: int, signed: bool = False):
        """Write an integer into the address."""
        self.uc.mem_write(
            address,
            value.to_bytes(size, signed=signed, byteorder=self.endian),
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

    def write_bytes(self, address: int, data: bytes):
        """Write bytes into the address."""
        self.uc.mem_write(address, data)

    def write_string(self, address: int, string: str):
        """Write string into the address."""
        self.uc.mem_write(address, string.encode("utf-8") + b"\x00")

    def write_pointer(self, address: int, value: int):
        """Write a pointer into the address."""
        self.write_int(address, value, self.arch.addr_size)

    def write_array(self, address: int, array: List[int], size: Optional[int] = None):
        """Write an array into the address."""
        if size is None:
            size = self.arch.addr_size

        data = b""

        for value in array:
            data += value.to_bytes(size, byteorder=self.endian)

        self.write_bytes(address, data)

    def call_symbol(self, symbol_name: str, *args: int) -> int:
        """Call function with the symbol name."""
        self.logger.info('Call symbol "%s"', symbol_name)

        symbol = self.find_symbol(symbol_name)
        address = symbol.address

        return self._start_emulate(address, *args)

    def call_address(self, address: int, *args: int) -> int:
        """Call function at the address."""
        return self._start_emulate(address, *args)
