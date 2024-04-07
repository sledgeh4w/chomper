import os
from ctypes import sizeof
from typing import List

from . import modules
from .hooks import IosFuncHooks
from .loader import MachoLoader
from .options import IosOptions
from .structs import MachHeader64
from .syscall import IosSyscallHandler

from chomper.types import BaseOs, Module
from chomper.utils import struct2bytes


class IosOs(BaseOs):
    """The iOS environment."""

    def __init__(self, emu, **kwargs):
        super().__init__(emu, **kwargs)

        if not self.options:
            self.options = IosOptions()

        self.loader = MachoLoader(emu)

    def init_hooks(self):
        """Initialize the hooks."""
        IosFuncHooks.register(self.emu)

    def init_syscall_handlers(self):
        """Initialize the system call handlers."""
        IosSyscallHandler.register(self.emu)

    def find_system_module(self, module_name: str) -> str:
        """Find system module in rootfs directory.

        raises:
            FileNotFoundError: If module not found.
        """
        lib_dirs = [
            "usr/lib/system",
            "usr/lib",
            "System/Library/Frameworks",
            "System/Library/PrivateFrameworks",
        ]

        for lib_dir in lib_dirs:
            path = os.path.join(self.rootfs_path or ".", lib_dir)

            lib_path = os.path.join(path, module_name)
            if os.path.exists(lib_path):
                return lib_path

            framework_path = os.path.join(path, f"{module_name}.framework")
            if os.path.exists(framework_path):
                return os.path.join(framework_path, module_name)

        raise FileNotFoundError("Module '%s' not found" % module_name)

    def check_module(self, module_name: str) -> bool:
        """Check if the module is loaded."""
        return module_name in (t.name for t in self.emu.modules)

    def init_objc(self, module: Module):
        """Initialize Objective-C."""
        if not self.check_module(modules.Objc.MODULE_NAME):
            return

        if not module.binary:
            return

        try:
            mach_header = MachHeader64(
                magic=module.binary.header.magic.value,
                cputype=module.binary.header.cpu_type.value,
                cpusubtype=module.binary.header.cpu_subtype,
                filetype=module.binary.header.file_type.value,
                ncmds=module.binary.header.nb_cmds,
                sizeofcmds=module.binary.header.sizeof_cmds,
                flags=module.binary.header.flags,
                reserved=module.binary.header.reserved,
            )

            mach_header_ptr = self.emu.create_buffer(sizeof(MachHeader64))
            self.emu.write_bytes(mach_header_ptr, struct2bytes(mach_header))

            mach_header_ptrs = self.emu.create_buffer(self.emu.arch.addr_size)
            self.emu.write_pointer(mach_header_ptrs, mach_header_ptr)

            self.emu.call_symbol("_map_images", 1, 0, mach_header_ptrs)
            self.emu.call_symbol("_load_images")

        except Exception as e:
            self.emu.logger.error("Initialize Objective-C failed.")
            self.emu.logger.exception(e)

    def load_modules(self, module_classes: List):
        """Load modules."""
        for module_cls in module_classes:
            module_cls(self.emu).load()

    def enable_objc(self):
        """Enable Objective-C support."""
        dependent_modules = [
            modules.SystemPlatform,
            modules.SystemKernel,
            modules.SystemC,
            modules.SystemPthread,
            modules.SystemInfo,
            modules.SystemDarwin,
            modules.SystemFeatureflags,
            modules.Corecrypto,
            modules.CommonCrypto,
            modules.Cppabi,
            modules.Cpp,
            modules.Dyld,
            modules.Objc,
            modules.Dispatch,
            modules.SystemBlocks,
            modules.SystemTrace,
            modules.SystemSandbox,
            modules.Network,
            modules.CoreFoundation,
            modules.CFNetwork,
            modules.Foundation,
            modules.Security,
        ]

        self.load_modules(dependent_modules)

    def enable_ui_kit(self):
        """Enable UIKit support.

        Mainly used to load `UIDevice` class, which is used to get device info.
        """
        dependent_modules = [
            modules.QuartzCore,
            modules.BaseBoard,
            modules.FrontBoardServices,
            modules.PrototypeTools,
            modules.TextInput,
            modules.PhysicsKit,
            modules.CoreAutoLayout,
            modules.UIFoundation,
            modules.UIKitServices,
            modules.UIKitCore,
        ]

        self.load_modules(dependent_modules)

    def initialize(self):
        """Initialize the environment."""
        self.init_hooks()
        self.init_syscall_handlers()

        if self.options.enable_objc:
            self.enable_objc()

        if self.options.enable_ui_kit:
            self.enable_ui_kit()
