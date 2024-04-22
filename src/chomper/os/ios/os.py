import os
from ctypes import sizeof
from typing import List

from chomper.abc import BaseOs
from chomper.types import Module
from chomper.utils import struct2bytes
from chomper.os.ios.hooks import hooks
from chomper.os.ios.loader import MachoLoader
from chomper.os.ios.module import module_patch_map
from chomper.os.ios.structs import MachHeader64
from chomper.os.ios.syscall import syscall_handlers


class IosOs(BaseOs):
    """Provide iOS runtime environment."""

    def __init__(self, emu, **kwargs):
        super().__init__(emu, **kwargs)

        self.loader = MachoLoader(emu)

    def _setup_hooks(self):
        """Initialize the hooks."""
        self.emu.hooks.update(hooks)

    def _setup_syscall_handlers(self):
        """Initialize the system call handlers."""
        self.emu.syscall_handlers.update(syscall_handlers)

    def _enable_objc(self):
        """Enable Objective-C support."""
        dependencies = [
            "libsystem_platform.dylib",
            "libsystem_kernel.dylib",
            "libsystem_c.dylib",
            "libsystem_pthread.dylib",
            "libsystem_info.dylib",
            "libsystem_darwin.dylib",
            "libsystem_featureflags.dylib",
            "libcorecrypto.dylib",
            "libcommonCrypto.dylib",
            "libc++abi.dylib",
            "libc++.1.dylib",
            "libdyld.dylib",
            "libobjc.A.dylib",
            "libdispatch.dylib",
            "libsystem_blocks.dylib",
            "libsystem_trace.dylib",
            "libsystem_sandbox.dylib",
            "libnetwork.dylib",
            "CoreFoundation",
            "CFNetwork",
            "Foundation",
            "Security",
        ]

        self.load_system_modules(dependencies)

    def _enable_ui_kit(self):
        """Enable UIKit support.

        Mainly used to load `UIDevice` class, which is used to get device info.
        """
        dependencies = [
            "QuartzCore",
            "BaseBoard",
            "FrontBoardServices",
            "PrototypeTools",
            "TextInput",
            "PhysicsKit",
            "CoreAutoLayout",
            "UIFoundation",
            "UIKitServices",
            "UIKitCore",
        ]

        self.load_system_modules(dependencies)

    def locate_system_module(self, module_name: str) -> str:
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

    def load_system_modules(self, module_names: List):
        """Load modules if don't loaded."""
        for module_name in module_names:
            if self.emu.find_module(module_name):
                continue

            module_path = self.emu.os.locate_system_module(module_name)
            module = self.emu.load_module(module_path, exec_objc_init=False)

            module_patch_cls = module_patch_map[module_name]
            module_patch_cls(self.emu).patch(module)

    def init_objc(self, module: Module):
        """Initialize Objective-C."""
        if not self.emu.find_module("libobjc.A.dylib") or not module.binary:
            return

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

        try:
            self.emu.call_symbol("_map_images", 1, 0, mach_header_ptrs)
            self.emu.call_symbol("_load_images")

        except Exception as e:
            self.emu.logger.error("Initialize Objective-C failed.")
            self.emu.logger.exception(e)

        finally:
            module.binary = None

    def initialize(self):
        """Initialize the environment."""
        self._setup_hooks()
        self._setup_syscall_handlers()

        if self.emu.enable_objc:
            self._enable_objc()

        if self.emu.enable_ui_kit:
            self._enable_ui_kit()
