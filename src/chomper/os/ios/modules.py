import uuid

import lief

from chomper.types import Module


class IosModule:
    """System module on iOS."""

    MODULE_NAME: str

    def __init__(self, emu):
        self.emu = emu

        self.reloc_map = {}
        self.refs_reloc = set()

    def relocate_address(self, module_base: int, address: int) -> int:
        """Relocate the address."""
        if address in self.reloc_map:
            return self.reloc_map[address]

        value = self.emu.read_pointer(address)
        if not value:
            return value

        value += module_base

        self.emu.write_pointer(address, value)
        self.reloc_map[address] = value

        return value

    def set_refs_reloc(self, address: int):
        self.refs_reloc.add(address)

    def relocate_refs(self, binary, module_base: int):
        """Relocate all references."""
        for section in binary.sections:
            content = section.content

            value = int.from_bytes(content[:7], "little") << 8

            for pos in range(0, len(content) - 7):
                value = (value >> 8) + (content[pos + 7] << (7 * 8))

                if value in self.refs_reloc:
                    address = module_base + section.virtual_address + pos
                    self.emu.write_pointer(address, module_base + value)

    def relocate_symbols(self, binary: lief.MachO.Binary):
        """Relocate references to all symbols."""
        for symbol in binary.symbols:
            if not symbol.value:
                continue

            self.set_refs_reloc(symbol.value)

    def relocate_block_invoke_calls(self, binary: lief.MachO.Binary, module_base: int):
        """Relocate function address for block struct."""
        for binding in binary.dyld_info.bindings:
            if binding.symbol.name == "__NSConcreteGlobalBlock":
                address = module_base + binding.address

                flags = self.emu.read_u32(address + 0x8)
                reversed_value = self.emu.read_u32(address + 0xC)

                if flags == 0x50000000 and reversed_value == 0:
                    self.relocate_address(module_base, address + 0x10)

    def fixup_sections(self, binary: lief.MachO.Binary, module_base: int):
        """Fixup sections which contains pointers."""
        section_names = [
            "__objc_classlist",
            "__objc_catlist",
            "__objc_nlcatlist",
            "__objc_protolist",
            "__objc_selrefs",
            "__objc_protorefs",
            "__la_resolver",
        ]

        for section_name in section_names:
            section = binary.get_section(section_name)
            if not section:
                continue

            begin = module_base + section.virtual_address
            end = begin + section.size

            values = self.emu.read_array(begin, end)

            if section_name == "__objc_classlist":
                for value in values:
                    self.fixup_class_struct(module_base, value)
                    self.set_refs_reloc(value)

                    meta_class_ptr = self.emu.read_pointer(module_base + value)

                    self.fixup_class_struct(module_base, meta_class_ptr)
                    self.set_refs_reloc(meta_class_ptr)

            elif section_name == "__objc_catlist":
                for value in values:
                    self.fixup_category_struct(module_base, value)

            elif section_name == "__objc_protolist":
                for value in values:
                    self.fixup_protocol_struct(module_base, value)

            elif section_name == "__objc_protorefs":
                for value in values:
                    self.relocate_address(module_base, module_base + value + 8)

            values = map(lambda v: module_base + v if v else 0, values)
            self.emu.write_array(begin, values)

        # Some system libraries don't contain `__objc_classlist`
        # or `__objc_protolist` section, so find struct by symbol name.
        if not binary.has_section("__objc_classlist"):
            for symbol in binary.symbols:
                symbol_name = str(symbol.name)

                if symbol.value and (
                    symbol_name.startswith("_OBJC_METACLASS_$")
                    or symbol_name.startswith("_OBJC_CLASS_$")
                ):
                    self.fixup_class_struct(module_base, symbol.value)
                    self.set_refs_reloc(symbol.value)

        if not binary.has_section("__objc_protolist"):
            for symbol in binary.symbols:
                symbol_name = str(symbol.name)

                if symbol.value and symbol_name.startswith("__OBJC_PROTOCOL_$"):
                    self.fixup_protocol_struct(module_base, symbol.value)

    def fixup_method_list(self, module_base: int, address: int):
        """Fixup the method list struct."""
        method_list_ptr = self.relocate_address(module_base, address)
        if not method_list_ptr:
            return

        flag = self.emu.read_u32(method_list_ptr)
        count = self.emu.read_u32(method_list_ptr + 4)

        # Set isFixedUp of method_list_t is False
        flag = flag & (~0x3)
        self.emu.write_u32(method_list_ptr, flag)

        if flag < 0x80000000:
            for i in range(count):
                method_ptr = method_list_ptr + 8 + i * 0x18

                # Fixup method SEL
                self.relocate_address(module_base, method_ptr)

                # Fixup method IMPL
                self.relocate_address(module_base, method_ptr + 0x10)

        else:
            for i in range(count):
                sel_offset_ptr = method_list_ptr + 8 + i * 12
                sel_offset = self.emu.read_u32(sel_offset_ptr)

                # Fixup method SEL
                self.relocate_address(module_base, sel_offset_ptr + sel_offset)

    def fixup_variable_list(self, module_base: int, address: int):
        """Fixup the variable list struct."""
        variable_list_ptr = self.relocate_address(module_base, address)
        if not variable_list_ptr:
            return

        count = self.emu.read_u32(variable_list_ptr + 4)

        for i in range(count):
            variable_offset = variable_list_ptr + 8 + i * 0x18

            self.relocate_address(module_base, variable_offset)
            self.relocate_address(module_base, variable_offset + 0x8)
            self.relocate_address(module_base, variable_offset + 0x16)

    def fixup_protocol_list(self, module_base: int, address: int):
        """Fixup the protocol list struct."""
        protocol_list_ptr = self.relocate_address(module_base, address)
        if not protocol_list_ptr:
            return

        count = self.emu.read_u64(protocol_list_ptr)

        for i in range(count):
            protocol_offset = protocol_list_ptr + 8 + i * 0x8

            protocol_address = self.relocate_address(module_base, protocol_offset)
            self.relocate_address(module_base, protocol_address + 0x8)

    def fixup_class_struct(self, module_base: int, address: int):
        """Fixup the class struct."""
        address += module_base

        data_ptr = self.emu.read_pointer(address + 0x20)
        self.set_refs_reloc(data_ptr)

        data_ptr += module_base

        name_ptr = self.emu.read_pointer(data_ptr + 0x18)
        if name_ptr:
            self.set_refs_reloc(name_ptr)

        instance_methods_ptr = data_ptr + 0x20
        self.fixup_method_list(module_base, instance_methods_ptr)

        protocols_ptr = data_ptr + 0x28
        self.fixup_protocol_list(module_base, protocols_ptr)

        instance_variables_ptr = data_ptr + 0x30
        self.fixup_variable_list(module_base, instance_variables_ptr)

    def fixup_protocol_struct(self, module_base: int, address: int):
        """Fixup the protocol struct."""
        address += module_base

        name_ptr = self.emu.read_pointer(address + 0x8)
        if name_ptr:
            self.set_refs_reloc(name_ptr)

        protocols_ptr = address + 0x10
        self.fixup_protocol_list(module_base, protocols_ptr)

    def fixup_category_struct(self, module_base: int, address: int):
        """Fixup the category struct."""
        address += module_base

        instance_methods_ptr = address + 0x10
        self.fixup_method_list(module_base, instance_methods_ptr)

        class_methods_ptr = address + 0x18
        self.fixup_method_list(module_base, class_methods_ptr)

    def fixup_cstring_section(self, binary: lief.MachO.Binary):
        """Fixup the `__cstring` section."""
        section = binary.get_section("__cstring")
        if not section:
            return

        section_content = bytes(section.content)
        if not section_content:
            return

        start = 0

        for offset in range(section.size):
            if section_content[offset] == 0:
                self.set_refs_reloc(section.virtual_address + start)
                start = offset + 1

    def fixup_cfstring_section(self, binary: lief.MachO.Binary, module_base: int):
        """Fixup the `__cfstring` section."""
        section_map = {
            "__cfstring": 0x20,
            "__cfstring_CFN": 0x38,
        }

        for section_name, step in section_map.items():
            section = binary.get_section(section_name)
            if not section:
                continue

            start = section.virtual_address
            offset = 0

            while offset < section.size:
                address = module_base + start + offset + 0x10
                self.relocate_address(module_base, address)
                self.set_refs_reloc(start + offset)
                offset += step

    def fixup_cf_uni_char_string(self, binary: lief.MachO.Binary):
        """Fixup references of the string which used by `__CFUniCharLoadFile`."""
        section_names = ["__csbitmaps", "__data", "__properties"]

        for section_name in section_names:
            section = binary.get_section("__UNICODE", section_name)
            if section:
                self.set_refs_reloc(section.virtual_address)

    def fixup_image(self, module: Module):
        """Fixup the image."""
        if not module.binary:
            return

        module_base = module.base - (module.image_base or 0)

        self.relocate_symbols(module.binary)
        self.relocate_block_invoke_calls(module.binary, module_base)
        self.fixup_sections(module.binary, module_base)
        self.fixup_cstring_section(module.binary)
        self.fixup_cfstring_section(module.binary, module_base)
        self.fixup_cf_uni_char_string(module.binary)
        self.relocate_refs(module.binary, module_base)

        self.reloc_map.clear()
        self.refs_reloc.clear()

    def init_objc(self, module: Module):
        """Initialize Objective-C."""
        self.emu.os.init_objc(module)

    def initialize(self, module: Module):
        self.fixup_image(module)
        self.init_objc(module)

    def resolve(self):
        module_path = self.emu.os.find_system_module(self.MODULE_NAME)

        module = self.emu.load_module(module_path, exec_objc_init=False)
        self.initialize(module)

        if module.binary:
            module.binary = None


class SystemPlatform(IosModule):
    MODULE_NAME = "libsystem_platform.dylib"

    def set_arch_flag(self):
        """Set a flag meaning the arch type, which will be read by functions
        such as `_os_unfair_recursive_lock_lock_with_options`."""
        self.emu.uc.mem_map(0xFFFFFC000, 1024)

        # arch flag
        self.emu.write_u64(0xFFFFFC023, 2)

        self.emu.write_u64(0xFFFFFC104, 0x100)

    def initialize(self, module):
        self.set_arch_flag()
        super().initialize(module)


class SystemKernel(IosModule):
    MODULE_NAME = "libsystem_kernel.dylib"


class SystemC(IosModule):
    MODULE_NAME = "libsystem_c.dylib"

    def init_program_vars(self):
        """Initialize program variables."""
        argc = self.emu.create_buffer(8)
        self.emu.write_int(argc, 0, 8)

        nxargc_pointer = self.emu.find_symbol("_NXArgc_pointer")
        self.emu.write_pointer(nxargc_pointer.address, argc)

        nxargv_pointer = self.emu.find_symbol("_NXArgv_pointer")
        self.emu.write_pointer(nxargv_pointer.address, self.emu.create_string(""))

        environ_dict = {
            "__CF_USER_TEXT_ENCODING": "0:0",
            "CFN_USE_HTTP3": "0",
            "CFStringDisableROM": "1",
            "HOME": (
                f"/Users/Sergey/Library/Developer/CoreSimulator/Devices/{uuid.uuid4()}"
                f"/data/Containers/Data/Application/{uuid.uuid4()}"
            ),
        }

        size = self.emu.arch.addr_size * len(environ_dict) + 1
        environ_values = self.emu.create_buffer(size)

        offset = 0x0

        for key, value in environ_dict.items():
            prop_str = self.emu.create_string(f"{key}={value}")
            self.emu.write_pointer(environ_values + offset, prop_str)
            offset += self.emu.arch.addr_size

        self.emu.write_pointer(environ_values + offset, 0)

        environ = self.emu.create_buffer(8)
        self.emu.write_pointer(environ, environ_values)

        environ_pointer = self.emu.find_symbol("_environ_pointer")
        self.emu.write_pointer(environ_pointer.address, environ)

        progname_pointer = self.emu.find_symbol("___progname_pointer")
        self.emu.write_pointer(progname_pointer.address, self.emu.create_string(""))

    def initialize(self, module):
        super().initialize(module)

        symbol_names = ("___locale_key", "___global_locale")

        for symbol_name in symbol_names:
            symbol = self.emu.find_symbol(symbol_name)
            self.emu.write_pointer(symbol.address, 0)

        self.init_program_vars()


class SystemPthread(IosModule):
    MODULE_NAME = "libsystem_pthread.dylib"


class SystemInfo(IosModule):
    MODULE_NAME = "libsystem_info.dylib"


class SystemDarwin(IosModule):
    MODULE_NAME = "libsystem_darwin.dylib"


class SystemFeatureflags(IosModule):
    MODULE_NAME = "libsystem_featureflags.dylib"


class Corecrypto(IosModule):
    MODULE_NAME = "libcorecrypto.dylib"


class CommonCrypto(IosModule):
    MODULE_NAME = "libcommonCrypto.dylib"


class Cppabi(IosModule):
    MODULE_NAME = "libc++abi.dylib"


class Cpp(IosModule):
    MODULE_NAME = "libc++.1.dylib"


class Dyld(IosModule):
    MODULE_NAME = "libdyld.dylib"

    def initialize(self, module):
        super().initialize(module)

        g_use_dyld3 = self.emu.find_symbol("_gUseDyld3")
        self.emu.write_u8(g_use_dyld3.address, 1)

        dyld_all_images = self.emu.find_symbol("__ZN5dyld310gAllImagesE")

        # dyld3::closure::ContainerTypedBytes::findAttributePayload
        attribute_payload_ptr = self.emu.create_buffer(8)

        self.emu.write_u32(attribute_payload_ptr, 2**10)
        self.emu.write_u8(attribute_payload_ptr + 4, 0x20)

        self.emu.write_pointer(dyld_all_images.address, attribute_payload_ptr)

        # dyld3::AllImages::platform
        platform_ptr = self.emu.create_buffer(0x144)
        self.emu.write_u32(platform_ptr + 0x140, 2)

        self.emu.write_pointer(dyld_all_images.address + 0x50, platform_ptr)


class Objc(IosModule):
    MODULE_NAME = "libobjc.A.dylib"

    def initialize(self, module):
        self.fixup_image(module)

        prototypes = self.emu.find_symbol("__ZL10prototypes")
        self.emu.write_u64(prototypes.address, 0)

        gdb_objc_realized_classes = self.emu.find_symbol("_gdb_objc_realized_classes")
        protocolsv_ret = self.emu.call_symbol("__ZL9protocolsv")

        self.emu.write_pointer(gdb_objc_realized_classes.address, protocolsv_ret)

        opt = self.emu.find_symbol("__ZL3opt")
        self.emu.write_pointer(opt.address, 0)

        # Disable pre-optimization
        disable_preopt = self.emu.find_symbol("_DisablePreopt")
        self.emu.write_u8(disable_preopt.address, 1)

        self.emu.call_symbol("__objc_init")

        self.init_objc(module)


class Dispatch(IosModule):
    MODULE_NAME = "libdispatch.dylib"

    def initialize(self, module):
        symbol = self.emu.find_symbol("_OBJC_CLASS_$_OS_dispatch_queue_serial")
        offsets = [0x30, 0x50, 0x58]

        for offset in offsets:
            address = self.emu.read_pointer(symbol.address + offset)
            self.set_refs_reloc(address)

        super().initialize(module)


class SystemBlocks(IosModule):
    MODULE_NAME = "libsystem_blocks.dylib"


class SystemTrace(IosModule):
    MODULE_NAME = "libsystem_trace.dylib"

    def initialize(self, module):
        super().initialize(module)

        self.emu.write_u64(0xFFFFFC104, 0x100)


class SystemSandbox(IosModule):
    MODULE_NAME = "libsystem_sandbox.dylib"


class Network(IosModule):
    MODULE_NAME = "libnetwork.dylib"


class CoreFoundation(IosModule):
    MODULE_NAME = "CoreFoundation"

    def initialize(self, module):
        super().initialize(module)

        cf_process_path_str = (
            f"/private/var/containers/Bundle/Application/{uuid.uuid4()}/App.app"
        )
        cf_process_path_ptr = self.emu.create_string(cf_process_path_str)

        cf_process_path = self.emu.find_symbol("___CFProcessPath")
        self.emu.write_pointer(cf_process_path.address, cf_process_path_ptr)

        self.emu.call_symbol("___CFInitialize")


class CFNetwork(IosModule):
    MODULE_NAME = "CFNetwork"

    def initialize(self, module):
        offset = module.base - module.image_base + 0x1D1C28610

        for i in range(25):
            address = self.emu.read_pointer(offset + i * 8)
            self.set_refs_reloc(address)

        self.set_refs_reloc(0x180A63880)

        super().initialize(module)


class Foundation(IosModule):
    MODULE_NAME = "Foundation"

    def initialize(self, module):
        super().initialize(module)

        self.emu.call_symbol("__NSInitializePlatform")


class Security(IosModule):
    MODULE_NAME = "Security"


class QuartzCore(IosModule):
    MODULE_NAME = "QuartzCore"


class BaseBoard(IosModule):
    MODULE_NAME = "BaseBoard"


class FrontBoardServices(IosModule):
    MODULE_NAME = "FrontBoardServices"


class PrototypeTools(IosModule):
    MODULE_NAME = "PrototypeTools"


class TextInput(IosModule):
    MODULE_NAME = "TextInput"


class PhysicsKit(IosModule):
    MODULE_NAME = "PhysicsKit"


class CoreAutoLayout(IosModule):
    MODULE_NAME = "CoreAutoLayout"


class UIFoundation(IosModule):
    MODULE_NAME = "UIFoundation"


class UIKitServices(IosModule):
    MODULE_NAME = "UIKitServices"


class UIKitCore(IosModule):
    MODULE_NAME = "UIKitCore"
