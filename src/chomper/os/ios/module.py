import uuid
from collections import defaultdict
from typing import Dict, Type

import lief

from chomper.types import Module


class ModulePatch:
    """Represents a patch to be applied to a module.

    These system modules are all extracted from `dyld_shared_cache`,
    and they are lost part relocation information, which needs to be fixed;
    In addition, some initialization processes that should have
    been carried out by the system also need to be executed.
    """

    def __init__(self, emu):
        self.emu = emu

        self._relocate_cache = {}

        self._refs_relocations = set()

    def relocate_pointer(self, module_base: int, address: int) -> int:
        """Relocate pointer stored at the address."""
        if address in self._relocate_cache:
            return self._relocate_cache[address]

        pointer = self.emu.read_pointer(address)
        if not pointer:
            return 0

        pointer += module_base

        self.emu.write_pointer(address, pointer)
        self._relocate_cache[address] = pointer

        return pointer

    def add_refs_relocation(self, address: int):
        """Add the address to the reference relocation."""
        self._refs_relocations.add(address)

    def relocate_refs(self, binary, module_base: int):
        """Relocate all references."""
        for section in binary.sections:
            content = section.content

            value = int.from_bytes(content[:7], "little") << 8

            for pos in range(0, len(content) - 7):
                value = (value >> 8) + (content[pos + 7] << (7 * 8))

                if value in self._refs_relocations:
                    address = module_base + section.virtual_address + pos
                    self.emu.write_pointer(address, module_base + value)

    def relocate_symbols(self, binary: lief.MachO.Binary):
        """Relocate references to all symbols."""
        for symbol in binary.symbols:
            if not symbol.value:
                continue

            self.add_refs_relocation(symbol.value)

    def relocate_block_invoke_calls(self, binary: lief.MachO.Binary, module_base: int):
        """Relocate function address for block struct."""
        for binding in binary.dyld_info.bindings:
            if binding.symbol.name == "__NSConcreteGlobalBlock":
                address = module_base + binding.address

                flags = self.emu.read_u32(address + 0x8)
                reversed_value = self.emu.read_u32(address + 0xC)

                if flags == 0x50000000 and reversed_value == 0:
                    self.relocate_pointer(module_base, address + 0x10)

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
                    self.add_refs_relocation(value)

                    meta_class_ptr = self.emu.read_pointer(module_base + value)

                    self.fixup_class_struct(module_base, meta_class_ptr)
                    self.add_refs_relocation(meta_class_ptr)

            elif section_name == "__objc_catlist":
                for value in values:
                    self.fixup_category_struct(module_base, value)

            elif section_name == "__objc_protolist":
                for value in values:
                    self.fixup_protocol_struct(module_base, value)

            elif section_name == "__objc_protorefs":
                for value in values:
                    self.relocate_pointer(module_base, module_base + value + 8)

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
                    self.add_refs_relocation(symbol.value)

        if not binary.has_section("__objc_protolist"):
            for symbol in binary.symbols:
                symbol_name = str(symbol.name)

                if symbol.value and symbol_name.startswith("__OBJC_PROTOCOL_$"):
                    self.fixup_protocol_struct(module_base, symbol.value)

    def fixup_method_list(self, module_base: int, address: int):
        """Fixup the method list struct."""
        method_list_ptr = self.relocate_pointer(module_base, address)
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
                self.relocate_pointer(module_base, method_ptr)

                # Fixup method IMPL
                self.relocate_pointer(module_base, method_ptr + 0x10)

        else:
            for i in range(count):
                sel_offset_ptr = method_list_ptr + 8 + i * 12
                sel_offset = self.emu.read_u32(sel_offset_ptr)

                # Fixup method SEL
                self.relocate_pointer(module_base, sel_offset_ptr + sel_offset)

    def fixup_variable_list(self, module_base: int, address: int):
        """Fixup the variable list struct."""
        variable_list_ptr = self.relocate_pointer(module_base, address)
        if not variable_list_ptr:
            return

        count = self.emu.read_u32(variable_list_ptr + 4)

        for i in range(count):
            variable_offset = variable_list_ptr + 8 + i * 0x18

            self.relocate_pointer(module_base, variable_offset)
            self.relocate_pointer(module_base, variable_offset + 0x8)
            self.relocate_pointer(module_base, variable_offset + 0x16)

    def fixup_protocol_list(self, module_base: int, address: int):
        """Fixup the protocol list struct."""
        protocol_list_ptr = self.relocate_pointer(module_base, address)
        if not protocol_list_ptr:
            return

        count = self.emu.read_u64(protocol_list_ptr)

        for i in range(count):
            protocol_offset = protocol_list_ptr + 8 + i * 0x8

            protocol_address = self.relocate_pointer(module_base, protocol_offset)
            self.relocate_pointer(module_base, protocol_address + 0x8)

    def fixup_class_struct(self, module_base: int, address: int):
        """Fixup the class struct."""
        address += module_base

        data_ptr = self.emu.read_pointer(address + 0x20)
        self.add_refs_relocation(data_ptr)

        data_ptr += module_base

        name_ptr = self.emu.read_pointer(data_ptr + 0x18)
        if name_ptr:
            self.add_refs_relocation(name_ptr)

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
            self.add_refs_relocation(name_ptr)

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
                self.add_refs_relocation(section.virtual_address + start)
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
                self.relocate_pointer(module_base, address)
                self.add_refs_relocation(start + offset)
                offset += step

    def fixup_cf_uni_char_string(self, binary: lief.MachO.Binary):
        """Fixup references of the string which used by `__CFUniCharLoadFile`."""
        section_names = ["__csbitmaps", "__data", "__properties"]

        for section_name in section_names:
            section = binary.get_section("__UNICODE", section_name)
            if section:
                self.add_refs_relocation(section.virtual_address)

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

        self._relocate_cache.clear()
        self._refs_relocations.clear()

    def init_objc(self, module: Module):
        """Initialize Objective-C."""
        self.emu.os.init_objc(module)

    def patch(self, module: Module):
        self.fixup_image(module)
        self.init_objc(module)


module_patch_map: Dict[str, Type[ModulePatch]] = defaultdict(lambda: ModulePatch)


def register_module_patch(module_name: str):
    """Decorator to register a module patch."""

    def decorator(cls):
        module_patch_map[module_name] = cls

        return cls

    return decorator


@register_module_patch("libsystem_platform.dylib")
class SystemPlatformPatch(ModulePatch):
    def patch(self, module):
        super().patch(module)

        self.emu.uc.mem_map(0xFFFFFC000, 1024)

        # arch flag
        self.emu.write_u64(0xFFFFFC023, 2)

        self.emu.write_u64(0xFFFFFC104, 0x100)


@register_module_patch("libsystem_c.dylib")
class SystemCPatch(ModulePatch):
    def init_program_vars(self):
        """Initialize program variables."""
        environ_vars = {
            "__CF_USER_TEXT_ENCODING": "0:0",
            "CFN_USE_HTTP3": "0",
            "CFStringDisableROM": "1",
            "HOME": (
                f"/Users/Sergey/Library/Developer/CoreSimulator/Devices/{uuid.uuid4()}"
                f"/data/Containers/Data/Application/{uuid.uuid4()}"
            ),
        }

        argc = self.emu.create_buffer(8)
        self.emu.write_int(argc, 0, 8)

        nx_argc_pointer = self.emu.find_symbol("_NXArgc_pointer")
        self.emu.write_pointer(nx_argc_pointer.address, argc)

        nx_argv_pointer = self.emu.find_symbol("_NXArgv_pointer")
        self.emu.write_pointer(nx_argv_pointer.address, self.emu.create_string(""))

        size = self.emu.arch.addr_size * len(environ_vars) + 1
        environ_buf = self.emu.create_buffer(size)

        offset = 0x0

        for key, value in environ_vars.items():
            prop_str = self.emu.create_string(f"{key}={value}")
            self.emu.write_pointer(environ_buf + offset, prop_str)
            offset += self.emu.arch.addr_size

        self.emu.write_pointer(environ_buf + offset, 0)

        environ = self.emu.create_buffer(8)
        self.emu.write_pointer(environ, environ_buf)

        environ_pointer = self.emu.find_symbol("_environ_pointer")
        self.emu.write_pointer(environ_pointer.address, environ)

        progname_pointer = self.emu.find_symbol("___progname_pointer")
        self.emu.write_pointer(progname_pointer.address, self.emu.create_string(""))

    def patch(self, module):
        super().patch(module)

        symbol_names = ("___locale_key", "___global_locale")

        for symbol_name in symbol_names:
            symbol = self.emu.find_symbol(symbol_name)
            self.emu.write_pointer(symbol.address, 0)

        self.init_program_vars()


@register_module_patch("libdyld.dylib")
class DyldPatch(ModulePatch):
    def patch(self, module):
        super().patch(module)

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


@register_module_patch("libobjc.A.dylib")
class ObjcPatch(ModulePatch):
    def patch(self, module):
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


@register_module_patch("libdispatch.dylib")
class DispatchPatch(ModulePatch):
    def patch(self, module):
        symbol = self.emu.find_symbol("_OBJC_CLASS_$_OS_dispatch_queue_serial")
        offsets = [0x30, 0x50, 0x58]

        for offset in offsets:
            address = self.emu.read_pointer(symbol.address + offset)
            self.add_refs_relocation(address)

        super().patch(module)


@register_module_patch("libsystem_trace.dylib")
class SystemTracePatch(ModulePatch):
    def patch(self, module):
        super().patch(module)

        self.emu.write_u64(0xFFFFFC104, 0x100)


@register_module_patch("CoreFoundation")
class CoreFoundationPatch(ModulePatch):
    def patch(self, module):
        super().patch(module)

        process_path = (
            f"/private/var/containers/Bundle/Application/{uuid.uuid4()}/App.app"
        )

        cf_process_path_ptr = self.emu.create_string(process_path)

        cf_process_path = self.emu.find_symbol("___CFProcessPath")
        self.emu.write_pointer(cf_process_path.address, cf_process_path_ptr)

        self.emu.call_symbol("___CFInitialize")


@register_module_patch("CFNetwork")
class CFNetworkPatch(ModulePatch):
    def patch(self, module):
        offset = module.base - module.image_base + 0x1D1C28610

        for i in range(25):
            address = self.emu.read_pointer(offset + i * 8)
            self.add_refs_relocation(address)

        self.add_refs_relocation(0x180A63880)

        super().patch(module)


@register_module_patch("Foundation")
class FoundationPatch(ModulePatch):
    def patch(self, module):
        super().patch(module)

        self.emu.call_symbol("__NSInitializePlatform")
