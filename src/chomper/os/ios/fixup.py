import lief

from chomper.exceptions import SymbolMissingException
from chomper.types import Module


class SystemModuleFixup:
    """Fixup system modules in iOS.

    System modules in the project are all extracted from `dyld_shared_cache`,
    and they are lost part relocation information, which needs to be fixed.
    """

    def __init__(self, emu):
        self.emu = emu

        # Filter duplicate relocations
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

    def relocate_refs(self, binary: lief.MachO.Binary, module_base: int):
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
                self.add_refs_relocation(start + offset)

                str_ptr = module_base + start + offset + 0x10
                self.relocate_pointer(module_base, str_ptr)

                offset += step

    def fixup_cf_uni_char_string(self, binary: lief.MachO.Binary):
        """Fixup references of the string which used by `__CFUniCharLoadFile`."""
        section_names = ["__csbitmaps", "__data", "__properties"]

        for section_name in section_names:
            section = binary.get_section("__UNICODE", section_name)
            if section:
                self.add_refs_relocation(section.virtual_address)

    def fixup_dispatch_vtable(self):
        """Fixup virtual function table in `libdipstch.dylib`."""
        try:
            symbol = self.emu.find_symbol("_OBJC_CLASS_$_OS_dispatch_queue_serial")

            if symbol:
                for i in range(6):
                    offset = 0x30 + 0x8 * i
                    address = self.emu.read_pointer(symbol.address + offset)
                    self.add_refs_relocation(address)

        except SymbolMissingException:
            pass

    def install(self, module: Module):
        """Fixup image for the module."""
        if not module.binary:
            return

        module_base = module.base - (module.image_base or 0)

        self.relocate_symbols(module.binary)
        self.relocate_block_invoke_calls(module.binary, module_base)

        self.fixup_sections(module.binary, module_base)
        self.fixup_cstring_section(module.binary)
        self.fixup_cfstring_section(module.binary, module_base)
        self.fixup_cf_uni_char_string(module.binary)
        self.fixup_dispatch_vtable()

        self.relocate_refs(module.binary, module_base)

        self._relocate_cache.clear()
        self._refs_relocations.clear()
