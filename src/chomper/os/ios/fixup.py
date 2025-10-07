from __future__ import annotations

from typing import Dict, Optional, Set, TYPE_CHECKING

from unicorn import UcError

from chomper.loader import Module

if TYPE_CHECKING:
    from chomper.core import Chomper


class SystemModuleFixer:
    """Fixup system modules in iOS.

    System modules in the project are all extracted from dyld_shared_cache,
    but they lack part of the relocation information, which needs to be fixed.
    """

    def __init__(self, emu: Chomper, module: Module):
        self.emu = emu

        if not module.binary:
            raise ValueError("Empty binary")

        self.module_base = module.base - (module.image_base or 0)
        self.module_binary = module.binary

        # Filter duplicate relocations
        self._relocation_cache: Dict[int, int] = {}

        self._refs_to_relocations: Set[int] = set()

    def relocate_reference(
        self, address: int, module_base: Optional[int] = None
    ) -> int:
        """Relocate reference at the address."""
        if module_base is None:
            module_base = self.module_base

        if address in self._relocation_cache:
            return self._relocation_cache[address]

        reference = self.emu.read_pointer(address)
        if not reference:
            return 0

        reference += module_base
        self.emu.write_pointer(address, reference)
        self._relocation_cache[address] = reference

        return reference

    def add_refs_to_relocation(self, address: int):
        """Add the address to references-to relocations."""
        self._refs_to_relocations.add(address)

    def relocate_refs_to(self):
        """Relocate all references-to relocations."""
        for section in self.module_binary.sections:
            # Reduce iterations to optimize performance
            if section.name in ("__text",):
                continue

            content = section.content

            for offset in range(0, len(content), 8):
                value = int.from_bytes(content[offset : offset + 8], "little")

                if value in self._refs_to_relocations:
                    address = self.module_base + section.virtual_address + offset
                    self.emu.write_pointer(address, self.module_base + value)

    def check_address(self, address: int) -> bool:
        """Check if the address is in a data section."""
        for segment_name in ("__DATA", "__DATA_DIRTY"):
            segment = self.module_binary.get_segment(segment_name)
            if not segment:
                continue

            for section_name in ("__data", "__cstring"):
                section = segment.get_section(section_name)
                if not section:
                    continue

                if (
                    section.virtual_address
                    <= address
                    <= section.virtual_address + section.size
                ):
                    return True
        return False

    def relocate_symbols(self):
        """Relocate references to all symbols."""
        for symbol in self.module_binary.symbols:
            if not symbol.value:
                continue

            self.add_refs_to_relocation(symbol.value)

    def relocate_block_invokes(self):
        """Relocate invoke addresses in block structs."""
        for binding in self.module_binary.bindings:
            if binding.symbol.name == "__NSConcreteGlobalBlock":
                address = self.module_base + binding.address

                flags = self.emu.read_u32(address + 8)
                reversed_value = self.emu.read_u32(address + 12)

                if flags == 0x50000000 and reversed_value == 0:
                    self.relocate_reference(address + 16)

    def fixup_objc_sections(self):
        """Fixup sections which contains references."""
        section_names = (
            "__objc_classlist",
            "__objc_catlist",
            "__objc_nlcatlist",
            "__objc_protolist",
            "__objc_selrefs",
            "__objc_protorefs",
            "__objc_arraydata",
            "__la_resolver",
        )

        for section_name in section_names:
            section = self.module_binary.get_section(section_name)
            if not section:
                continue

            begin = self.module_base + section.virtual_address
            end = begin + section.size

            if section_name == "__objc_arraydata":
                for offset in range(begin, end, 8):
                    self.add_refs_to_relocation(offset - self.module_base)
                continue

            values = self.emu.read_array(begin, end)

            if section_name == "__objc_classlist":
                for value in values:
                    self.fixup_class_struct(value)
                    self.add_refs_to_relocation(value)

                    meta_class_addr = self.emu.read_pointer(self.module_base + value)

                    self.fixup_class_struct(meta_class_addr)
                    self.add_refs_to_relocation(meta_class_addr)
            elif section_name == "__objc_catlist":
                for value in values:
                    self.fixup_category_struct(value)
            elif section_name == "__objc_protolist":
                for value in values:
                    self.fixup_protocol_struct(value)
            elif section_name == "__objc_protorefs":
                for value in values:
                    self.relocate_reference(self.module_base + value + 8)

            values = [self.module_base + v if v else 0 for v in values]
            self.emu.write_array(begin, values)

        # Certain system libraries don't contain `__objc_classlist`
        # or `__objc_protolist` sections, so we find structs using symbol names.
        if not self.module_binary.has_section("__objc_classlist"):
            self.fixup_classes_from_symbols()

        if not self.module_binary.has_section("__objc_protolist"):
            self.fixup_protocols_from_symbols()

    def fixup_classes_from_symbols(self):
        """Find and fixup class structs via symbol matching."""
        for symbol in self.module_binary.symbols:
            symbol_name = str(symbol.name)

            if symbol.value and (
                symbol_name.startswith("_OBJC_METACLASS_$")
                or symbol_name.startswith("_OBJC_CLASS_$")
            ):
                self.fixup_class_struct(symbol.value)
                self.add_refs_to_relocation(symbol.value)

    def fixup_protocols_from_symbols(self):
        """Find and fixup protocol structs via symbol matching."""
        for symbol in self.module_binary.symbols:
            symbol_name = str(symbol.name)

            if symbol.value and symbol_name.startswith("__OBJC_PROTOCOL_$"):
                self.fixup_protocol_struct(symbol.value)

    def fixup_class_method_list(self, address: int):
        """Fixup the method list struct of Objective-C."""
        struct_addr = self.relocate_reference(address)
        if not struct_addr:
            return

        flag = self.emu.read_u32(struct_addr)
        count = self.emu.read_u32(struct_addr + 4)

        # Set isFixedUp of method_list_t is False
        flag = flag & (~0x3)
        self.emu.write_u32(struct_addr, flag)

        if flag < 0x80000000:
            for index in range(count):
                method_ptr = struct_addr + 8 + index * 24

                # Fixup method SEL
                self.relocate_reference(method_ptr)

                # Fixup method typeEncoding
                self.relocate_reference(method_ptr + 8)

                # Fixup method IMPL
                self.relocate_reference(method_ptr + 16)
        else:
            for index in range(count):
                sel_offset_ptr = struct_addr + 8 + index * 12
                sel_offset = self.emu.read_u32(sel_offset_ptr)

                # Fixup method SEL
                self.relocate_reference(sel_offset_ptr + sel_offset)

    def fixup_class_variable_list(self, address: int):
        """Fixup the variable list struct of Objective-C."""
        struct_addr = self.relocate_reference(address)
        if not struct_addr:
            return

        count = self.emu.read_u32(struct_addr + 4)

        for index in range(count):
            variable_offset = struct_addr + 8 + index * 32

            # offset
            self.relocate_reference(variable_offset)
            # name
            self.relocate_reference(variable_offset + 8)
            # typeEncoding
            self.relocate_reference(variable_offset + 16)

    def fixup_class_protocol_list(self, address: int):
        """Fixup the protocol list struct of Objective-C."""
        struct_addr = self.relocate_reference(address)
        if not struct_addr:
            return

        count = self.emu.read_u64(struct_addr)

        for index in range(count):
            protocol_offset = struct_addr + 8 + index * 8
            protocol_address = self.relocate_reference(protocol_offset)

            self.relocate_reference(protocol_address + 8)

    def fixup_class_struct(self, address: int):
        """Fixup the class struct of Objective-C."""
        address += self.module_base

        data_addr = self.emu.read_pointer(address + 32)
        self.add_refs_to_relocation(data_addr)

        data_addr += self.module_base

        name_addr = self.emu.read_pointer(data_addr + 24)
        if name_addr:
            self.add_refs_to_relocation(name_addr)

        instance_methods_ptr = data_addr + 32
        self.fixup_class_method_list(instance_methods_ptr)

        protocols_ptr = data_addr + 40
        self.fixup_class_protocol_list(protocols_ptr)

        instance_variables_ptr = data_addr + 48
        self.fixup_class_variable_list(instance_variables_ptr)

    def fixup_protocol_method_types(
        self, method_types_ptr: int, instance_methods_ptr: int
    ):
        """Fixup the method types list of Objective-C."""
        instance_methods_addr = self.emu.read_pointer(instance_methods_ptr)
        if not instance_methods_addr:
            return

        method_count = self.emu.read_u32(instance_methods_addr + 4)
        method_types_addr = self.relocate_reference(method_types_ptr)

        for index in range(method_count):
            method_type_offset = method_types_addr + index * 8
            method_type_addr = self.emu.read_pointer(method_type_offset)

            for module in self.emu.modules:
                if not module.shared_segments:
                    continue

                for segment in module.shared_segments:
                    if (
                        segment.virtual_address
                        <= method_type_addr
                        < segment.virtual_address + segment.virtual_size
                    ):
                        module_base = module.base - (module.image_base or 0)
                        self.relocate_reference(
                            method_type_offset, module_base=module_base
                        )

    def fixup_protocol_struct(self, address: int):
        """Fixup the protocol struct of Objective-C."""
        address += self.module_base

        name_addr = self.emu.read_pointer(address + 8)
        if name_addr:
            self.add_refs_to_relocation(name_addr)

        protocols_ptr = address + 16
        self.fixup_class_protocol_list(protocols_ptr)

        instance_methods_ptr = address + 24
        self.fixup_class_method_list(instance_methods_ptr)

        method_types_ptr = address + 72
        self.fixup_protocol_method_types(method_types_ptr, instance_methods_ptr)

    def fixup_category_struct(self, address: int):
        """Fixup the category struct of Objective-C."""
        address += self.module_base

        name_ptr = address
        name_addr = self.relocate_reference(name_ptr)
        name = self.emu.read_string(name_addr)

        class_ptr = address + 8
        class_addr = self.emu.read_pointer(class_ptr)

        # Validate target class and set to nil if invalid to prevent map_images crashes.
        try:
            self.emu.read_pointer(class_addr)
        except UcError:
            self.emu.logger.warning("Category %s missing target class", name)
            self.emu.write_pointer(class_ptr, 0)

        instance_methods_ptr = address + 16
        self.fixup_class_method_list(instance_methods_ptr)

        class_methods_ptr = address + 24
        self.fixup_class_method_list(class_methods_ptr)

        protocols_ptr = address + 32
        self.fixup_class_protocol_list(protocols_ptr)

    def fixup_cstring_section(self):
        """Fixup the `__cstring` section."""
        section = self.module_binary.get_section("__cstring")
        if not section or not section.content:
            return

        start = 0

        for index in range(section.size):
            if section.content[index] == 0:
                self.add_refs_to_relocation(section.virtual_address + start)
                start = index + 1

    def fixup_cfstring_section(self):
        """Fixup the `__cfstring` section."""
        section_map = {
            "__cfstring": 0x20,
            "__cfstring_CFN": 0x38,
        }

        for section_name, item_size in section_map.items():
            section = self.module_binary.get_section(section_name)
            if not section:
                continue

            start = section.virtual_address
            offset = 0

            while offset < section.size:
                self.add_refs_to_relocation(start + offset)

                address = self.module_base + start + offset + 16
                self.relocate_reference(address)

                offset += item_size

    def fixup_unicode_segment(self):
        """Fixup references in the `__UNICODE` segment."""
        section_names = ("__csbitmaps", "__data", "__properties")

        for section_name in section_names:
            section = self.module_binary.get_section("__UNICODE", section_name)
            if section:
                self.add_refs_to_relocation(section.virtual_address)

    def fixup_data_const_segment(self):
        """Fixup references in the `__DATA_CONST` segment."""
        sections = (
            self.module_binary.get_section("__DATA", "__data"),
            self.module_binary.get_section("__DATA_CONST", "__const"),
            self.module_binary.get_section("__DATA_DIRTY", "__data"),
            self.module_binary.get_section("__TEXT", "__const"),
        )

        sections = [t for t in sections if t]

        text_section = self.module_binary.get_section("__TEXT", "__text")

        text_begin = text_section.virtual_address
        text_end = text_begin + text_section.size

        for section in sections:
            for offset in range(0, section.size, 8):
                address = int.from_bytes(section.content[offset : offset + 8], "little")

                for data_section in sections:
                    if (
                        data_section.virtual_address
                        < address
                        < data_section.virtual_address + data_section.size
                    ):
                        self.add_refs_to_relocation(address)

                if offset % 4 == 0 and text_begin < address < text_end:
                    self.add_refs_to_relocation(address)

    def fixup_stubs_section(self):
        """Fixup references to the `__stubs` section."""
        section = self.module_binary.get_section("__stubs")
        if not section:
            return

        for offset in range(0, section.size, 12):
            self.add_refs_to_relocation(section.virtual_address + offset)

    def fixup_all(self):
        """Apply all fixup to the module."""
        self.relocate_symbols()
        self.relocate_block_invokes()

        self.fixup_objc_sections()
        self.fixup_cstring_section()
        self.fixup_cfstring_section()
        self.fixup_stubs_section()
        self.fixup_unicode_segment()
        self.fixup_data_const_segment()

        # Do this at the end
        self.relocate_refs_to()
