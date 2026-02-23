from __future__ import annotations

from typing import Dict, Iterator, Optional, Sequence, Set, Tuple, Union, TYPE_CHECKING

import lief
from unicorn import UcError

from chomper.loader import Module, Segment

if TYPE_CHECKING:
    from chomper.core import Chomper


class SystemModuleFixer:
    """Fixup system modules in iOS.

    System modules in the project are all extracted from dyld_shared_cache,
    but they lack part of the relocation information, which needs to be fixed.
    """

    def __init__(self, emu: Chomper, module: Module):
        self.emu = emu

        self._module = module
        self._module_base = module.base - (module.macho_info.image_base or 0)
        self._module_binary: lief.MachO.Binary = lief.parse(module.path)  # type: ignore

        # Filter duplicate relocations
        self._relocation_cache: Dict[int, int] = {}

        self._refs_to_relocations: Set[int] = set()

    @staticmethod
    def is_address_in_segment(
        address: int,
        segment: Union[lief.MachO.SegmentCommand, Segment],
    ) -> bool:
        """Check whether the address is in the specified segment."""
        return (
            segment.virtual_address
            <= address
            < segment.virtual_address + segment.virtual_size
        )

    @staticmethod
    def is_address_in_section(address: int, section: lief.MachO.Section) -> bool:
        """Check whether the address is in the specified section."""
        return (
            section.virtual_address <= address < section.virtual_address + section.size
        )

    def iter_sections(self, names: Sequence[Tuple[str, str]]) -> Iterator:
        for segment_name, section_name in names:
            section = self._module_binary.get_section(segment_name, section_name)
            if section:
                yield section

    def relocate_reference(
        self,
        address: int,
        module_base: Optional[int] = None,
    ) -> int:
        """Relocate reference at the address."""
        if module_base is None:
            module_base = self._module_base

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
        for section in self._module_binary.sections:
            # Reduce iterations to optimize performance
            if section.name in ("__text",):
                continue

            content = section.content

            for offset in range(0, len(content), 8):
                value = int.from_bytes(content[offset : offset + 8], "little")

                if value in self._refs_to_relocations:
                    address = self._module_base + section.virtual_address + offset
                    self.emu.write_pointer(address, self._module_base + value)

    def check_address(self, address: int) -> bool:
        """Check if the address is in a data section."""
        names = [
            ("__DATA", "__data"),
            ("__DATA", "__cstring"),
            ("__DATA_DIRTY", "__data"),
            ("__DATA_DIRTY", "__cstring"),
        ]

        for section in self.iter_sections(names):
            if self.is_address_in_section(address, section):
                return True

        return False

    def relocate_symbols(self):
        """Relocate references to all symbols."""
        for symbol in self._module_binary.symbols:
            if not symbol.value:
                continue

            self.add_refs_to_relocation(symbol.value)

    def relocate_block_invokes(self):
        """Relocate invoke addresses in block structs."""
        for binding in self._module_binary.bindings:
            if binding.symbol.name == "__NSConcreteGlobalBlock":
                address = self._module_base + binding.address

                flags = self.emu.read_u32(address + 8)
                reversed_value = self.emu.read_u32(address + 12)

                if flags == 0x50000000 and reversed_value == 0:
                    self.relocate_reference(address + 16)

    def iter_section_pointers(
        self,
        section_name: str,
        segment_name: Optional[str] = None,
    ) -> Iterator[Tuple[int, int]]:
        """Iterate addresses in the specified section."""
        if segment_name:
            section = self._module_binary.get_section(segment_name, section_name)
        else:
            section = self._module_binary.get_section(section_name)

        if not section:
            return

        for offset in range(0, section.size, 8):
            address = self._module_base + section.virtual_address + offset

            data = section.content[offset : offset + 8]
            target_address = int.from_bytes(data, "little")

            yield address, target_address

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
            section = self._module_binary.get_section(section_name)
            if not section:
                continue

            start = self._module_base + section.virtual_address
            end = start + section.size

            if section_name == "__objc_arraydata":
                for offset in range(start, end, 8):
                    self.add_refs_to_relocation(offset - self._module_base)
                continue

            values = self.emu.read_array(start, end)

            if section_name == "__objc_classlist":
                for value in values:
                    self.fixup_class_struct(value)
                    self.add_refs_to_relocation(value)

                    meta_class_addr = self.emu.read_pointer(self._module_base + value)

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
                    self.relocate_reference(self._module_base + value + 8)

            values = [self._module_base + v if v else 0 for v in values]
            self.emu.write_array(start, values)

        # Certain system libraries don't contain `__objc_classlist`
        # or `__objc_protolist` sections, so we find structs using symbol names.
        if not self._module_binary.has_section("__objc_classlist"):
            self.fixup_classes_from_symbols()

        if not self._module_binary.has_section("__objc_protolist"):
            self.fixup_protocols_from_symbols()

    def fixup_classes_from_symbols(self):
        """Find and fixup class structs via symbol matching."""
        for symbol in self._module_binary.symbols:
            symbol_name = str(symbol.name)

            if symbol.value and (
                symbol_name.startswith("_OBJC_METACLASS_$")
                or symbol_name.startswith("_OBJC_CLASS_$")
            ):
                self.fixup_class_struct(symbol.value)
                self.add_refs_to_relocation(symbol.value)

    def fixup_protocols_from_symbols(self):
        """Find and fixup protocol structs via symbol matching."""
        for symbol in self._module_binary.symbols:
            symbol_name = str(symbol.name)

            if symbol.value and symbol_name.startswith("_OBJC_PROTOCOL_$"):
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
        address += self._module_base

        superclass_ptr = address + 8
        superclass_addr = self.emu.read_pointer(superclass_ptr)

        data_addr = self.emu.read_pointer(address + 32)
        self.add_refs_to_relocation(data_addr)

        data_addr += self._module_base

        name_ptr = data_addr + 24
        name_addr = self.relocate_reference(name_ptr)
        name = self.emu.read_string(name_addr)

        # Validate superclass and set to nil if invalid to prevent map_images crashes.
        if superclass_addr:
            names = [
                ("__DATA", "__objc_data"),
                ("__DATA_DIRTY", "__objc_data"),
            ]

            is_valid = False

            for section in self.iter_sections(names):
                if self.is_address_in_section(superclass_addr, section):
                    is_valid = True
                    break

            if not is_valid:
                try:
                    self.emu.read_pointer(superclass_addr)
                except UcError:
                    self.emu.logger.warning("Class '%s' missing superclass", name)
                    self.emu.write_pointer(superclass_ptr, 0)

        instance_methods_ptr = data_addr + 32
        self.fixup_class_method_list(instance_methods_ptr)

        protocols_ptr = data_addr + 40
        self.fixup_class_protocol_list(protocols_ptr)

        instance_variables_ptr = data_addr + 48
        self.fixup_class_variable_list(instance_variables_ptr)

    def fixup_protocol_method_types(
        self,
        method_types_ptr: int,
        instance_methods_ptr: int,
        instance_methods2_ptr: int,
    ):
        """Fixup the method types list of Objective-C."""
        instance_methods_addr = self.emu.read_pointer(
            instance_methods_ptr
        ) or self.emu.read_pointer(instance_methods2_ptr)

        if not instance_methods_addr:
            return

        method_count = self.emu.read_u32(instance_methods_addr + 4)
        method_types_addr = self.relocate_reference(method_types_ptr)

        for index in range(method_count):
            method_type_offset = method_types_addr + index * 8
            method_type_addr = self.emu.read_pointer(method_type_offset)

            for module in self.emu.modules:
                if not module.macho_info.shared_segments:
                    continue

                module_base = module.base - module.macho_info.image_base

                for segment in module.macho_info.shared_segments:
                    if self.is_address_in_segment(method_type_addr, segment):
                        self.relocate_reference(
                            method_type_offset, module_base=module_base
                        )

    def fixup_protocol_struct(self, address: int):
        """Fixup the protocol struct of Objective-C."""
        address += self._module_base

        name_addr = self.emu.read_pointer(address + 8)
        if name_addr:
            self.add_refs_to_relocation(name_addr)

        protocols_ptr = address + 16
        self.fixup_class_protocol_list(protocols_ptr)

        instance_methods_ptr = address + 24
        self.fixup_class_method_list(instance_methods_ptr)

        instance_methods2_ptr = address + 40
        self.fixup_class_method_list(instance_methods2_ptr)

        method_types_ptr = address + 72
        self.fixup_protocol_method_types(
            method_types_ptr,
            instance_methods_ptr,
            instance_methods2_ptr,
        )

    def fixup_category_struct(self, address: int):
        """Fixup the category struct of Objective-C."""
        address += self._module_base

        name_ptr = address
        name_addr = self.relocate_reference(name_ptr)
        name = self.emu.read_string(name_addr)

        class_ptr = address + 8
        class_addr = self.emu.read_pointer(class_ptr)

        # Validate target class and set to nil if invalid to prevent map_images crashes.
        if class_addr:
            is_valid = False

            try:
                self.emu.read_pointer(class_addr)
                is_valid = True
            except UcError:
                pass

            if not is_valid:
                # In some cases, the relocation information is corrupted,
                # and relocation does not complete.
                try:
                    self.emu.read_pointer(self._module_base + class_addr)
                    self.relocate_reference(class_addr)
                    is_valid = True
                except UcError:
                    pass

            if not is_valid:
                self.emu.logger.warning("Category '%s' missing target class", name)
                self.emu.write_pointer(class_ptr, 0)

        instance_methods_ptr = address + 16
        self.fixup_class_method_list(instance_methods_ptr)

        class_methods_ptr = address + 24
        self.fixup_class_method_list(class_methods_ptr)

        protocols_ptr = address + 32
        self.fixup_class_protocol_list(protocols_ptr)

    def fixup_cstring_section(self):
        """Fixup the `__cstring` section."""
        section = self._module_binary.get_section("__cstring")
        if not section or not section.content:
            return

        start = 0

        for index in range(section.size):
            if section.content[index] == 0:
                self.add_refs_to_relocation(section.virtual_address + start)
                start = index + 1

    def fixup_cfstring_section(self):
        """Fixup `__cfstring` and `__cfstring_CFN` section."""
        section_map = {
            "__cfstring": 0x20,
            "__cfstring_CFN": 0x38,
        }

        for section_name, item_size in section_map.items():
            section = self._module_binary.get_section(section_name)
            if not section:
                continue

            start = section.virtual_address
            offset = 0

            while offset < section.size:
                self.add_refs_to_relocation(start + offset)

                address = self._module_base + start + offset + 16
                self.relocate_reference(address)

                offset += item_size

    def fixup_unicode_segment(self):
        """Fixup the `__UNICODE` segment."""
        names = [
            ("__UNICODE", "__csbitmaps"),
            ("__UNICODE", "__data"),
            ("__UNICODE", "__properties"),
        ]

        for section in self.iter_sections(names):
            self.add_refs_to_relocation(section.virtual_address)

    def fixup_const_data(self):
        """Fixup references to const data."""
        names = [
            ("__DATA", "__common"),
            ("__DATA", "__data"),
            ("__DATA", "__objc_arraydata"),
            ("__DATA", "__objc_arrayobj"),
            ("__DATA", "__objc_dictobj"),
            ("__DATA_CONST", "__const"),
            ("__DATA_DIRTY", "__common"),
            ("__DATA_DIRTY", "__data"),
            ("__TEXT", "__const"),
        ]

        # Address range of the module
        module_start = self._module_binary.imagebase
        module_end = module_start

        for segment in self._module_binary.segments:
            module_end = max(module_end, segment.virtual_address + segment.virtual_size)

        text_section = self._module_binary.get_section("__TEXT", "__text")

        # Address range of the `__TEXT` segment
        text_start = text_section.virtual_address
        text_end = text_start + text_section.size

        for section in self.iter_sections(names):
            for offset in range(0, section.size, 8):
                data = section.content[offset : offset + 8]
                address = int.from_bytes(data, "little")

                if not (module_start <= address < module_end):
                    continue

                for data_section in self.iter_sections(names):
                    if self.is_address_in_section(address, data_section):
                        self.add_refs_to_relocation(address)

                if text_start <= address < text_end:
                    self.add_refs_to_relocation(address)

    def fixup_stubs_section(self):
        """Fixup the `__stubs` section."""
        section = self._module_binary.get_section("__stubs")
        if not section:
            return

        for offset in range(0, section.size, 12):
            self.add_refs_to_relocation(section.virtual_address + offset)

    def fixup_auth_ptr_section(self):
        """Fixup the `__auth_ptr` section."""
        for address, target_address in self.iter_section_pointers("__auth_ptr"):
            for module in self.emu.modules:
                if module.name == self._module.name:
                    continue

                module_base = module.base - module.macho_info.image_base

                if module.contains(target_address + module_base):
                    self.relocate_reference(address, module_base=module_base)

    def fixup_sel_references(self):
        """Fixup references to SEL."""
        names = [
            ("__DATA_DIRTY", "__objc_data"),
            ("__DATA_CONST", "__const"),
        ]

        for segment_name, section_name in names:
            for address, target_address in self.iter_section_pointers(
                section_name,
                segment_name=segment_name,
            ):
                for module in self.emu.modules:
                    if not module.macho_info.shared_segments:
                        continue

                    module_base = module.base - module.macho_info.image_base

                    for segment in module.macho_info.shared_segments:
                        if self.is_address_in_segment(target_address, segment):
                            self.relocate_reference(address, module_base=module_base)

    def fixup_all(self):
        """Apply all fixup to the module."""
        self.relocate_symbols()
        self.relocate_block_invokes()

        self.fixup_objc_sections()
        self.fixup_cstring_section()
        self.fixup_cfstring_section()
        self.fixup_stubs_section()

        # For arm64e
        self.fixup_auth_ptr_section()

        self.fixup_sel_references()

        self.fixup_unicode_segment()
        self.fixup_const_data()

        # Do this at the end
        self.relocate_refs_to()
