from __future__ import annotations

from typing import (
    Dict,
    Iterator,
    List,
    Optional,
    Sequence,
    Set,
    Tuple,
    Union,
    TYPE_CHECKING,
)

import lief
import struct
from unicorn import UcError

from chomper.exceptions import SymbolMissing
from chomper.loader import Binding, Module, Segment

if TYPE_CHECKING:
    from chomper.core import Chomper


class FixupContext:
    def __init__(self):
        self.pending_auth_ptrs: List[Tuple[int, int]] = []


class SystemModuleFixer:
    """Fix up iOS system modules extracted from dyld_shared_cache.

    Compensate for relocation information missing from the extracted modules.
    """

    def __init__(self, emu: Chomper, module: Module, context: FixupContext):
        self.emu = emu

        self._module = module
        self._context = context

        self._module_base = module.base - (module.macho_info.image_base or 0)
        self._module_binary: lief.MachO.Binary = lief.parse(module.path)  # type: ignore

        # Avoid duplicate relocations
        self._relocation_cache: Dict[int, int] = {}

        self._refs_to_relocations: Set[int] = set()

    @staticmethod
    def is_address_in_segment(
        address: int,
        segment: Union[lief.MachO.SegmentCommand, Segment],
    ) -> bool:
        return (
            segment.virtual_address
            <= address
            < segment.virtual_address + segment.virtual_size
        )

    @staticmethod
    def is_address_in_section(address: int, section: lief.MachO.Section) -> bool:
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
        """Relocate the pointer stored at the address."""
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

    def bind_symbol(self, address: int, symbol_name: str) -> bool:
        try:
            symbol = self.emu.get_symbol(symbol_name)
        except SymbolMissing:
            self._module.macho_info.lazy_bindings.append(
                Binding(
                    symbol=symbol_name,
                    address=address - self._module_base,
                    addend=0,
                )
            )
            return False

        self.emu.write_pointer(address, symbol.address)
        return True

    def add_relocation_target(self, address: int):
        """Register a target address for reference relocation."""
        self._refs_to_relocations.add(address)

    def relocate_registered_refs(self):
        """Relocate references to all registered target addresses."""
        for section in self._module_binary.sections:
            if section.name in ("__text",):
                continue

            content = section.content

            count = len(content) // 8
            values = struct.unpack(f"<{count}Q", content[: count * 8])

            for index, value in enumerate(values):
                if value in self._refs_to_relocations:
                    address = self._module_base + section.virtual_address + index * 8
                    self.emu.write_pointer(address, self._module_base + value)

    def is_address_in_data_section(self, address: int) -> bool:
        """Check if the address is in a data section."""
        sections = (
            ("__DATA", "__data"),
            ("__DATA", "__cstring"),
            ("__DATA_DIRTY", "__data"),
            ("__DATA_DIRTY", "__cstring"),
        )

        for section in self.iter_sections(sections):
            if self.is_address_in_section(address, section):
                return True

        return False

    def register_symbol_addresses(self):
        """Register symbol addresses for reference relocation."""
        for symbol in self._module_binary.symbols:
            if not symbol.value:
                continue

            self.add_relocation_target(symbol.value)

            if symbol.name.startswith("__ZTV"):
                self.add_relocation_target(symbol.value + 16)

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
        """Iterate pointer slots and their target values in the specified section."""
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
        """Fixup Objective-C metadata sections."""
        section_names = (
            "__objc_classlist",
            "__objc_catlist",
            "__objc_nlcatlist",
            "__objc_classrefs",
            "__objc_superrefs",
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
                    self.add_relocation_target(offset - self._module_base)
                continue

            values = self.emu.read_array(start, end)

            if section_name == "__objc_classlist":
                for value in values:
                    self.fixup_class_struct(value)
                    self.add_relocation_target(value)

                    meta_class_addr = self.emu.read_pointer(self._module_base + value)

                    self.fixup_class_struct(meta_class_addr)
                    self.add_relocation_target(meta_class_addr)
            elif section_name == "__objc_catlist":
                for value in values:
                    self.fixup_category_struct(value)
            elif section_name in ("__objc_classrefs", "__objc_superrefs"):
                for offset in range(start, end, 8):
                    self.fixup_extra_objc_reference(offset)
                continue
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
        for symbol in self._module_binary.symbols:
            symbol_name = str(symbol.name)

            if symbol.value and (
                symbol_name.startswith("_OBJC_METACLASS_$")
                or symbol_name.startswith("_OBJC_CLASS_$")
            ):
                self.fixup_class_struct(symbol.value)
                self.add_relocation_target(symbol.value)

    def fixup_protocols_from_symbols(self):
        for symbol in self._module_binary.symbols:
            symbol_name = str(symbol.name)

            if symbol.value and symbol_name.startswith("_OBJC_PROTOCOL_$"):
                self.fixup_protocol_struct(symbol.value)

    def fixup_method_list(self, address: int):
        struct_addr = self.relocate_reference(address)
        if not struct_addr:
            return

        flag = self.emu.read_u32(struct_addr)
        count = self.emu.read_u32(struct_addr + 4)

        # Clear isFixedUp and isUniqued flags
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

    def fixup_ivar_list(self, address: int):
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

    def fixup_protocol_list(self, address: int):
        struct_addr = self.relocate_reference(address)
        if not struct_addr:
            return

        count = self.emu.read_u64(struct_addr)

        for index in range(count):
            protocol_offset = struct_addr + 8 + index * 8
            protocol_address = self.relocate_reference(protocol_offset)

            self.relocate_reference(protocol_address + 8)

    def fixup_extra_objc_reference(self, address: int) -> bool:
        """Resolve a class reference through the pre-optimized class struct."""
        value = self.emu.read_pointer(address)
        extra_objc = self._module_binary.get_segment("__EXTRA_OBJC")

        if (
            not value
            or not extra_objc
            or not self.is_address_in_segment(value, extra_objc)
        ):
            return False

        data_addr = self.emu.read_pointer(self._module_base + value + 32)
        data_addr &= 0x7FFFFFFFFFF8
        data_addr += self._module_base

        flags = self.emu.read_u32(data_addr)
        class_type = "METACLASS" if flags & 1 else "CLASS"

        name_addr = self.emu.read_pointer(data_addr + 24)
        class_name = self.emu.read_string(self._module_base + name_addr)
        symbol_name = f"_OBJC_{class_type}_$_{class_name}"
        return self.bind_symbol(address, symbol_name)

    def fixup_class_struct(self, address: int):
        address += self._module_base

        superclass_ptr = address + 8
        superclass_addr = self.emu.read_pointer(superclass_ptr)

        # Empty cache
        objc_empty_cache = self.emu.get_symbol("__objc_empty_cache")
        self.emu.write_pointer(address + 16, objc_empty_cache.address)

        # Class data
        class_data_addr = self.emu.read_pointer(address + 32)
        self.add_relocation_target(class_data_addr)

        class_data_addr += self._module_base

        name_addr = self.relocate_reference(class_data_addr + 24)
        name = self.emu.read_string(name_addr)

        self.fixup_extra_objc_reference(address)

        # Validate superclass and clear invalid references
        if superclass_addr:
            sections = (
                ("__DATA", "__objc_data"),
                ("__DATA_DIRTY", "__objc_data"),
                ("__AUTH", "__objc_data"),
            )

            is_valid = False

            for section in self.iter_sections(sections):
                if self.is_address_in_section(superclass_addr, section):
                    is_valid = True
                    break

            if not is_valid:
                is_valid = self.fixup_extra_objc_reference(superclass_ptr)

            if not is_valid:
                try:
                    self.emu.read_pointer(superclass_addr)
                except UcError:
                    self.emu.logger.warning("Class '%s' missing superclass", name)
                    self.emu.write_pointer(superclass_ptr, 0)

        # Instance methods
        self.fixup_method_list(class_data_addr + 32)

        # Protocols
        self.fixup_protocol_list(class_data_addr + 40)

        # Instance variables
        self.fixup_ivar_list(class_data_addr + 48)

    def fixup_protocol_method_types(
        self,
        method_types_ptr: int,
        instance_methods_ptr: int,
        class_methods_ptr: int,
        optional_instance_methods_ptr: int,
        optional_class_methods_ptr: int,
    ):
        method_types_addr = self.relocate_reference(method_types_ptr)
        if not method_types_addr:
            return

        methods_ptrs = (
            instance_methods_ptr,
            class_methods_ptr,
            optional_instance_methods_ptr,
            optional_class_methods_ptr,
        )
        type_index = 0

        for methods_ptr in methods_ptrs:
            methods_addr = self.emu.read_pointer(methods_ptr)
            if not methods_addr:
                continue

            method_count = self.emu.read_u32(methods_addr + 4)

            for index in range(method_count):
                method_type_ptr = method_types_addr + (type_index + index) * 8
                method_type_addr = self.emu.read_pointer(method_type_ptr)

                for module in self.emu.modules:
                    if not module.macho_info.shared_segments:
                        continue

                    module_base = module.base - module.macho_info.image_base

                    for segment in module.macho_info.shared_segments:
                        if self.is_address_in_segment(method_type_addr, segment):
                            self.relocate_reference(
                                method_type_ptr,
                                module_base=module_base,
                            )

            type_index += method_count

    def fixup_protocol_struct(self, address: int):
        address += self._module_base

        name_addr = self.emu.read_pointer(address + 8)
        if name_addr:
            self.add_relocation_target(name_addr)

        # Protocols
        self.fixup_protocol_list(address + 16)

        instance_methods_ptr = address + 24
        self.fixup_method_list(instance_methods_ptr)

        class_methods_ptr = address + 32
        self.fixup_method_list(class_methods_ptr)

        optional_instance_methods_ptr = address + 40
        self.fixup_method_list(optional_instance_methods_ptr)

        optional_class_methods_ptr = address + 48
        self.fixup_method_list(optional_class_methods_ptr)

        # Extended method types
        self.fixup_protocol_method_types(
            address + 72,
            instance_methods_ptr,
            class_methods_ptr,
            optional_instance_methods_ptr,
            optional_class_methods_ptr,
        )

    def fixup_category_struct(self, address: int):
        address += self._module_base

        name_ptr = address
        name_addr = self.relocate_reference(name_ptr)
        name = self.emu.read_string(name_addr)

        class_ptr = address + 8
        class_addr = self.emu.read_pointer(class_ptr)

        # Validate target class and clear invalid references
        if class_addr:
            is_valid = self.fixup_extra_objc_reference(class_ptr)

            if not is_valid:
                try:
                    self.emu.read_pointer(class_addr)
                    is_valid = True
                except UcError:
                    pass

            if not is_valid:
                self.emu.logger.warning("Category '%s' missing target class", name)
                self.emu.write_pointer(class_ptr, 0)

        # Instance methods
        self.fixup_method_list(address + 16)

        # Class methods
        self.fixup_method_list(address + 24)

        # Protocols
        self.fixup_protocol_list(address + 32)

    def fixup_cstring_section(self):
        cstring = self._module_binary.get_section("__cstring")
        if not cstring or not cstring.content:
            return

        content = bytes(cstring.content)
        start = 0

        while start < len(content):
            end = content.find(b"\x00", start)
            if end == -1:
                break

            self.add_relocation_target(cstring.virtual_address + start)
            start = end + 1

    def fixup_cfstring_sections(self):
        object_sizes = {
            "__cfstring": 32,
            "__cfstring_CFN": 56,
        }

        for section_name, object_size in object_sizes.items():
            section = self._module_binary.get_section(section_name)
            if not section:
                continue

            start = section.virtual_address
            offset = 0

            while offset < section.size:
                self.add_relocation_target(start + offset)
                address = self._module_base + start + offset

                # CFString isa
                self.bind_symbol(address, "___CFConstantStringClassReference")

                # CFString bytes
                self.relocate_reference(address + 16)

                offset += object_size

    def fixup_unicode_segment(self):
        sections = (
            ("__UNICODE", "__csbitmaps"),
            ("__UNICODE", "__data"),
            ("__UNICODE", "__properties"),
        )

        for section in self.iter_sections(sections):
            self.add_relocation_target(section.virtual_address)

    def build_external_symbol_addresses(self) -> Dict[int, int]:
        symbol_addresses: Dict[int, int] = {}

        for module in self.emu.modules:
            if module.name == self._module.name:
                continue

            module_base = module.base - module.macho_info.image_base

            for symbol in module.symbols:
                if symbol.address:
                    address = symbol.address - module_base
                    symbol_addresses[address] = symbol.address

                    if symbol.name.startswith("__ZTV"):
                        symbol_addresses[address + 16] = symbol.address + 16

        return symbol_addresses

    def fixup_data_refs(self):
        """Fixup references stored in data sections."""
        ref_sections = (
            ("__DATA", "__data"),
            ("__DATA", "__objc_arraydata"),
            ("__DATA_CONST", "__const"),
            ("__AUTH_CONST", "__const"),
            ("__AUTH_CONST", "__auth_ptr"),
            ("__AUTH", "__objc_intobj"),
            ("__AUTH", "__objc_arrayobj"),
            ("__AUTH", "__objc_dictobj"),
            ("__DATA_DIRTY", "__bss"),
            ("__DATA_DIRTY", "__data"),
        )

        data_sections = (
            ("__DATA", "__data"),
            ("__DATA", "__objc_arrayobj"),
            ("__DATA", "__objc_dictobj"),
            ("__AUTH", "__objc_arrayobj"),
            ("__AUTH", "__objc_dictobj"),
            ("__DATA_CONST", "__const"),
            ("__DATA_CONST", "__objc_const"),
            ("__AUTH_CONST", "__const"),
            ("__DATA_DIRTY", "__common"),
            ("__DATA_DIRTY", "__data"),
            ("__TEXT", "__const"),
            ("__TEXT", "__swift5_typeref"),
        )

        data_regions = [
            (section.virtual_address, section.virtual_address + section.size)
            for section in self.iter_sections(data_sections)
        ]

        # Address range of the module
        module_start = self._module_binary.imagebase
        module_end = module_start

        for segment in self._module_binary.segments:
            module_end = max(module_end, segment.virtual_address + segment.virtual_size)

        text_section = self._module_binary.get_section("__TEXT", "__text")

        # Address range of the `__text` section
        text_start = text_section.virtual_address
        text_end = text_start + text_section.size

        external_symbol_addresses = self.build_external_symbol_addresses()

        for ref_section in self.iter_sections(ref_sections):
            content = ref_section.content

            count = len(content) // 8
            values = struct.unpack(f"<{count}Q", content[: count * 8])

            for index, address in enumerate(values):
                symbol_address = external_symbol_addresses.get(address)
                if symbol_address:
                    ref_address = (
                        self._module_base + ref_section.virtual_address + index * 8
                    )
                    self.emu.write_pointer(ref_address, symbol_address)
                    continue

                if not (module_start <= address < module_end):
                    continue

                for start, end in data_regions:
                    if start <= address < end:
                        self.add_relocation_target(address)
                        break

                if text_start <= address < text_end:
                    self.add_relocation_target(address)

    def fixup_stubs_section(self):
        section = self._module_binary.get_section("__stubs")
        if not section:
            return

        for offset in range(0, section.size, 12):
            self.add_relocation_target(section.virtual_address + offset)

    def fixup_auth_ptr_section(self):
        pending_auth_ptrs = self._context.pending_auth_ptrs

        for item in pending_auth_ptrs[:]:
            address, target_address = item
            if self.emu.read_pointer(address) != target_address:
                pending_auth_ptrs.remove(item)
                continue

            if self._module.contains(target_address + self._module_base):
                self.relocate_reference(address, module_base=self._module_base)
                pending_auth_ptrs.remove(item)

        for address, target_address in self.iter_section_pointers("__auth_ptr"):
            if self._module.contains(target_address + self._module_base):
                continue

            for module in self.emu.modules:
                if module.name == self._module.name:
                    continue

                module_base = module.base - module.macho_info.image_base

                if module.contains(target_address + module_base):
                    self.relocate_reference(address, module_base=module_base)
                    break
            else:
                pending_auth_ptrs.append((address, target_address))

    def fixup_sel_refs(self):
        sections = (
            ("__DATA_DIRTY", "__objc_data"),
            ("__DATA_CONST", "__const"),
        )

        shared_segments = []
        for module in self.emu.modules:
            segments = module.macho_info.shared_segments
            if not segments:
                continue

            module_base = module.base - module.macho_info.image_base
            for segment in segments:
                start = segment.virtual_address
                end = start + segment.virtual_size
                shared_segments.append((start, end, module_base))

        if not shared_segments:
            return

        min_start = min(start for start, _, _ in shared_segments)
        max_end = max(end for _, end, _ in shared_segments)

        for segment_name, section_name in sections:
            for address, target_address in self.iter_section_pointers(
                section_name,
                segment_name=segment_name,
            ):
                # Fast rejection
                if not (min_start <= target_address < max_end):
                    continue

                for start, end, module_base in shared_segments:
                    if start <= target_address < end:
                        self.relocate_reference(address, module_base=module_base)
                        break

    def fixup_all(self):
        self.register_symbol_addresses()
        self.relocate_block_invokes()

        self.fixup_objc_sections()
        self.fixup_cstring_section()
        self.fixup_cfstring_sections()
        self.fixup_stubs_section()

        self.fixup_auth_ptr_section()

        self.fixup_unicode_segment()

        self.fixup_data_refs()
        self.fixup_sel_refs()

        # Relocate references after all targets are registered
        self.relocate_registered_refs()
