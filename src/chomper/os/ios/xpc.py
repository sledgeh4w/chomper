from __future__ import annotations

import binascii
import plistlib
import uuid
from io import BytesIO
from typing import Any, Dict, Optional, Tuple, TYPE_CHECKING

from chomper.objc import ObjcRuntime
from chomper.plist17lib import _BinaryPlist17Parser, _BinaryPlist17Writer
from chomper.utils import bytes_to_float, int_to_bytes

if TYPE_CHECKING:
    from chomper.core import Chomper


class XpcPayloadParser:
    """Parse the XPC payload of a mach msg into a Python object."""

    def __init__(self, emu: Chomper):
        self.emu = emu

    def parse(self, payload: int) -> Any:
        if self.emu.read_u32(payload) != 0x40585043:  # magic
            self.emu.logger.warning(f"Unrecognized xpc payload at {hex(payload)}")
            return {}

        return self._parse_value(payload + 8)[0]

    def _parse_value(self, address: int) -> Tuple[Any, int]:
        wire_type = self.emu.read_u32(address)
        offset = address + 4

        value: Any

        if wire_type == 0x3000:  # int64
            value = self.emu.read_s64(offset)
            offset += 8
        elif wire_type == 0x4000:  # uint64
            value = self.emu.read_u64(offset)
            offset += 8
        elif wire_type == 0x9000:  # string
            length = self.emu.read_u32(offset)
            value = self.emu.read_string(offset + 4)
            offset += 4 + ((length + 3) & ~3)
        elif wire_type == 0xA000:  # uuid
            value = self.emu.read_bytes(offset, 16)
            offset += 16
        elif wire_type == 0xF000:  # dictionary
            value = self._parse_dict(offset)
            wire_length = self.emu.read_u32(offset)
            offset += 4 + wire_length
        else:
            self.emu.logger.warning(f"Unrecognized xpc wire type: {hex(wire_type)}")
            value = None

        return value, offset

    def _parse_dict(self, address: int) -> Dict[str, Any]:
        wire_length = self.emu.read_u32(address)
        count = self.emu.read_u32(address + 4)

        offset = address + 8
        end = address + 4 + wire_length

        data = {}

        for _ in range(count):
            if offset >= end:
                break

            key = self.emu.read_string(offset)
            offset += (len(key) + 4) & ~3

            value, offset = self._parse_value(offset)
            if value is None:
                # Failed to parse the field, skip the rest
                break

            data[key] = value

        return data


class XpcPayloadSerializer:
    """Serialize an object into the XPC payload of a mach msg."""

    def serialize(self, value: Any) -> bytes:
        return (
            int_to_bytes(0x40585043, 4)  # magic
            + int_to_bytes(5, 4)  # version
            + self._serialize_value(value)
        )

    @classmethod
    def _serialize_value(cls, value: Any) -> bytes:
        if isinstance(value, dict) and "$type" in value:
            return cls._serialize_tagged(value)
        elif isinstance(value, dict):
            return int_to_bytes(0xF000, 4) + cls._serialize_dict(value)
        elif isinstance(value, str):
            return int_to_bytes(0x9000, 4) + cls._serialize_string(value)
        elif isinstance(value, int):
            return int_to_bytes(0x3000, 4) + int_to_bytes(value, 8, signed=True)
        else:
            raise TypeError(f"Unsupported xpc type: {type(value).__name__}")

    @staticmethod
    def _serialize_string(value: str) -> bytes:
        data = value.encode("utf-8") + b"\x00"
        return int_to_bytes(len(data), 4) + data + bytes((4 - len(data) % 4) % 4)

    @staticmethod
    def _serialize_key(key: str) -> bytes:
        raw = key.encode("utf-8") + b"\x00"
        return raw + bytes((4 - len(raw) % 4) % 4)

    @classmethod
    def _serialize_dict(cls, value: Dict[str, Any]) -> bytes:
        data = b"".join(
            cls._serialize_key(key) + cls._serialize_value(item)
            for key, item in value.items()
        )

        return (
            int_to_bytes(4 + len(data), 4)  # wire length
            + int_to_bytes(len(value), 4)  # count
            + data
        )

    @staticmethod
    def _serialize_tagged(value: Dict[str, Any]) -> bytes:
        type_ = value["$type"]

        if type_ == "uint64":
            return int_to_bytes(0x4000, 4) + int_to_bytes(value["value"], 8)
        elif type_ == "mach_send_right":
            return int_to_bytes(0xD000, 4)
        else:
            raise TypeError(f"Unsupported wire type: {type_!r}")


class XpcMessageHandler:
    """Receive and reply XPC messages."""

    def __init__(self, emu: Chomper):
        self.emu = emu

    def _create_xpc_dictionary(self, data: Optional[Dict[str, Any]] = None) -> int:
        """Create a XPC dictionary based on a dict."""
        with self.emu.memory_scope() as mem:
            dictionary = self.emu.call_symbol("_xpc_dictionary_create_empty")

            for key, value in (data or {}).items():
                key_ptr = mem.create_string(key)

                if isinstance(value, bytes):
                    value_ptr = mem.create_buffer(len(value))
                    self.emu.write_bytes(value_ptr, value)

                    self.emu.call_symbol(
                        "_xpc_dictionary_set_data",
                        dictionary,
                        key_ptr,
                        value_ptr,
                        len(value),
                    )
                elif isinstance(value, dict):
                    nested = self._create_xpc_dictionary(value)

                    self.emu.call_symbol(
                        "_xpc_dictionary_set_value",
                        dictionary,
                        key_ptr,
                        nested,
                    )
                    self.emu.call_symbol("_xpc_release", nested)
                elif isinstance(value, bool):
                    self.emu.call_symbol(
                        "_xpc_dictionary_set_bool",
                        dictionary,
                        key_ptr,
                        int(value),
                    )
                elif isinstance(value, int):
                    self.emu.call_symbol(
                        "_xpc_dictionary_set_int64",
                        dictionary,
                        key_ptr,
                        value,
                    )
                elif isinstance(value, str):
                    self.emu.call_symbol(
                        "_xpc_dictionary_set_string",
                        dictionary,
                        key_ptr,
                        mem.create_string(value),
                    )
                elif isinstance(value, float):
                    self.emu.call_symbol(
                        "_xpc_dictionary_set_double",
                        dictionary,
                        key_ptr,
                        float_args=[("double", value)],
                    )
                else:
                    raise TypeError(f"Unsupported xpc type: {type(value).__name__}")

            return dictionary

    def _read_xpc_dictionary_value(self, obj: int, key: str) -> Any:
        """Read the value of a key in a XPC dictionary."""
        with self.emu.memory_scope() as mem:
            value = self.emu.call_symbol(
                "_xpc_dictionary_get_value",
                obj,
                mem.create_string(key),
            )

        if not value:
            return None

        type_id = self.emu.call_symbol("_xpc_get_type", value)

        if type_id == self.emu.get_symbol("__xpc_type_null").address:
            return None
        elif type_id == self.emu.get_symbol("__xpc_type_bool").address:
            return bool(self.emu.call_symbol("_xpc_bool_get_value", value))
        elif type_id == self.emu.get_symbol("__xpc_type_int64").address:
            result = self.emu.call_symbol("_xpc_int64_get_value", value)
            return result - (1 << 64) if result >= (1 << 63) else result
        elif type_id == self.emu.get_symbol("__xpc_type_uint64").address:
            return self.emu.call_symbol("_xpc_uint64_get_value", value)
        elif type_id == self.emu.get_symbol("__xpc_type_double").address:
            result = self.emu.call_symbol(
                "_xpc_double_get_value",
                value,
                return_type="double",
            )
            return bytes_to_float(result.to_bytes(8, self.emu.endian), self.emu.endian)
        elif type_id == self.emu.get_symbol("__xpc_type_string").address:
            string_ptr = self.emu.call_symbol("_xpc_string_get_string_ptr", value)
            return self.emu.read_string(string_ptr)
        elif type_id == self.emu.get_symbol("__xpc_type_data").address:
            length = self.emu.call_symbol("_xpc_data_get_length", value)
            bytes_ptr = self.emu.call_symbol("_xpc_data_get_bytes_ptr", value)
            return self.emu.read_bytes(bytes_ptr, length)
        elif type_id == self.emu.get_symbol("__xpc_type_uuid").address:
            bytes_ptr = self.emu.call_symbol("_xpc_uuid_get_bytes", value)
            return self.emu.read_bytes(bytes_ptr, 16)

        return None

    def _read_cf_string(self, obj: int) -> str:
        length = self.emu.call_symbol("_CFStringGetLength", obj)
        size = length * 4 + 1

        with self.emu.memory_scope() as mem:
            buffer = mem.create_buffer(size)

            self.emu.call_symbol(
                "_CFStringGetCString",
                obj,
                buffer,
                size,
                0x8000100,  # kCFStringEncodingUTF8
            )

            return self.emu.read_string(buffer)

    def _read_cf_object(self, obj: int) -> Any:
        """Convert a CF object into a Python object."""
        type_id = self.emu.call_symbol("_CFGetTypeID", obj)

        if type_id == self.emu.call_symbol("_CFBooleanGetTypeID"):
            return bool(self.emu.call_symbol("_CFBooleanGetValue", obj))
        elif type_id == self.emu.call_symbol("_CFStringGetTypeID"):
            return self._read_cf_string(obj)
        elif type_id == self.emu.call_symbol("_CFDataGetTypeID"):
            length = self.emu.call_symbol("_CFDataGetLength", obj)
            byte_ptr = self.emu.call_symbol("_CFDataGetBytePtr", obj)
            return self.emu.read_bytes(byte_ptr, length)
        elif type_id == self.emu.call_symbol("_CFNumberGetTypeID"):
            with self.emu.memory_scope() as mem:
                value = mem.create_buffer(8)

                self.emu.call_symbol(
                    "_CFNumberGetValue",
                    obj,
                    4,  # kCFNumberSInt64Type
                    value,
                )

                return self.emu.read_s64(value)
        elif type_id == self.emu.call_symbol("_CFArrayGetTypeID"):
            count = self.emu.call_symbol("_CFArrayGetCount", obj)
            array = []

            for index in range(count):
                value = self.emu.call_symbol("_CFArrayGetValueAtIndex", obj, index)
                array.append(self._read_cf_object(value))

            return array
        elif type_id == self.emu.call_symbol("_CFDictionaryGetTypeID"):
            count = self.emu.call_symbol("_CFDictionaryGetCount", obj)
            dictionary = {}

            with self.emu.memory_scope() as mem:
                keys = mem.create_buffer(count * 8)
                values = mem.create_buffer(count * 8)

                self.emu.call_symbol("_CFDictionaryGetKeysAndValues", obj, keys, values)

                for index in range(count):
                    key = self._read_cf_string(self.emu.read_pointer(keys + index * 8))
                    value = self._read_cf_object(
                        self.emu.read_pointer(values + index * 8)
                    )
                    dictionary[key] = value

                return dictionary

        return None

    @classmethod
    def _add_plist_type_info(cls, obj: Any):
        data = {}
        if isinstance(obj, int):
            data.update(
                {
                    "type": "int",
                    "value": obj,
                }
            )
        elif isinstance(obj, str):
            data.update(
                {
                    "type": "string_ascii",
                    "value": obj,
                }
            )
        elif isinstance(obj, (bytes, bytearray)):
            data.update(
                {
                    "type": "data.hexstring",
                    "value": binascii.b2a_hex(obj).decode("utf-8"),
                }
            )
        elif isinstance(obj, (list, tuple)):
            data.update(
                {
                    "type": "array",
                    "value": [cls._add_plist_type_info(item) for item in obj],
                }
            )
        elif isinstance(obj, dict):
            data.update(
                {
                    "type": "dict",
                    "value": {
                        key: cls._add_plist_type_info(value)
                        for key, value in obj.items()
                    },
                }
            )
        elif obj is None:
            data.update(
                {
                    "type": "null",
                    "value": None,
                }
            )
        else:
            raise ValueError(f"Unsupported type: {type(obj).__name__}")
        return data

    def handle_message(self, connection: int, message: int) -> int:
        name_ptr = self.emu.call_symbol("_xpc_connection_get_name", connection)
        desc_ptr = self.emu.call_symbol("_xpc_copy_description", message)

        name = self.emu.read_string(name_ptr) if name_ptr else ""
        desc = self.emu.read_string(desc_ptr) if desc_ptr else ""
        connection_name = f"'{name}'" if name else hex(connection)

        self.emu.logger.info("Received an xpc message to %s: %s", connection_name, desc)

        if not name:
            return 0

        # NSXPCConnection
        root_obj = self.parse_ns_xpc_message(message)
        if root_obj and isinstance(root_obj, list):
            sel_name = root_obj[0]
            return self.reply_ns_xpc_message(name, sel_name)

        if name == "com.apple.cfprefsd.daemon":
            return self._handle_cfprefsd_message(message)
        elif name == "com.apple.securityd":
            return self._handle_securityd_message(message)
        elif name == "com.apple.SystemConfiguration.DNSConfiguration":
            return self._handle_dns_configuration_message(message)

        return 0

    def parse_ns_xpc_message(self, message: int) -> Optional[Any]:
        # Parse object
        root_data = self._read_xpc_dictionary_value(message, "root")
        if not root_data:
            return None

        plist_parser = _BinaryPlist17Parser(dict_type=dict)

        root_obj = plist_parser.parse(BytesIO(root_data))
        if not root_obj:
            return None

        self.emu.logger.info("object = %s", root_obj)

        return root_obj

    def create_ns_xpc_reply(self, obj: Any) -> int:
        write_io = BytesIO()
        plist_writer = _BinaryPlist17Writer(write_io)
        plist_writer.write(self._add_plist_type_info(obj), with_type_info=True)
        reply_data = write_io.getvalue()

        return self._create_xpc_dictionary(
            {
                "root": reply_data,
            }
        )

    def reply_ns_xpc_message(self, name: str, sel_name: str) -> int:
        reply_obj = None

        if name == "com.apple.lsd.advertisingidentifiers":
            if sel_name == "getIdentifierOfType:completionHandler:":
                reply_obj = self._reply_get_identifier_of_type()
        elif name == "com.apple.bird.token":
            if sel_name == "currentAccountCopyTokenWithBundleID:version:reply:":
                reply_obj = self._reply_current_account_copy_token()
        elif name == "com.apple.lsd.mapdb":
            if sel_name == "getBundleProxyForCurrentProcessWithCompletionHandler:":
                reply_obj = self._reply_get_bundle_proxy()
            elif sel_name == "resolveQueries:legacySPI:completionHandler:":
                reply_obj = self._reply_resolve_queries()
            elif (
                sel_name
                == "getWhetherTypeIdentifier:conformsToTypeIdentifier:completionHandler:"  # noqa
            ):
                reply_obj = self._reply_get_whether_type_identifier()
        elif name == "com.apple.mobilegestalt.xpc":
            if sel_name == "getServerAnswerForQuestion:reply:":
                reply_obj = self._reply_get_server_answer_for_question()
        elif name == "com.apple.commcenter.coretelephony.xpc":
            if sel_name == "getDescriptorsForDomain:completion:":
                reply_obj = self._reply_get_descriptors_for_domain()
        elif name == "com.apple.locationd.synchronous":
            if sel_name == "getLocationServicesEnabledWithReplyBlock:":
                reply_obj = self._reply_get_location_services_enabled()
            elif (
                sel_name == "getAuthorizationStatusForBundleID:orBundlePath:replyBlock:"
            ):
                reply_obj = self._reply_get_authorization_status_for_bundle_id()
        elif name == "com.apple.pasteboard.pasted":
            if sel_name == "pasteboardWithName:createIfNeeded:completionBlock:":
                reply_obj = self._reply_pasteboard_with_name()
            elif sel_name == "savePasteboard:dataProviderEndpoint:completionBlock:":
                reply_obj = self._reply_save_pasteboard()

        if not reply_obj:
            from_addr = self.emu.debug_symbol(
                self.emu.uc.reg_read(self.emu.arch.reg_lr)
            )
            self.emu.logger.warning(
                f"Ignored an 'xpc_connection_send_message_with_reply_sync' "
                f"called from {from_addr}."
            )
            return 0

        return self.create_ns_xpc_reply(reply_obj)

    def _handle_cfprefsd_message(self, message: int) -> int:
        operation = self._read_xpc_dictionary_value(message, "CFPreferencesOperation")
        if operation in (1, 5):
            plist_data = plistlib.dumps(
                self.emu.ios_os.preferences,
                fmt=plistlib.FMT_BINARY,
            )

            return self._create_xpc_dictionary(
                {
                    "CFPreferencesPropertyList": plist_data,
                }
            )

        return 0

    def _handle_securityd_message(self, message: int) -> int:
        operation = self._read_xpc_dictionary_value(message, "operation")

        query = self._sec_xpc_dictionary_copy_plist(message, "query")
        if query is None:
            return self._create_sec_error_reply(-25300)

        # Filter out protocol fields
        match_query = {
            key: value
            for key, value in query.items()
            if not key.startswith(("m_", "r_", "u_"))
        }

        if operation == 0:  # Add
            self.emu.ios_os.sec_item_add(match_query)

            reply = self._create_xpc_dictionary()
            self._sec_xpc_dictionary_set_plist(reply, "status", match_query)

            return reply
        elif operation == 1:  # CopyMatching
            items = self.emu.ios_os.sec_item_copy_matching(match_query)
            if not items:
                return self._create_sec_error_reply(-25300)

            result = items if query.get("m_Limit") == "m_LimitAll" else items[0]

            reply = self._create_xpc_dictionary()
            self._sec_xpc_dictionary_set_plist(reply, "status", result)

            return reply
        elif operation == 2:  # Update
            attributes = self._sec_xpc_dictionary_copy_plist(
                message,
                "attributesToUpdate",
            )
            count = self.emu.ios_os.sec_item_update(match_query, attributes or {})

            if not count:
                return self._create_sec_error_reply(-25300)
        elif operation == 3:  # Delete
            count = self.emu.ios_os.sec_item_delete(match_query)

            if not count:
                return self._create_sec_error_reply(-25300)

        return self._create_xpc_dictionary()

    def _create_sec_error_reply(self, status: int) -> int:
        return self._create_xpc_dictionary(
            {
                "error": {
                    "domain": "NSOSStatusErrorDomain",
                    "code": status,
                },
            }
        )

    def _sec_xpc_dictionary_set_plist(self, dictionary: int, key: str, value: Any):
        """Set a DER encoded plist into a XPC dictionary by key."""
        objc = ObjcRuntime(self.emu)

        if isinstance(value, list):
            plist = objc.create_cf_array(value)
        elif isinstance(value, dict):
            plist = objc.create_cf_dictionary(value)
        else:
            raise TypeError(f"Unsupported plist type: {type(value).__name__}")

        with self.emu.memory_scope() as mem:
            self.emu.call_symbol(
                "_SecXPCDictionarySetPListWithRepair",
                dictionary,
                mem.create_string(key),
                plist,
            )

        self.emu.call_symbol("_CFRelease", plist)

    def _sec_xpc_dictionary_copy_plist(self, dictionary: int, key: str) -> Any:
        """Copy a DER encoded plist from a XPC dictionary by key."""
        with self.emu.memory_scope() as mem:
            plist = self.emu.call_symbol(
                "_SecXPCDictionaryCopyPList",
                dictionary,
                mem.create_string(key),
                0,
            )

        if not plist:
            return None

        value = self._read_cf_object(plist)

        self.emu.call_symbol("_CFRelease", plist)

        return value

    def _handle_dns_configuration_message(self, message: int) -> int:
        request_op = self._read_xpc_dictionary_value(message, "request_op")

        if request_op == 65537:  # _res_9_ninit
            return self._create_xpc_dictionary()

        return 0

    @staticmethod
    def _reply_get_identifier_of_type():
        uuid_obj = uuid.uuid4()
        uuid_bytes = uuid_obj.bytes

        return [
            None,
            'v16@?0@"NSUUID"8',
            [
                {
                    "$class": "NSUUID",
                    "NS.uuidbytes": uuid_bytes,
                },
            ],
        ]

    @staticmethod
    def _reply_current_account_copy_token():
        return [
            None,
            'v24@?0@"NSData"8@"NSError"16',
            [
                bytes(128),  # type: ignore
                None,  # type: ignore
            ],
        ]

    @staticmethod
    def _reply_get_bundle_proxy():
        return [
            None,
            'v24@?0@"LSBundleProxy"8@"NSError"16',
            [
                {
                    "$class": "LSBundleProxy",
                },
                None,  # type: ignore
            ],
        ]

    @staticmethod
    def _reply_resolve_queries():
        return [
            None,
            'v24@?0@"NSDictionary"8@"NSError"16',
            [
                None,
                None,
            ],
        ]

    @staticmethod
    def _reply_get_whether_type_identifier():
        return [
            None,
            "v12@?0B8",
            [0],
        ]

    @staticmethod
    def _reply_get_server_answer_for_question():
        return [
            None,
            'v16@?0@"NSDictionary"8',
            [
                None,  # type: ignore
            ],
        ]

    @staticmethod
    def _reply_get_descriptors_for_domain():
        return [
            None,
            'v24@?0@"CTServiceDescriptorContainer"8@"NSError"16',
            [
                {
                    "$class": "CTServiceDescriptorContainer",
                },
                None,  # type: ignore
            ],
        ]

    @staticmethod
    def _reply_get_location_services_enabled():
        return [
            None,
            'v20@?0@"NSError"8i16',
            [
                None,
                0,
            ],
        ]

    @staticmethod
    def _reply_get_authorization_status_for_bundle_id():
        return [
            None,
            'v20@?0@"NSError"8i16',
            [
                None,
                0,
            ],
        ]

    @staticmethod
    def _reply_pasteboard_with_name():
        return [
            None,
            'v24@?0@"PBItemCollection"8@"NSError"16',
            [
                None,
                None,
            ],
        ]

    @staticmethod
    def _reply_save_pasteboard():
        return [
            None,
            'v32@?0Q8q16@"NSError"24',
            [
                0,
                0,
                None,
            ],
        ]
