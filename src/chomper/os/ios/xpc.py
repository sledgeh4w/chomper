from __future__ import annotations

import binascii
import uuid
from io import BytesIO
from typing import Any, Optional, TYPE_CHECKING

from chomper.plist17lib import _BinaryPlist17Parser, _BinaryPlist17Writer

if TYPE_CHECKING:
    from chomper.core import Chomper


class XpcMessageHandler:
    """Receive and reply XPC messages."""

    def __init__(self, emu: Chomper):
        self.emu = emu

    def get_connection_name(self, connection: int) -> str:
        name_ptr = self.emu.call_symbol("_xpc_connection_get_name", connection)
        if not name_ptr:
            return ""
        return self.emu.read_string(name_ptr)

    def _copy_description(self, obj: int) -> str:
        desc_ptr = self.emu.call_symbol("_xpc_copy_description", obj)
        return self.emu.read_string(desc_ptr)

    def _dictionary_get_int64(self, obj: int, key: str) -> int:
        with self.emu.mem_context() as ctx:
            return self.emu.call_symbol(
                "_xpc_dictionary_get_int64",
                obj,
                ctx.create_string(key),
            )

    def _dictionary_get_data(self, obj: int, key: str) -> Optional[bytes]:
        with self.emu.mem_context() as ctx:
            key_ptr = ctx.create_string(key)
            length_out = ctx.create_buffer(4)

            result = self.emu.call_symbol(
                "_xpc_dictionary_get_data",
                obj,
                key_ptr,
                length_out,
            )
            if not result:
                return None

            length = self.emu.read_u32(length_out)
            return self.emu.read_bytes(result, length)

    @classmethod
    def _add_type_info(cls, obj: Any):
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
                    "value": [cls._add_type_info(item) for item in obj],
                }
            )
        elif isinstance(obj, dict):
            data.update(
                {
                    "type": "dict",
                    "value": {
                        key: cls._add_type_info(value) for key, value in obj.items()
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
            raise ValueError(f"Unsupported type: {type(obj)}")
        return data

    def handle_message(self, connection: int, message: int) -> int:
        name = self.get_connection_name(connection)
        desc = self._copy_description(message)
        display = f"'{name}'" if name else hex(connection)

        self.emu.logger.info("Received an xpc message to %s: %s", display, desc)

        if not name:
            return 0

        # NSXPCConnection
        root_obj = self.parse_ns_xpc_message(message)
        if root_obj and isinstance(root_obj, list):
            sel_name = root_obj[0]
            return self.reply_ns_xpc_message(name, sel_name)

        if name == "com.apple.SystemConfiguration.DNSConfiguration":
            request_op = self._dictionary_get_int64(message, "request_op")
            # _res_9_ninit
            if request_op == 65537:
                reply = self.emu.call_symbol("_xpc_dictionary_create_empty")
                return reply

        return 0

    def parse_ns_xpc_message(self, message: int) -> Optional[Any]:
        # Parse object
        root_data = self._dictionary_get_data(message, "root")
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
        plist_writer.write(self._add_type_info(obj), with_type_info=True)
        reply_data = write_io.getvalue()

        with self.emu.mem_context() as ctx:
            key_root = ctx.create_string("root")

            reply_buf = ctx.create_buffer(len(reply_data))
            self.emu.write_bytes(reply_buf, reply_data)

            reply = self.emu.call_symbol("_xpc_dictionary_create_empty")
            self.emu.call_symbol(
                "_xpc_dictionary_set_data",
                reply,
                key_root,
                reply_buf,
                len(reply_data),
            )

        return reply

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
