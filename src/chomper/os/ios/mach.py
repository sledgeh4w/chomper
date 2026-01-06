from __future__ import annotations

import ctypes
import plistlib
import time
from typing import Dict, TYPE_CHECKING

from unicorn import UcError

from chomper.os.handle import HandleManager
from chomper.utils import read_struct, struct_to_bytes, int_to_bytes, float_to_bytes

from . import const
from .structs import (
    HostBasicInfo,
    MachMsgHeader,
    MachMsgBody,
    MachMsgPortDescriptor,
    MachMsgOolDescriptor,
    MachMsgOolPortsDescriptor,
    MachTimespec,
    VmRegionBasicInfo64,
    VmStatistics,
    VmStatistics64,
)

if TYPE_CHECKING:
    from chomper.core import Chomper


class MachMsgHandler:
    """Handle mach msg."""

    def __init__(self, emu: Chomper, mach_port_manager: HandleManager):
        self.emu = emu
        self.mach_port_manager = mach_port_manager

    def _get_task_port_map(self) -> Dict[int, int]:
        return {
            const.TASK_BOOTSTRAP_PORT: self.emu.ios_os.MACH_PORT_BOOTSTRAP,
            const.TASK_DEBUG_CONTROL_PORT: self.emu.ios_os.MACH_PORT_DEBUG_CONTROL,
        }

    def write_msg(
        self,
        msg: int,
        msg_header: MachMsgHeader,
        msg_body: MachMsgBody,
        *args,
    ):
        self.emu.write_bytes(
            msg,
            struct_to_bytes(msg_header) + struct_to_bytes(msg_body) + b"".join(args),
        )

    def write_reply_port_msg(self, msg: int, msgh: MachMsgHeader, port: int):
        msg_header = MachMsgHeader(
            msgh_bits=const.MACH_MSGH_BITS_COMPLEX,
            msgh_size=40,
            msgh_remote_port=0,
            msgh_local_port=0,
            msgh_voucher_port=0,
            msgh_id=(msgh.msgh_id + 100),
        )

        msg_body = MachMsgBody(
            msgh_descriptor_count=1,
        )

        port_descriptor = MachMsgPortDescriptor(
            name=port,
            disposition=const.MACH_MSG_TYPE_MOVE_SEND,
            type=const.MACH_MSG_PORT_DESCRIPTOR,
        )

        self.write_msg(
            msg,
            msg_header,
            msg_body,
            struct_to_bytes(port_descriptor),
        )

    def handle_msg(
        self,
        msg: int,
        option: int,
        send_size: int,
        rcv_size: int,
        rcv_name: int,
        timeout: int,
        notify: int,
    ) -> int:
        msgh = read_struct(self.emu, msg, MachMsgHeader)

        msgh_id = msgh.msgh_id
        remote_port = msgh.msgh_remote_port
        local_port = msgh.msgh_local_port

        self.emu.logger.info(
            "Received a mach msg: msgh_id=%s, remote_port=%s, local_port=%s, "
            "option=%s, rcv_name=%s, timeout=%s",
            msgh_id,
            remote_port,
            local_port,
            hex(option),
            rcv_name,
            timeout,
        )

        send = option & const.MACH_SEND_MSG
        rcv = option & const.MACH_RCV_MSG

        # Send only
        if send and not rcv:
            return const.KERN_SUCCESS

        # Receive only
        if not send and rcv:
            return self.handle_rcv_msg(msg, rcv_name)

        return self.handle_send_and_rcv_msg(msg, msgh)

    def handle_rcv_msg(self, msg: int, rcv_name: int) -> int:
        result = None

        if self.mach_port_manager.validate(rcv_name):
            port = self.mach_port_manager.get_prop(rcv_name, "port")

            if port == self.emu.ios_os.MACH_PORT_DEBUG_CONTROL:
                result = const.MACH_RCV_TIMED_OUT

        if result is None:
            result = const.MACH_RCV_TIMED_OUT

        return result

    def handle_send_and_rcv_msg(self, msg: int, msgh: MachMsgHeader) -> int:
        """Handle mach msg with both `MACH_SEND_MSG` and `MACH_RCV_MSG` flags."""
        msgh_id = msgh.msgh_id
        remote_port = msgh.msgh_remote_port

        result = None

        if remote_port == self.emu.ios_os.MACH_PORT_HOST:
            if msgh_id == 200:
                result = self._handle_host_info(msg, msgh)
            elif msgh_id == 205:
                result = self._handle_host_get_io_master(msg, msgh)
            elif msgh_id == 216:
                result = self._handle_host_statistics(msg, msgh)
            elif msgh_id == 219:
                result = self._handle_host_statistics64(msg, msgh)
            elif msgh_id == 412:
                result = self._handle_host_get_special_port(msg, msgh)
        elif remote_port == self.emu.ios_os.MACH_PORT_TASK:
            if msgh_id == 3402:
                result = self._handle_task_threads(msg, msgh)
            elif msgh_id == 3405:
                result = self._handle_task_info(msg, msgh)
            elif msgh_id == 3409:
                result = self._handle_task_get_special_port(msg, msgh)
            elif msgh_id == 3410:
                result = self._handle_task_set_special_port(msg, msgh)
            elif msgh_id == 3418:
                result = self._handle_semaphore_create(msg, msgh)
            elif msgh_id == 4808:
                result = self._handle_vm_read_overwrite(msg, msgh)
            elif msgh_id == 4813:
                result = self._handle_kernelrpc_vm_remap(msg, msgh)
            elif msgh_id == 4816:
                result = self._handle_vm_region_64(msg, msgh)
            elif msgh_id == 8000:  # task_restartable_ranges_register
                result = const.KERN_RESOURCE_SHORTAGE
        elif remote_port == self.emu.ios_os.MACH_PORT_BOOTSTRAP:
            if msgh_id == 1073741824:
                result = self._handle_xpc_pipe_mach_msg(msg, msgh)
        elif remote_port == self.emu.ios_os.MACH_PORT_CLOCK:
            if msgh_id == 1000:
                result = self._handle_clock_get_time(msg, msgh)
        elif remote_port == self.emu.ios_os.MACH_PORT_NOTIFICATION_CENTER:
            result = const.KERN_SUCCESS
        elif remote_port == self.emu.ios_os.MACH_PORT_CA_RENDER_SERVER:
            if msgh_id == 40231:
                result = self._handle_cas_get_displays(msg, msgh)
            # elif msgh_id == 40232:
            #     result = self._handle_ca_display_display_update(msg, msgh)
        elif remote_port == self.emu.ios_os.MACH_PORT_BKS_HID_SERVER:
            if msgh_id == 6000050:
                result = self._handle_bks_hid_get_current_display_brightness(msg, msgh)
        elif remote_port == self.emu.ios_os.MACH_PORT_CONFIGD:
            if msgh_id == 20010:
                result = self._handle_configget(msg, msgh)
        elif self.mach_port_manager.validate(remote_port):
            if msgh_id == 3603:
                result = self._handle_thread_get_state(msg, msgh)

        if result is None:
            self.emu.logger.warning(
                "Unhandled mach msg, returning KERN_RESOURCE_SHORTAGE"
            )
            return const.KERN_RESOURCE_SHORTAGE

        return result

    def _handle_host_info(self, msg: int, msgh: MachMsgHeader) -> int:
        flavor = self.emu.read_s32(msg + 0x20)
        count = self.emu.read_s32(msg + 0x24)

        self.emu.logger.info(f"flavor={flavor}, count={count}")

        if flavor == const.HOST_BASIC_INFO:
            msg_header = MachMsgHeader(
                msgh_bits=0,
                msgh_size=40 + ctypes.sizeof(HostBasicInfo),
                msgh_remote_port=0,
                msgh_local_port=0,
                msgh_voucher_port=0,
                msgh_id=(msgh.msgh_id + 100),
            )

            msg_body = MachMsgBody(
                msgh_descriptor_count=0,
            )

            info = HostBasicInfo(
                # TODO: Fill values
            )

            self.write_msg(
                msg,
                msg_header,
                msg_body,
                int_to_bytes(0, 8),
                int_to_bytes(count, 4),
                struct_to_bytes(info),
            )

            return const.KERN_SUCCESS
        else:
            self.emu.logger.warning(f"Unhandled host_info: flavor={flavor}")

        return const.KERN_RESOURCE_SHORTAGE

    def _handle_host_get_io_master(self, msg: int, msgh: MachMsgHeader) -> int:
        port = self.emu.ios_os.MACH_PORT_IO_MASTER

        self.write_reply_port_msg(msg, msgh, port)

        return const.KERN_SUCCESS

    def _handle_host_statistics(self, msg: int, msgh: MachMsgHeader) -> int:
        flavor = self.emu.read_s32(msg + 0x20)
        count = self.emu.read_s32(msg + 0x24)

        self.emu.logger.info(f"flavor={flavor}, count={count}")

        if flavor == const.HOST_VM_INFO:
            msg_header = MachMsgHeader(
                msgh_bits=0,
                msgh_size=40 + ctypes.sizeof(VmStatistics),
                msgh_remote_port=0,
                msgh_local_port=0,
                msgh_voucher_port=0,
                msgh_id=(msgh.msgh_id + 100),
            )

            msg_body = MachMsgBody(
                msgh_descriptor_count=0,
            )

            info = VmStatistics(
                # TODO: Fill values
            )

            self.write_msg(
                msg,
                msg_header,
                msg_body,
                int_to_bytes(0, 8),
                int_to_bytes(count, 4),
                struct_to_bytes(info),
            )

            return const.KERN_SUCCESS
        else:
            self.emu.logger.warning(f"Unhandled host_statistics: flavor={flavor}")

        return const.KERN_RESOURCE_SHORTAGE

    def _handle_host_statistics64(self, msg: int, msgh: MachMsgHeader) -> int:
        flavor = self.emu.read_s32(msg + 0x20)
        count = self.emu.read_s32(msg + 0x24)

        self.emu.logger.info(f"flavor={flavor}, count={count}")

        if flavor == const.HOST_VM_INFO64:
            msg_header = MachMsgHeader(
                msgh_bits=0,
                msgh_size=40 + ctypes.sizeof(VmStatistics64),
                msgh_remote_port=0,
                msgh_local_port=0,
                msgh_voucher_port=0,
                msgh_id=(msgh.msgh_id + 100),
            )

            msg_body = MachMsgBody(
                msgh_descriptor_count=0,
            )

            info = VmStatistics64(
                # TODO: Fill values
            )

            self.write_msg(
                msg,
                msg_header,
                msg_body,
                int_to_bytes(0, 8),
                int_to_bytes(count, 4),
                struct_to_bytes(info),
            )

            return const.KERN_SUCCESS
        else:
            self.emu.logger.warning(f"Unhandled host_statistics64: flavor={flavor}")

        return const.KERN_RESOURCE_SHORTAGE

    def _handle_host_get_special_port(self, msg: int, msgh: MachMsgHeader) -> int:
        which_port = self.emu.read_s32(msg + 0x24)

        if which_port == const.HOST_PORT:
            port = self.emu.ios_os.MACH_PORT_HOST
        else:
            port = self.emu.ios_os.MACH_PORT_NULL
            self.emu.logger.warning(
                f"Unhandled host_get_special_port: which_port={which_port}"
            )

        self.write_reply_port_msg(msg, msgh, port)

        return const.KERN_SUCCESS

    def _handle_task_threads(self, msg: int, msgh: MachMsgHeader) -> int:
        thread_act = self.mach_port_manager.new()
        if not thread_act:
            return const.KERN_RESOURCE_SHORTAGE

        self.mach_port_manager.set_prop(thread_act, "tid", self.emu.ios_os.tid)

        thread_act_list = [thread_act]

        count = len(thread_act_list)
        address = self.emu.create_buffer(4 * count)

        self.emu.write_array(
            address,
            thread_act_list,
            size=4,
        )

        msg_header = MachMsgHeader(
            msgh_bits=const.MACH_MSGH_BITS_COMPLEX,
            msgh_size=56,
            msgh_remote_port=0,
            msgh_local_port=0,
            msgh_voucher_port=0,
            msgh_id=(msgh.msgh_id + 100),
        )

        msg_body = MachMsgBody(
            msgh_descriptor_count=1,
        )

        descriptor = MachMsgOolPortsDescriptor(
            address=address,
            deallocate=0,
            copy=0,
            disposition=const.MACH_MSG_TYPE_MOVE_SEND,
            type=const.MACH_MSG_OOL_PORTS_DESCRIPTOR,
            count=count,
        )

        self.write_msg(
            msg,
            msg_header,
            msg_body,
            struct_to_bytes(descriptor),
            int_to_bytes(0, 8),
            int_to_bytes(count, 4),
        )

        return const.KERN_SUCCESS

    def _handle_task_info(self, msg: int, msgh: MachMsgHeader) -> int:
        flavor = self.emu.read_s32(msg + 0x20)
        count = self.emu.read_s32(msg + 0x24)

        self.emu.logger.info(f"flavor={flavor}, count={count}")

        if flavor == const.TASK_AUDIT_TOKEN:
            msg_header = MachMsgHeader(
                msgh_bits=0,
                msgh_size=72,
                msgh_remote_port=0,
                msgh_local_port=0,
                msgh_voucher_port=0,
                msgh_id=(msgh.msgh_id + 100),
            )

            msg_body = MachMsgBody(
                msgh_descriptor_count=0,
            )

            audit_token = [0, 0, 0, 0, 0, self.emu.ios_os.pid, 0, 1]

            self.write_msg(
                msg,
                msg_header,
                msg_body,
                int_to_bytes(0, 8),
                int_to_bytes(count, 4),
                b"".join([int_to_bytes(value, 4) for value in audit_token]),
            )

            return const.KERN_SUCCESS
        else:
            self.emu.logger.warning(f"Unhandled task_info: flavor={flavor}")

        return const.KERN_RESOURCE_SHORTAGE

    def _handle_task_get_special_port(self, msg: int, msgh: MachMsgHeader) -> int:
        which_port = self.emu.read_s32(msg + 0x20)

        task_port_map = self._get_task_port_map()

        if which_port in task_port_map:
            port = task_port_map[which_port]
        else:
            port = self.emu.ios_os.MACH_PORT_NULL
            self.emu.logger.warning(
                f"Unhandled task_get_special_port: which_port={which_port}"
            )

        self.write_reply_port_msg(msg, msgh, port)

        return const.KERN_SUCCESS

    def _handle_task_set_special_port(self, msg: int, msgh: MachMsgHeader) -> int:
        special_port = self.emu.read_s32(msg + 0x24)
        which_port = self.emu.read_s32(msg + 0x30)

        task_port_map = self._get_task_port_map()

        self.emu.logger.info(f"special_port={special_port}, which_port={which_port}")

        if self.mach_port_manager.validate(special_port):
            if which_port in task_port_map:
                port = task_port_map[which_port]
                self.mach_port_manager.set_prop(special_port, "port", port)

        msg_header = MachMsgHeader(
            msgh_bits=0,
            msgh_size=36,
            msgh_remote_port=0,
            msgh_local_port=0,
            msgh_voucher_port=0,
            msgh_id=(msgh.msgh_id + 100),
        )

        msg_body = MachMsgBody(
            msgh_descriptor_count=0,
        )

        self.write_msg(
            msg,
            msg_header,
            msg_body,
            int_to_bytes(0, 8),
        )

        return const.KERN_SUCCESS

    def _handle_semaphore_create(self, msg: int, msgh: MachMsgHeader) -> int:
        # policy = self.emu.read_s32(msg_ptr + 0x20)
        value = self.emu.read_s32(msg + 0x24)
        semaphore = self.emu.ios_os.semaphore_create(value)

        self.write_reply_port_msg(msg, msgh, semaphore)

        return const.KERN_SUCCESS

    def _handle_thread_get_state(self, msg: int, msgh: MachMsgHeader) -> int:
        tid = self.mach_port_manager.get_prop(msgh.msgh_remote_port, "tid")
        self.emu.logger.warning(f"Unhandled thread_get_state: tid={tid}")
        return const.KERN_RESOURCE_SHORTAGE

    def _handle_vm_read_overwrite(self, msg: int, msgh: MachMsgHeader) -> int:
        address = self.emu.read_u64(msg + 0x20)
        size = self.emu.read_u32(msg + 0x28)
        data = self.emu.read_u64(msg + 0x30)

        self.emu.logger.info(f"address={hex(address)}, size={size}, data={hex(data)}")

        try:
            read_data = self.emu.read_bytes(address, size)
            out_size = len(read_data)
            self.emu.write_bytes(data, read_data)
        except UcError:
            self.emu.logger.warning("vm_read_overwrite failed: invalid address")
            return const.KERN_INVALID_ADDRESS

        msg_header = MachMsgHeader(
            msgh_bits=0,
            msgh_size=44,
            msgh_remote_port=0,
            msgh_local_port=0,
            msgh_voucher_port=0,
            msgh_id=(msgh.msgh_id + 100),
        )

        msg_body = MachMsgBody(
            msgh_descriptor_count=0,
        )

        self.write_msg(
            msg,
            msg_header,
            msg_body,
            int_to_bytes(0, 8),
            int_to_bytes(out_size, 8),
        )

        return const.KERN_SUCCESS

    def _handle_kernelrpc_vm_remap(self, msg: int, msgh: MachMsgHeader) -> int:
        target_address = self.emu.read_u64(msg + 0x30)
        size = self.emu.read_u32(msg + 0x38)
        mask = self.emu.read_u64(msg + 0x40)
        flags = self.emu.read_u32(msg + 0x48)
        src_address = self.emu.read_u64(msg + 0x4C)
        copy = self.emu.read_u32(msg + 0x54)

        self.emu.logger.info(
            f"target_address={hex(target_address)}, size={size}, mask={mask}, "
            f"flags={hex(flags)}, src_address={hex(src_address)}, copy={copy}"
        )

        if not target_address:
            target_address = self.emu.create_buffer(size)

        read_data = self.emu.read_bytes(src_address, size)
        self.emu.write_bytes(target_address, read_data)

        msg_header = MachMsgHeader(
            msgh_bits=0,
            msgh_size=52,
            msgh_remote_port=0,
            msgh_local_port=0,
            msgh_voucher_port=0,
            msgh_id=(msgh.msgh_id + 100),
        )

        msg_body = MachMsgBody(
            msgh_descriptor_count=0,
        )

        self.write_msg(
            msg,
            msg_header,
            msg_body,
            int_to_bytes(0, 8),
            int_to_bytes(target_address, 8),
            int_to_bytes(0, 4),
            int_to_bytes(0, 4),
        )

        return const.KERN_SUCCESS

    def _handle_vm_region_64(self, msg: int, msgh: MachMsgHeader) -> int:
        address = self.emu.read_u64(msg + 0x20)
        flavor = self.emu.read_s32(msg + 0x28)
        count = self.emu.read_u32(msg + 0x2C)

        self.emu.logger.info(f"address={hex(address)}, flavor={flavor}, count={count}")

        if flavor == const.VM_REGION_BASIC_INFO_64:
            for start, end, prop in self.emu.uc.mem_regions():
                if start <= address < end:
                    out_address = start
                    size = end - start
                    break
            else:
                self.emu.logger.warning("vm_region_64 failed: invalid address")
                return const.KERN_INVALID_ADDRESS

            out_count = ctypes.sizeof(VmRegionBasicInfo64) // 4
            object_name = 0

            info = VmRegionBasicInfo64(
                protection=const.VM_PROT_DEFAULT,
                max_protection=const.VM_PROT_DEFAULT,
                inheritance=0,
                shared=0,
                reserved=0,
                offset=0,
                behavior=0,
                user_wired_count=0,
            )

            msg_header = MachMsgHeader(
                msgh_bits=const.MACH_MSGH_BITS_COMPLEX,
                msgh_size=(68 + out_count * 4),
                msgh_remote_port=0,
                msgh_local_port=0,
                msgh_voucher_port=0,
                msgh_id=(msgh.msgh_id + 100),
            )

            msg_body = MachMsgBody(
                msgh_descriptor_count=1,
            )

            port_descriptor = MachMsgPortDescriptor(
                name=object_name,
                disposition=const.MACH_MSG_TYPE_MOVE_SEND,
                type=const.MACH_MSG_PORT_DESCRIPTOR,
            )

            self.write_msg(
                msg,
                msg_header,
                msg_body,
                struct_to_bytes(port_descriptor),
                int_to_bytes(0, 8),
                int_to_bytes(out_address, 8),
                int_to_bytes(size, 8),
                int_to_bytes(out_count, 4),
                struct_to_bytes(info),
            )

            return const.KERN_SUCCESS
        else:
            self.emu.logger.warning(f"Unhandled vm_region_64: flavor={flavor}")

        return const.KERN_RESOURCE_SHORTAGE

    def _handle_xpc_pipe_mach_msg(self, msg: int, msgh: MachMsgHeader) -> int:
        msg_header = MachMsgHeader(
            msgh_bits=0,
            msgh_size=0,
            msgh_remote_port=0,
            msgh_local_port=0,
            msgh_voucher_port=0,
            msgh_id=0x20000000,
        )

        msg_body = MachMsgBody(
            msgh_descriptor_count=0x40585043,
        )

        audit_token = [0, 0, 0, 0, 0, self.emu.ios_os.pid, 0, 1]

        self.write_msg(
            msg,
            msg_header,
            msg_body,
            int_to_bytes(0, 4),
            b"".join([int_to_bytes(value, 4) for value in audit_token]),
        )

        return const.KERN_SUCCESS

    def _handle_clock_get_time(self, msg: int, msgh: MachMsgHeader) -> int:
        msg_header = MachMsgHeader(
            msgh_bits=0,
            msgh_size=44,
            msgh_remote_port=0,
            msgh_local_port=0,
            msgh_voucher_port=0,
            msgh_id=(msgh.msgh_id + 100),
        )

        msg_body = MachMsgBody(
            msgh_descriptor_count=1,
        )

        time_ns = time.time_ns()
        cur_time = MachTimespec.from_time_ns(time_ns)

        self.write_msg(
            msg,
            msg_header,
            msg_body,
            int_to_bytes(0, 8),
            struct_to_bytes(cur_time),
        )

        return const.KERN_SUCCESS

    def _handle_cas_get_displays(self, msg: int, msgh: MachMsgHeader) -> int:
        displays = [
            {
                "kCADisplayId": 1,
                "kCADisplayName": "LCD",
                "kCADisplayDeviceName": "primary",
            }
        ]

        displays_data = plistlib.dumps(displays, fmt=plistlib.FMT_BINARY)

        displays_buf = self.emu.create_buffer(len(displays_data))
        self.emu.write_bytes(displays_buf, displays_data)

        msg_header = MachMsgHeader(
            msgh_bits=const.MACH_MSGH_BITS_COMPLEX,
            msgh_size=56,
            msgh_remote_port=0,
            msgh_local_port=0,
            msgh_voucher_port=0,
            msgh_id=(msgh.msgh_id + 100),
        )

        msg_body = MachMsgBody(
            msgh_descriptor_count=1,
        )

        ool_descriptor = MachMsgOolDescriptor(
            address=displays_buf,
            deallocate=0,
            copy=0,
            disposition=0,
            type=const.MACH_MSG_OOL_DESCRIPTOR,
            size=len(displays_data),
        )

        self.write_msg(
            msg,
            msg_header,
            msg_body,
            struct_to_bytes(ool_descriptor),
            int_to_bytes(0, 8),
            int_to_bytes(len(displays_data), 4),
        )

        return const.KERN_SUCCESS

    def _handle_ca_display_display_update(self, msg: int, msgh: MachMsgHeader) -> int:
        msg_header = MachMsgHeader(
            msgh_bits=const.MACH_MSGH_BITS_COMPLEX,
            msgh_size=276,
            msgh_remote_port=0,
            msgh_local_port=0,
            msgh_voucher_port=0,
            msgh_id=(msgh.msgh_id + 100),
        )

        msg_body = MachMsgBody(
            msgh_descriptor_count=2,
        )

        ool_descriptor = MachMsgOolDescriptor(
            address=0,
            deallocate=0,
            copy=0,
            disposition=0,
            type=const.MACH_MSG_OOL_DESCRIPTOR,
            size=0,
        )

        port_descriptor = MachMsgPortDescriptor(
            name=0,
            disposition=const.MACH_MSG_TYPE_MOVE_SEND,
            type=const.MACH_MSG_PORT_DESCRIPTOR,
        )

        self.write_msg(
            msg,
            msg_header,
            msg_body,
            struct_to_bytes(ool_descriptor),
            struct_to_bytes(port_descriptor),
        )

        # Not completed

        return const.KERN_SUCCESS

    def _handle_bks_hid_get_current_display_brightness(
        self,
        msg: int,
        msgh: MachMsgHeader,
    ) -> int:
        msg_header = MachMsgHeader(
            msgh_bits=0,
            msgh_size=40,
            msgh_remote_port=0,
            msgh_local_port=0,
            msgh_voucher_port=0,
            msgh_id=(msgh.msgh_id + 100),
        )

        msg_body = MachMsgBody(
            msgh_descriptor_count=1,
        )

        brightness = 0.4

        self.write_msg(
            msg,
            msg_header,
            msg_body,
            int_to_bytes(0, 8),
            float_to_bytes(brightness),
        )

        return const.KERN_SUCCESS

    def _handle_configget(self, msg: int, msgh: MachMsgHeader) -> int:
        key_ptr = self.emu.read_u64(msg + 0x1C)
        key = self.emu.read_string(key_ptr)

        self.emu.logger.info(f"key='{key}'")

        if key == "State:/Network/Global/Proxies":
            config = {
                "ExceptionsList": [
                    "*.local",
                    "169.254/16",
                ],
                "FTPPassive": 1,
                "__SCOPED__": {
                    "en0": {
                        "ExceptionsList": [
                            "*.local",
                            "169.254/16",
                        ],
                        "FTPPassive": 1,
                    }
                },
            }
        else:
            self.emu.logger.warning(f"Unhandled configget: key='{key}'")
            return const.KERN_RESOURCE_SHORTAGE

        config_data = plistlib.dumps(config, fmt=plistlib.FMT_BINARY)

        config_buf = self.emu.create_buffer(len(config_data))
        self.emu.write_bytes(config_buf, config_data)

        msg_header = MachMsgHeader(
            msgh_bits=const.MACH_MSGH_BITS_COMPLEX,
            msgh_size=64,
            msgh_remote_port=0,
            msgh_local_port=0,
            msgh_voucher_port=0,
            msgh_id=(msgh.msgh_id + 100),
        )

        msg_body = MachMsgBody(
            msgh_descriptor_count=1,
        )

        ool_descriptor = MachMsgOolDescriptor(
            address=config_buf,
            deallocate=0,
            copy=0,
            disposition=0,
            type=const.MACH_MSG_OOL_DESCRIPTOR,
            size=len(config_data),
        )

        self.write_msg(
            msg,
            msg_header,
            msg_body,
            struct_to_bytes(ool_descriptor),
            int_to_bytes(0, 8),
            int_to_bytes(len(config_data), 4),
            int_to_bytes(0, 4),
            int_to_bytes(0, 4),
        )

        return const.KERN_SUCCESS
