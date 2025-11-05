import ctypes
import plistlib
import time

from unicorn import UcError

from chomper.utils import read_struct, struct_to_bytes, int_to_bytes, float_to_bytes

from . import const
from .structs import (
    MachMsgHeaderT,
    MachMsgBodyT,
    MachMsgPortDescriptorT,
    MachMsgOolDescriptorT,
    VmRegionBasicInfo64,
    MachTimespec,
)


class MachMsgHandler:
    """Handle mach msg."""

    def __init__(self, emu):
        self.emu = emu

    def write_msg(
        self,
        msg: int,
        msg_header: MachMsgHeaderT,
        msg_body: MachMsgBodyT,
        *args,
    ):
        self.emu.write_bytes(
            msg,
            struct_to_bytes(msg_header) + struct_to_bytes(msg_body) + b"".join(args),
        )

    def handle_msg(self, msg: int, option: int):
        msgh = read_struct(self.emu, msg, MachMsgHeaderT)

        msgh_id = msgh.msgh_id
        remote_port = msgh.msgh_remote_port

        self.emu.logger.info(
            "Received a mach msg: msgh_id=%s, remote_port=%s, option=%s",
            msgh_id,
            remote_port,
            hex(option),
        )

        result = None

        if remote_port == self.emu.ios_os.MACH_PORT_HOST:
            if msgh_id == 412:
                result = self._handle_host_get_special_port(msg, msgh)
        elif remote_port == self.emu.ios_os.MACH_PORT_TASK:
            if msgh_id == 3405:
                result = self._handle_task_info(msg, msgh)
            elif msgh_id == 3409:
                result = self._handle_task_get_special_port(msg, msgh)
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
        elif remote_port == self.emu.ios_os.MACH_PORT_BKS_HID_SERVER:
            if msgh_id == 6000050:
                result = self._handle_bks_hid_get_current_display_brightness(msg, msgh)

        # xpc message to com.apple.commcenter.cupolicy.xpc
        if msgh_id == 268435456:
            result = const.KERN_SUCCESS

        if result is None:
            self.emu.logger.warning(
                "Unhandled mach msg, returning KERN_RESOURCE_SHORTAGE"
            )
            return const.KERN_RESOURCE_SHORTAGE

        return result

    def _handle_host_get_special_port(self, msg: int, msgh: MachMsgHeaderT) -> int:
        which_port = self.emu.read_s32(msg + 0x24)

        msg_header = MachMsgHeaderT(
            msgh_bits=const.MACH_MSGH_BITS_COMPLEX,
            msgh_size=40,
            msgh_remote_port=0,
            msgh_local_port=0,
            msgh_voucher_port=0,
            msgh_id=(msgh.msgh_id + 100),
        )

        msg_body = MachMsgBodyT(
            msgh_descriptor_count=1,
        )

        if which_port == const.HOST_PORT:
            port = self.emu.ios_os.MACH_PORT_HOST
        else:
            port = self.emu.ios_os.MACH_PORT_NULL

        port_descriptor = MachMsgPortDescriptorT(
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

        return const.KERN_SUCCESS

    def _handle_task_info(self, msg: int, msgh: MachMsgHeaderT) -> int:
        flavor = self.emu.read_s32(msg + 0x20)
        task_info_out_cnt = self.emu.read_s32(msg + 0x24)

        self.emu.logger.info(f"flavor={flavor}, task_info_out_cnt={task_info_out_cnt}")

        if flavor == const.TASK_AUDIT_TOKEN:
            msg_header = MachMsgHeaderT(
                msgh_bits=0,
                msgh_size=72,
                msgh_remote_port=0,
                msgh_local_port=0,
                msgh_voucher_port=0,
                msgh_id=(msgh.msgh_id + 100),
            )

            msg_body = MachMsgBodyT(
                msgh_descriptor_count=0,
            )

            audit_token = [0, 0, 0, 0, 0, self.emu.ios_os.pid, 0, 1]

            self.write_msg(
                msg,
                msg_header,
                msg_body,
                int_to_bytes(0, 8),
                int_to_bytes(task_info_out_cnt, 4),
                b"".join([int_to_bytes(value, 4) for value in audit_token]),
            )

            return const.KERN_SUCCESS

        return const.KERN_RESOURCE_SHORTAGE

    def _handle_task_get_special_port(self, msg: int, msgh: MachMsgHeaderT) -> int:
        which_port = self.emu.read_s32(msg + 0x20)

        msg_header = MachMsgHeaderT(
            msgh_bits=const.MACH_MSGH_BITS_COMPLEX,
            msgh_size=40,
            msgh_remote_port=0,
            msgh_local_port=0,
            msgh_voucher_port=0,
            msgh_id=(msgh.msgh_id + 100),
        )

        msg_body = MachMsgBodyT(
            msgh_descriptor_count=1,
        )

        if which_port == const.TASK_BOOTSTRAP_PORT:
            port = self.emu.ios_os.MACH_PORT_BOOTSTRAP
        else:
            port = self.emu.ios_os.MACH_PORT_NULL

        port_descriptor = MachMsgPortDescriptorT(
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

        return const.KERN_SUCCESS

    def _handle_semaphore_create(self, msg: int, msgh: MachMsgHeaderT) -> int:
        # policy = self.emu.read_s32(msg_ptr + 0x20)
        value = self.emu.read_s32(msg + 0x24)

        semaphore = self.emu.ios_os.semaphore_create(value)

        msg_header = MachMsgHeaderT(
            msgh_bits=const.MACH_MSGH_BITS_COMPLEX,
            msgh_size=40,
            msgh_remote_port=0,
            msgh_local_port=0,
            msgh_voucher_port=0,
            msgh_id=(msgh.msgh_id + 100),
        )

        msg_body = MachMsgBodyT(
            msgh_descriptor_count=1,
        )

        port_descriptor = MachMsgPortDescriptorT(
            name=semaphore,
            disposition=const.MACH_MSG_TYPE_MOVE_SEND,
            type=const.MACH_MSG_PORT_DESCRIPTOR,
        )

        self.write_msg(
            msg,
            msg_header,
            msg_body,
            struct_to_bytes(port_descriptor),
        )

        return const.KERN_SUCCESS

    def _handle_vm_read_overwrite(self, msg: int, msgh: MachMsgHeaderT) -> int:
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

        msg_header = MachMsgHeaderT(
            msgh_bits=0,
            msgh_size=44,
            msgh_remote_port=0,
            msgh_local_port=0,
            msgh_voucher_port=0,
            msgh_id=(msgh.msgh_id + 100),
        )

        msg_body = MachMsgBodyT(
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

    def _handle_kernelrpc_vm_remap(self, msg: int, msgh: MachMsgHeaderT) -> int:
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

        msg_header = MachMsgHeaderT(
            msgh_bits=0,
            msgh_size=52,
            msgh_remote_port=0,
            msgh_local_port=0,
            msgh_voucher_port=0,
            msgh_id=(msgh.msgh_id + 100),
        )

        msg_body = MachMsgBodyT(
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

    def _handle_vm_region_64(self, msg: int, msgh: MachMsgHeaderT) -> int:
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

            msg_header = MachMsgHeaderT(
                msgh_bits=const.MACH_MSGH_BITS_COMPLEX,
                msgh_size=(68 + out_count * 4),
                msgh_remote_port=0,
                msgh_local_port=0,
                msgh_voucher_port=0,
                msgh_id=(msgh.msgh_id + 100),
            )

            msg_body = MachMsgBodyT(
                msgh_descriptor_count=1,
            )

            port_descriptor = MachMsgPortDescriptorT(
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

        return const.KERN_RESOURCE_SHORTAGE

    def _handle_xpc_pipe_mach_msg(self, msg: int, msgh: MachMsgHeaderT) -> int:
        msg_header = MachMsgHeaderT(
            msgh_bits=0,
            msgh_size=0,
            msgh_remote_port=0,
            msgh_local_port=0,
            msgh_voucher_port=0,
            msgh_id=0x20000000,
        )

        msg_body = MachMsgBodyT(
            msgh_descriptor_count=0,
        )

        self.write_msg(msg, msg_header, msg_body)

        return const.KERN_SUCCESS

    def _handle_clock_get_time(self, msg: int, msgh: MachMsgHeaderT) -> int:
        msg_header = MachMsgHeaderT(
            msgh_bits=0,
            msgh_size=44,
            msgh_remote_port=0,
            msgh_local_port=0,
            msgh_voucher_port=0,
            msgh_id=(msgh.msgh_id + 100),
        )

        msg_body = MachMsgBodyT(
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

    def _handle_cas_get_displays(self, msg: int, msgh: MachMsgHeaderT) -> int:
        displays_prop = [
            {
                "kCADisplayId": 1,
                "kCADisplayName": "LCD",
                "kCADisplayDeviceName": "primary",
            }
        ]
        displays_data = plistlib.dumps(displays_prop, fmt=plistlib.FMT_BINARY)

        displays_buf = self.emu.create_buffer(len(displays_data))
        self.emu.write_bytes(displays_buf, displays_data)

        msg_header = MachMsgHeaderT(
            msgh_bits=const.MACH_MSGH_BITS_COMPLEX,
            msgh_size=56,
            msgh_remote_port=0,
            msgh_local_port=0,
            msgh_voucher_port=0,
            msgh_id=(msgh.msgh_id + 100),
        )

        msg_body = MachMsgBodyT(
            msgh_descriptor_count=1,
        )

        ool_descriptor = MachMsgOolDescriptorT(
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

    def _handle_bks_hid_get_current_display_brightness(
        self,
        msg: int,
        msgh: MachMsgHeaderT,
    ) -> int:
        msg_header = MachMsgHeaderT(
            msgh_bits=0,
            msgh_size=40,
            msgh_remote_port=0,
            msgh_local_port=0,
            msgh_voucher_port=0,
            msgh_id=(msgh.msgh_id + 100),
        )

        msg_body = MachMsgBodyT(
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
