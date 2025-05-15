import os

from chomper import Chomper
from chomper.const import ARCH_ARM64, OS_IOS
from chomper.objc import ObjC
from unicorn import UC_MEM_READ

base_path = os.path.abspath(os.path.dirname(__file__))


def hook_access(uc, address, size, user_data):
    emu = user_data["emu"]
    emu.logger.info("access called")


def hook_stat(uc, address, size, user_data):
    emu = user_data["emu"]
    emu.logger.info("stat called")


def hook_ui_device_current_device(uc, address, size, user_data):
    emu = user_data["emu"]
    emu.logger.info("+[UIDevice currentDevice] called")


def hook_ui_device_identifier_for_vendor(uc, address, size, user_data):
    emu = user_data["emu"]
    objc = ObjC(emu)
    return objc.msg_send("NSUUID", "UUID")


def mem_hook(uc, access, address, size, value, user_data):
    emu = user_data.get("emu")
    access_str = "READ" if access == UC_MEM_READ else "WRITE"
    print(f"[{access_str}] addr=0x{address:X}, size={size}, value={value}")


def main():
    emu = Chomper(
        arch=ARCH_ARM64,
        os_type=OS_IOS,
        rootfs_path=os.path.join(base_path, "../rootfs/ios"),
    )
    objc = ObjC(emu)

    # Hook function by symbol name
    emu.add_hook("_access", hook_access)

    # Hook function by address
    stat = emu.find_symbol("_stat")
    emu.add_hook(stat.address, hook_stat)

    # Hook Objetive-C function by symbol name
    emu.add_hook("+[UIDevice currentDevice]", hook_ui_device_current_device)
    
    # Hook Memory Read/Write
    emu.add_mem_hook(mem_hook)
    
    # Hook and intercept
    emu.add_interceptor("-[UIDevice identifierForVendor]", hook_ui_device_identifier_for_vendor)

    ui_device = objc.msg_send("UIDevice", "currentDevice")
    vendor_identifier = objc.msg_send(ui_device, "identifierForVendor")
    print(vendor_identifier)


if __name__ == '__main__':
    main()
