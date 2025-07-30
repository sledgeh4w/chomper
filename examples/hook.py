import os

from chomper import Chomper
from chomper.const import ARCH_ARM64, OS_IOS, HOOK_MEM_READ, HOOK_MEM_WRITE
from chomper.objc import ObjcRuntime

base_path = os.path.abspath(os.path.dirname(__file__))


def hook_access(uc, address, size, user_data):
    emu = user_data["emu"]
    emu.logger.info("access called")


def hook_stat(uc, address, size, user_data):
    emu = user_data["emu"]
    emu.logger.info("stat called")


def hook_stat_return(uc, address, size, user_data):
    emu = user_data["emu"]
    emu.logger.info("stat returned")


def hook_ui_device_current_device(uc, address, size, user_data):
    emu = user_data["emu"]
    emu.logger.info("+[UIDevice currentDevice] called")


def hook_ui_device_identifier_for_vendor(uc, address, size, user_data):
    emu = user_data["emu"]
    objc = ObjcRuntime(emu)
    return objc.msg_send("NSUUID", "UUID")


def on_mem_read(uc, access, address, size, value, user_data):
    emu = user_data["emu"]
    emu.logger.info(f"[READ] {hex(address)} ({size} bytes), value = {hex(value)}")


def on_mem_write(uc, access, address, size, value, user_data):
    emu = user_data["emu"]
    emu.logger.info(f"[WRITE] {hex(address)} ({size} bytes), value = {hex(value)}")


def main():
    emu = Chomper(
        arch=ARCH_ARM64,
        os_type=OS_IOS,
        rootfs_path=os.path.join(base_path, "../rootfs/ios"),
    )
    objc = ObjcRuntime(emu)

    ui_device_class = objc.find_class("UIDevice")

    # Hook function by symbol name
    emu.add_hook("_access", hook_access)

    # Hook function by address
    stat = emu.find_symbol("_stat")
    emu.add_hook(stat.address, hook_stat, return_callback=hook_stat_return)

    # Hook Objetive-C method
    emu.add_hook(
        ui_device_class.get_class_method("currentDevice").implementation,
        hook_ui_device_current_device,
    )

    # Hook Memory Read/Write
    # emu.add_mem_hook(HOOK_MEM_READ, on_mem_read)
    # emu.add_mem_hook(HOOK_MEM_WRITE, on_mem_write)

    # Hook and intercept
    emu.add_interceptor(
        ui_device_class.get_instance_method("identifierForVendor").implementation,
        hook_ui_device_identifier_for_vendor,
    )

    ui_device = objc.msg_send("UIDevice", "currentDevice")
    vendor_identifier = objc.msg_send(ui_device, "identifierForVendor")
    print(vendor_identifier)


if __name__ == '__main__':
    main()
