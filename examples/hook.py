import os

from chomper import Chomper
from chomper.const import ARCH_ARM64, OS_IOS, HOOK_MEM_READ, HOOK_MEM_WRITE
from chomper.objc import ObjcRuntime

base_path = os.path.abspath(os.path.dirname(__file__))
rootfs_path = os.path.join(base_path, "../rootfs/ios")


def hook_stat(uc, address, size, user_data):
    emu = user_data["emu"]
    emu.logger.info(f"[HOOK] stat called: {emu.read_string(emu.get_arg(0))}")


def hook_access(uc, address, size, user_data):
    emu = user_data["emu"]
    emu.logger.info(f"[HOOK] access called: {emu.read_string(emu.get_arg(0))}")


def hook_access_return(uc, address, size, user_data):
    emu = user_data["emu"]
    emu.logger.info(f"[HOOK] access returned: {emu.get_retval()}")


def hook_ui_device_current_device(uc, address, size, user_data):
    emu = user_data["emu"]
    emu.logger.info("[HOOK] +[UIDevice currentDevice] called")


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
        rootfs_path=rootfs_path,
    )
    objc = ObjcRuntime(emu)

    ui_device_class = objc.find_class("UIDevice")

    # Hook function by symbol name
    emu.add_hook("_stat", hook_stat)

    # Hook function by address
    access = emu.find_symbol("_access")
    emu.add_hook(access.address, hook_access, return_callback=hook_access_return)

    # Hook Objetive-C method
    emu.add_hook(
        ui_device_class.get_class_method("currentDevice").implementation,
        hook_ui_device_current_device,
    )

    # Hook and intercept
    emu.add_interceptor(
        ui_device_class.get_instance_method("identifierForVendor").implementation,
        hook_ui_device_identifier_for_vendor,
    )

    # Hook memory read/write
    emu.add_mem_hook(HOOK_MEM_READ, on_mem_read)
    emu.add_mem_hook(HOOK_MEM_WRITE, on_mem_write)


if __name__ == '__main__':
    main()
