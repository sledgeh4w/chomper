import os

from chomper import Chomper
from chomper.const import ARCH_ARM64, OS_IOS
from chomper.objc import ObjcRuntime

base_path = os.path.abspath(os.path.dirname(__file__))

rootfs_path = os.path.join(base_path, "../../rootfs/ios")
module_path = os.path.join(base_path, "../../examples/binaries/ios/com.beeasy.shopee.sg/ShopeeSG")


def hook_dispatch_group_wait(uc, address, size, user_data):
    pass


def hook_shp_sec_mini_sdk_manager_get_mmp_id(uc, address, size, user_data):
    return 0


def main():
    if not os.path.exists(module_path):
        print(
            "Binary doesn't exist, please download "
            "from 'https://sourceforge.net/projects/chomper-emu/files/'"
        )
        return

    emu = Chomper(
        arch=ARCH_ARM64,
        os_type=OS_IOS,
        rootfs_path=rootfs_path,
    )
    objc = ObjcRuntime(emu)

    emu.load_module(module_path)

    shp_sec_mini_sdk_manager_class = objc.find_class("SHPSECminiSDKManager")
    shopee_security_sdk_manager_class = objc.find_class("ShopeeSecuritySDKManager")

    # Some async functions are not fully supported
    emu.add_interceptor("_dispatch_group_wait", hook_dispatch_group_wait)

    emu.add_interceptor(
        shp_sec_mini_sdk_manager_class.get_instance_method("getMMPId").implementation,
        hook_shp_sec_mini_sdk_manager_get_mmp_id,
    )

    with objc.autorelease_pool():
        # Sign
        path = objc.create_ns_string("https://mall.shopee.sg/api/v4/pages/get_category_tree")
        data = 0

        result = shopee_security_sdk_manager_class.call_method("genSignWithURL:data:", path, data)
        result_str = emu.read_string(result.call_method("description").call_method("UTF8String"))

        emu.logger.info("Sign result: %s", result_str)


if __name__ == "__main__":
    main()
