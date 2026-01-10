import os

from chomper import Chomper
from chomper.const import ARCH_ARM64, OS_IOS
from chomper.objc import ObjcRuntime

base_path = os.path.abspath(os.path.dirname(__file__))

rootfs_path = os.path.join(base_path, "../../rootfs/ios")
module_path = os.path.join(base_path, "../../examples/binaries/ios/com.xingin.discover/8.74/discover")


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

    ti_options_class = objc.find_class("TIOptions")
    ti_tiny_class = objc.find_class("TITiny")

    with objc.autorelease_pool():
        # Initialize
        options = ti_options_class.call_method("sharedInstance")
        options.call_method("setAppID:", objc.create_ns_string("ECFAAF02"))

        ti_tiny_class.call_method("initializeWithOptions:", options)

        # Sign
        method = objc.create_ns_string("GET")
        url = objc.create_ns_string("https://edith.xiaohongshu.com/api/sns/v1/system_service/config")
        payload = 0

        result = ti_tiny_class.call_method("signWithMethod:url:payload:", method, url, payload)
        result_str = emu.read_string(result.call_method("description").call_method("UTF8String"))

        emu.logger.info("Sign result: %s", result_str)


if __name__ == "__main__":
    main()
