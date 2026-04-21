import os

from chomper import Chomper
from chomper.const import ARCH_ARM64, OS_IOS
from chomper.objc import ObjcRuntime

base_path = os.path.abspath(os.path.dirname(__file__))

rootfs_path = os.path.join(base_path, "../../rootfs/ios")
module_path = os.path.join(base_path, "../../examples/binaries/ios/com.taobao.taobao4iphone/Taobao4iPhone")


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

    security_image = "yw_1222.jpg"

    # Forward security image accesses
    emu.os.forward_path(
        f"{os.path.dirname(emu.os.executable_path)}/{security_image}",
        os.path.join(module_path, "..", security_image),
    )

    tb_sdk_security_class = objc.find_class("TBSDKSecurity")

    with objc.autorelease_pool():
        # Initialize
        tb_sdk_security = tb_sdk_security_class.call_method("instance")

        # Sign
        app_key = objc.create_ns_string("21380790")
        input_payload = objc.create_ns_string("&")
        extend_paras = objc.create_ns_dictionary({})
        api = objc.create_ns_string("mtop.taobao.miniapp.top.get")
        request_id = objc.create_ns_string("")

        result = tb_sdk_security.call_method(
            "factorSign:input:extendParas:isUseWua:api:requestId:",
            app_key,
            input_payload,
            extend_paras,
            0,
            api,
            request_id,
        )
        result_str = emu.read_string(result.call_method("description").call_method("UTF8String"))

        emu.logger.info("Sign result: %s", result_str)


if __name__ == "__main__":
    main()
