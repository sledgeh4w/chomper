import os

from chomper import Chomper
from chomper.const import ARCH_ARM64, OS_IOS
from chomper.objc import ObjcRuntime

base_path = os.path.abspath(os.path.dirname(__file__))

rootfs_path = os.path.join(base_path, "../../rootfs/ios")
module_path = os.path.join(base_path, "../../examples/binaries/ios/com.csair.MBP/CSMBP-AppStore-Package")


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

    ali_tiger_tally_class = objc.find_class("AliTigerTally")

    with objc.autorelease_pool():
        # Initialize
        ali_tiger_tally_instance = ali_tiger_tally_class.call_method("sharedInstance")

        app_key = objc.create_ns_string("xPEj7uv0KuziQnXUyPIBNUjnDvvHuW09VOYFuLYBcY-jV6fgqmfy5B1y75_iSuRM5U2zNq7MRoR9N1F-UthTEgv-QBWk68gr95BrAySzWuDzt08FrkeBZWQCGyZ0iAybalYLOJEF7nkKBtmDGLewcw==")
        objc.msg_send(ali_tiger_tally_instance, "initialize:", app_key)

        # Sign
        data = objc.create_ns_data(b'{"biClassId":["2","3","4"]}')

        result = objc.msg_send(ali_tiger_tally_instance, "vmpSign:", data)
        result_str = emu.read_string(objc.msg_send(result, "UTF8String"))

        emu.logger.info("Result: %s", result_str)


if __name__ == "__main__":
    main()
