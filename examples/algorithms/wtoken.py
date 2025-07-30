import logging
import os

from chomper import Chomper
from chomper.const import ARCH_ARM64, OS_IOS
from chomper.objc import ObjcRuntime

from utils import get_base_path, download_sample_file

log_format = "%(levelname)s: %(message)s"
logging.basicConfig(
    format=log_format,
    level=logging.INFO,
)

logger = logging.getLogger()


def main():
    base_path = get_base_path()
    binary_path = "examples/binaries/ios/com.csair.MBP/CSMBP-AppStore-Package"

    # Download sample file
    download_sample_file(binary_path)

    emu = Chomper(
        arch=ARCH_ARM64,
        os_type=OS_IOS,
        rootfs_path=os.path.join(base_path, "../../rootfs/ios"),
        enable_ui_kit=True,
    )
    objc = ObjcRuntime(emu)

    emu.load_module(os.path.join(base_path, "../..", binary_path))

    ali_tiger_tally_class = objc.find_class("AliTigerTally")

    with objc.autorelease_pool():
        # Initialize
        ali_tiger_tally_instance = ali_tiger_tally_class.call_method("sharedInstance")

        app_key = objc.create_ns_string("xPEj7uv0KuziQnXUyPIBNUjnDvvHuW09VOYFuLYBcY-jV6fgqmfy5B1y75_iSuRM5U2zNq7MRoR9N1F-UthTEgv-QBWk68gr95BrAySzWuDzt08FrkeBZWQCGyZ0iAybalYLOJEF7nkKBtmDGLewcw==")
        objc.msg_send(ali_tiger_tally_instance, "initialize:", app_key)

        # Get wtoken
        data = objc.create_ns_data(b'{"biClassId":["2","3","4"]}')

        wtoken = objc.msg_send(ali_tiger_tally_instance, "vmpSign:", data)
        wtoken_str = emu.read_string(objc.msg_send(wtoken, "UTF8String"))

        logger.info("wtoken: %s", wtoken_str)


if __name__ == "__main__":
    main()
