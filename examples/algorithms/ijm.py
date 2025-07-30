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


def hook_retval(retval):
    def decorator(emu, *args):
        return retval

    return decorator


def main():
    base_path = get_base_path()
    binary_path = "examples/binaries/ios/com.csair.MBP/CSMBP-AppStore-Package"

    # Download sample file
    download_sample_file(binary_path)

    emu = Chomper(
        arch=ARCH_ARM64,
        os_type=OS_IOS,
        rootfs_path=os.path.join(base_path, "../../rootfs/ios"),
    )
    objc = ObjcRuntime(emu)

    czair = emu.load_module(
        module_file=os.path.join(base_path, "../..", binary_path),
        exec_init_array=True,
    )

    # Pass a check
    emu.add_interceptor(czair.base + 0x38F0004, hook_retval(1))

    jm_box_125_class = objc.find_class("JMBox125")

    with objc.autorelease_pool():
        # Encrypt
        encrypt_input = objc.create_ns_string('{"biClassId":["2","3","4"]}')

        encrypt_result = jm_box_125_class.call_method("JMBox167:JMBox501:", encrypt_input, 1)
        encrypt_result_str = emu.read_string(objc.msg_send(encrypt_result, "UTF8String"))

        logger.info("Encrypt result: %s", encrypt_result_str)

        # Decrypt
        decrypt_input = objc.create_ns_string("XKQYFMCP9Eb0IUzrQ9KaRRvTeFcYYyLcInrS/IWp6be1+VZa14GanCrzeb3DR45HW+XH0xiZLA5WUjUcXnlpM+CC6EtauUDUxCLap3QPWRyewLUosCB/ESHE7341DQca6lx5KFcP0XCkBpGlEKpACR5v7TwNBxc62auNBDvmEY422LTAUEEBrC8FDE+Y4DS2IJTLN6h9f7hdmQ4zUnY4cwyZXwgdIoH+bVuNy6TSw1JjQaFF/fLLHVZOQovrMcjtTpMZGr8xOSoW/+msiZzKwET3")

        decrypt_result = jm_box_125_class.call_method("JMBox153:JMBox501:", decrypt_input, 1)
        decrypt_result_str = emu.read_string(objc.msg_send(decrypt_result, "UTF8String"))

        logger.info("Decrypt result: %s", decrypt_result_str)


if __name__ == "__main__":
    main()
