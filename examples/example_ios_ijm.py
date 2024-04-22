import logging
import os

from chomper import Chomper
from chomper.const import ARCH_ARM64, OS_IOS

base_path = os.path.abspath(os.path.dirname(__file__))

log_format = "%(asctime)s - %(name)s - %(levelname)s: %(message)s"
logging.basicConfig(
    format=log_format,
    level=logging.INFO,
)

logger = logging.getLogger(__name__)


def create_emulator():
    return Chomper(
        arch=ARCH_ARM64,
        os_type=OS_IOS,
        logger=logger,
        rootfs_path=os.path.join(base_path, "ios/rootfs"),
        enable_objc=True,
        enable_ui_kit=True,
    )


def objc_get_class(emu, class_name):
    return emu.call_symbol("_objc_getClass", emu.create_string(class_name))


def objc_sel_register_name(emu, sel_name):
    return emu.call_symbol("_sel_registerName", emu.create_string(sel_name))


def objc_create_ns_string(emu, s):
    ns_string_class = objc_get_class(emu, "NSString")
    string_with_utf8_string_sel = objc_sel_register_name(emu, "stringWithUTF8String:")
    obj = emu.call_symbol(
        "_objc_msgSend",
        ns_string_class,
        string_with_utf8_string_sel,
        emu.create_string(s),
    )
    return obj


def objc_read_ns_string(emu, obj):
    c_string_using_encoding_sel = objc_sel_register_name(emu, "cStringUsingEncoding:")
    ptr = emu.call_symbol("_objc_msgSend", obj, c_string_using_encoding_sel, 4)
    return emu.read_string(ptr)


def hook_retval(retval):
    def decorator(emu, *args):
        return retval

    return decorator


def main():
    emu = create_emulator()

    czair = emu.load_module(
        module_file=os.path.join(base_path, "ios/apps/com.csair.MBP/CSMBP-AppStore-Package"),
        exec_init_array=True,
    )

    # pass ijm special check
    emu.add_interceptor(czair.base + 0x1038F0004, hook_retval(1))

    jm_box_125_class = objc_get_class(emu, "JMBox125")

    jm_box_167_jm_box_501_sel = objc_sel_register_name(emu, "JMBox167:JMBox501:")
    jm_box_153_jm_box_501_sel = objc_sel_register_name(emu, "JMBox153:JMBox501:")

    encrypt_data = '{"biClassId":["2","3","4"]}'
    encrypt_input = objc_create_ns_string(emu, encrypt_data)

    encrypt_result = emu.call_symbol("_objc_msgSend", jm_box_125_class, jm_box_167_jm_box_501_sel, encrypt_input, 1)

    logger.info("encrypt_result: %s", objc_read_ns_string(emu, encrypt_result))

    decrypt_data = "XKQYFMCP9Eb0IUzrQ9KaRRvTeFcYYyLcInrS/IWp6be1+VZa14GanCrzeb3DR45HW+XH0xiZLA5WUjUcXnlpM+CC6EtauUDUxCLap3QPWRyewLUosCB/ESHE7341DQca6lx5KFcP0XCkBpGlEKpACR5v7TwNBxc62auNBDvmEY422LTAUEEBrC8FDE+Y4DS2IJTLN6h9f7hdmQ4zUnY4cwyZXwgdIoH+bVuNy6TSw1JjQaFF/fLLHVZOQovrMcjtTpMZGr8xOSoW/+msiZzKwET3"
    decrypt_input = objc_create_ns_string(emu, decrypt_data)

    decrypt_result = emu.call_symbol("_objc_msgSend", jm_box_125_class, jm_box_153_jm_box_501_sel, decrypt_input, 1)

    logger.info("decrypt_result: %s", objc_read_ns_string(emu, decrypt_result))


if __name__ == "__main__":
    main()
