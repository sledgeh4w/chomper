import logging
import os

from chomper import Chomper
from chomper.const import ARCH_ARM64, OS_IOS
from chomper.objc import ObjC
from chomper.utils import pyobj2nsobj

base_path = os.path.abspath(os.path.dirname(__file__))

log_format = "%(asctime)s - %(name)s - %(levelname)s: %(message)s"
logging.basicConfig(
    format=log_format,
    level=logging.INFO,
)

logger = logging.getLogger(__name__)


def hook_retval(retval):
    def decorator(emu, *args):
        return retval

    return decorator


def main():
    emu = Chomper(
        arch=ARCH_ARM64,
        os_type=OS_IOS,
        logger=logger,
        rootfs_path=os.path.join(base_path, "ios/rootfs"),
    )

    objc = ObjC(emu)

    czair = emu.load_module(
        module_file=os.path.join(base_path, "ios/apps/com.csair.MBP/CSMBP-AppStore-Package"),
        exec_init_array=True,
    )

    # Skip a special check of ijm
    emu.add_interceptor(czair.base + 0x1038F0004, hook_retval(1))

    with objc.autorelease_pool():
        # Encrypt
        encrypt_str = '{"biClassId":["2","3","4"]}'
        encrypt_result = objc.msg_send("JMBox125", "JMBox167:JMBox501:", pyobj2nsobj(emu, encrypt_str), 1)

        logger.info("Encrypt result: %s", emu.read_string(objc.msg_send(encrypt_result, "cStringUsingEncoding:", 4)))

        # Decrypt
        decrypt_str = "XKQYFMCP9Eb0IUzrQ9KaRRvTeFcYYyLcInrS/IWp6be1+VZa14GanCrzeb3DR45HW+XH0xiZLA5WUjUcXnlpM+CC6EtauUDUxCLap3QPWRyewLUosCB/ESHE7341DQca6lx5KFcP0XCkBpGlEKpACR5v7TwNBxc62auNBDvmEY422LTAUEEBrC8FDE+Y4DS2IJTLN6h9f7hdmQ4zUnY4cwyZXwgdIoH+bVuNy6TSw1JjQaFF/fLLHVZOQovrMcjtTpMZGr8xOSoW/+msiZzKwET3"
        decrypt_result = objc.msg_send("JMBox125", "JMBox153:JMBox501:", pyobj2nsobj(emu, decrypt_str), 1)

        logger.info("Decrypt result: %s", emu.read_string(objc.msg_send(decrypt_result, "cStringUsingEncoding:", 4)))


if __name__ == "__main__":
    main()
