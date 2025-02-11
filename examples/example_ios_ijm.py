import logging
import os
import urllib.request
from pathlib import Path

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

logger = logging.getLogger()


def hook_retval(retval):
    def decorator(emu, *args):
        return retval

    return decorator


def download_sample_file(binary_path: str) -> str:
    filepath = os.path.join(base_path, "..", binary_path)

    path = Path(filepath).resolve()
    if path.exists():
        return filepath

    if not path.parent.exists():
        path.parent.mkdir(parents=True)

    url = "https://sourceforge.net/projects/chomper-emu/files/%s/download" % binary_path

    print(f"Downloading sample file: {url}")
    urllib.request.urlretrieve(url, path)
    return filepath


def main():
    binary_path = "examples/binaries/ios/com.csair.MBP/CSMBP-AppStore-Package"

    # Download sample file from SourceForge
    download_sample_file(binary_path)
    download_sample_file(f"{binary_path}/../Info.plist")

    emu = Chomper(
        arch=ARCH_ARM64,
        os_type=OS_IOS,
        rootfs_path=os.path.join(base_path, "../rootfs/ios"),
    )
    objc = ObjC(emu)

    czair = emu.load_module(
        module_file=os.path.join(base_path, "..", binary_path),
        exec_init_array=True,
    )

    # Skip a special check of ijm
    emu.add_interceptor(czair.base + 0x1038F0004, hook_retval(1))

    with objc.autorelease_pool():
        # Encrypt
        encrypt_input = pyobj2nsobj(emu, '{"biClassId":["2","3","4"]}')
        encrypt_result = objc.msg_send("JMBox125", "JMBox167:JMBox501:", encrypt_input, 1)
        encrypt_result_str = emu.read_string(objc.msg_send(encrypt_result, "cStringUsingEncoding:", 4))

        logger.info("Encrypt result: %s", encrypt_result_str)

        # Decrypt
        decrypt_input = pyobj2nsobj(emu, "XKQYFMCP9Eb0IUzrQ9KaRRvTeFcYYyLcInrS/IWp6be1+VZa14GanCrzeb3DR45HW+XH0xiZLA5WUjUcXnlpM+CC6EtauUDUxCLap3QPWRyewLUosCB/ESHE7341DQca6lx5KFcP0XCkBpGlEKpACR5v7TwNBxc62auNBDvmEY422LTAUEEBrC8FDE+Y4DS2IJTLN6h9f7hdmQ4zUnY4cwyZXwgdIoH+bVuNy6TSw1JjQaFF/fLLHVZOQovrMcjtTpMZGr8xOSoW/+msiZzKwET3")
        decrypt_result = objc.msg_send("JMBox125", "JMBox153:JMBox501:", decrypt_input, 1)
        decrypt_result_str = emu.read_string(objc.msg_send(decrypt_result, "cStringUsingEncoding:", 4))

        logger.info("Decrypt result: %s", decrypt_result_str)


if __name__ == "__main__":
    main()
