import logging
import os
import urllib.request
from pathlib import Path

from chomper import Chomper
from chomper.const import ARCH_ARM64, OS_IOS
from chomper.objc import ObjC, pyobj2nsobj

base_path = os.path.abspath(os.path.dirname(__file__))

log_format = "%(asctime)s - %(name)s - %(levelname)s: %(message)s"
logging.basicConfig(
    format=log_format,
    level=logging.INFO,
)

logger = logging.getLogger()


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
    binary_path = "examples/binaries/ios/com.ceair.b2m/ceair_iOS_branch"

    # Download sample file
    download_sample_file(binary_path)
    download_sample_file(f"{binary_path}/../Info.plist")

    emu = Chomper(
        arch=ARCH_ARM64,
        os_type=OS_IOS,
        rootfs_path=os.path.join(base_path, "../rootfs/ios"),
        enable_ui_kit=True,
    )
    objc = ObjC(emu)

    emu.load_module(os.path.join(base_path, "..", binary_path))

    with objc.autorelease_pool():
        # Encrypt
        encrypt_input = pyobj2nsobj(emu, 'S{"osVersion":"14.2.1","os":"iOS","deviceModel":"iPhone","channelNo":"APPSTORE"}')

        encrypt_result = objc.msg_send("BangSafeSDK", "checkcode:dataStyle:", encrypt_input, 2)
        encrypt_result_str = emu.read_string(objc.msg_send(encrypt_result, "cStringUsingEncoding:", 4))

        logger.info("Encrypt result: %s", encrypt_result_str)

        # Decrypt
        decrypt_input = pyobj2nsobj(emu, "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")

        decrypt_result = objc.msg_send("BangSafeSDK", "decheckcode:", decrypt_input)
        decrypt_result_str = emu.read_string(objc.msg_send(decrypt_result, "cStringUsingEncoding:", 4))

        logger.info("Decrypt result: %s", decrypt_result_str)


if __name__ == "__main__":
    main()
