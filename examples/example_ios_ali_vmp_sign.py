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

logger = logging.getLogger(__name__)


def download_file(url: str, filepath: str):
    path = Path(filepath).resolve()
    if path.exists():
        return
    if not path.parent.exists():
        path.parent.mkdir(parents=True)
    print(f"Downloading file: {url}")
    urllib.request.urlretrieve(url, path)


def main():
    binary_path = "binaries/ios/com.csair.MBP/CSMBP-AppStore-Package"

    # Download example binary file from the Internet
    download_file(
        url=f"https://sourceforge.net/projects/chomper-emu/files/examples/{binary_path}/download",
        filepath=os.path.join(base_path, binary_path),
    )
    download_file(
        url=f"https://sourceforge.net/projects/chomper-emu/files/examples/{binary_path}/../Info.plist/download",
        filepath=os.path.join(base_path, binary_path, "../Info.plist"),
    )

    emu = Chomper(
        arch=ARCH_ARM64,
        os_type=OS_IOS,
        rootfs_path=os.path.join(base_path, "rootfs/ios"),
        enable_ui_kit=True,
    )
    objc = ObjC(emu)

    emu.load_module(os.path.join(base_path, binary_path))

    ali_tiger_tally_instance = objc.msg_send("AliTigerTally", "sharedInstance")

    app_key = "xPEj7uv0KuziQnXUyPIBNUjnDvvHuW09VOYFuLYBcY-jV6fgqmfy5B1y75_iSuRM5U2zNq7MRoR9N1F-UthTEgv-QBWk68gr95BrAySzWuDzt08FrkeBZWQCGyZ0iAybalYLOJEF7nkKBtmDGLewcw=="
    objc.msg_send(ali_tiger_tally_instance, "initialize:", pyobj2nsobj(emu, app_key))

    with objc.autorelease_pool():
        encrypt_str = '{"biClassId":["2","3","4"]}'
        encrypt_bytes = objc.msg_send(pyobj2nsobj(emu, encrypt_str), "dataUsingEncoding:", 1)

        vmp_sign = objc.msg_send(ali_tiger_tally_instance, "vmpSign:", encrypt_bytes)
        logger.info("vmpSign: %s", emu.read_string(objc.msg_send(vmp_sign, "cStringUsingEncoding:", 4)))


if __name__ == "__main__":
    main()
