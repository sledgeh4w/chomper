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
        enable_ui_kit=True,
    )
    objc = ObjC(emu)

    emu.load_module(os.path.join(base_path, "..", binary_path))

    with objc.autorelease_pool():
        # Initialize
        ali_tiger_tally_instance = objc.msg_send("AliTigerTally", "sharedInstance")

        app_key = pyobj2nsobj(emu, "xPEj7uv0KuziQnXUyPIBNUjnDvvHuW09VOYFuLYBcY-jV6fgqmfy5B1y75_iSuRM5U2zNq7MRoR9N1F-UthTEgv-QBWk68gr95BrAySzWuDzt08FrkeBZWQCGyZ0iAybalYLOJEF7nkKBtmDGLewcw==")
        objc.msg_send(ali_tiger_tally_instance, "initialize:", app_key)

        # vmpSign
        data = pyobj2nsobj(emu, b'{"biClassId":["2","3","4"]}')
        vmp_sign = objc.msg_send(ali_tiger_tally_instance, "vmpSign:", data)
        vmp_sign_str = emu.read_string(objc.msg_send(vmp_sign, "cStringUsingEncoding:", 4))

        logger.info("AliTigerTally vmpSign: %s", vmp_sign_str)


if __name__ == "__main__":
    main()
