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
    binary_path = "examples/binaries/ios/com.zhihu.ios/osee2unifiedRelease"

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

    emu.load_module(module_file=os.path.join(base_path, "..", binary_path))

    with objc.autorelease_pool():
        # x-zse-96
        zse93 = pyobj2nsobj(emu, "101_2_1.0")
        path = pyobj2nsobj(emu, "/message-push/event")
        app_version = pyobj2nsobj(emu, "10.26.0")
        authorization = pyobj2nsobj(emu, "")
        udid = pyobj2nsobj(emu, "")
        body = pyobj2nsobj(emu, '{"report_time":1729768217954,"type":5}')
        signature_version = pyobj2nsobj(emu, "1.0")

        result = objc.msg_send(
            "NSURLRequest",
            "encryptWithZse83:path:APPVersion:authorization:UDID:body:signatureVersion:",
            zse93,
            path,
            app_version,
            authorization,
            udid,
            body,
            signature_version
        )
        result_str = emu.read_string(objc.msg_send(result, "cStringUsingEncoding:", 4))

        logger.info("x-zse-96: %s", result_str)

        # ZHRUIDHelper decrypt
        data = pyobj2nsobj(emu, "0mGSqs8Wu8UdhQQnQiPsmaW/+rjJ0F21dou7hNNHqjk=")
        key = pyobj2nsobj(emu, "19cc5914cb717bb5a4ecd4e2b61b7fbf3013464c6a214141873f40103c0cf1f11b4f5d81b8a527be83bed1d107851161dbc195b0053b263cd363e7adfa0ee030f6c2a211aa78f48d0e224e1d7177581fa4fdcda185d4bd1764243a1ccdb9a9806969193e136e32ad284065876351c510685c0c36600fb0ea5306b844c3a16710c18f7fae7eb4ba865bd57166185da1328f93a63b2747a7927928bb282c6350dcf8b59b587d744c75c71f15a0a308d5d8b37e8a2a")
        iv = pyobj2nsobj(emu, "18df3016faf4869c")

        objc.msg_send("ZHLog", "setLogLevel:", 0)

        result = objc.msg_send("ZHRUIDHelper", "decryptWithJson:decryptKey:iv:", data, key, iv)
        result_str = emu.read_string(objc.msg_send(result, "cStringUsingEncoding:", 4))

        logger.info("ZHRUIDHelper decrypt result: %s", result_str)

        # ZHWhiteBoxEncryptTool encrypt
        data = pyobj2nsobj(emu, b"test")
        result = objc.msg_send("ZHWhiteBoxEncryptTool", "encryptDataBase64String:", data)
        result_str = emu.read_string(objc.msg_send(result, "cStringUsingEncoding:", 4))

        logger.info("ZHWhiteBoxEncryptTool encrypt result: %s", result_str)


if __name__ == "__main__":
    main()
