import os

from chomper import Chomper
from chomper.const import ARCH_ARM64, OS_IOS
from chomper.objc import ObjcRuntime

base_path = os.path.abspath(os.path.dirname(__file__))

rootfs_path = os.path.join(base_path, "../../rootfs/ios")
module_path = os.path.join(base_path, "../../examples/binaries/ios/com.zhihu.ios/osee2unifiedRelease")


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

    ns_url_request_class = objc.find_class("NSURLRequest")

    zh_ruid_helper_class = objc.find_class("ZHRUIDHelper")
    zh_white_box_encrypt_tool_class = objc.find_class("ZHWhiteBoxEncryptTool")

    with objc.autorelease_pool():
        # x-zse-96
        zse93 = objc.create_ns_string("101_2_1.0")
        path = objc.create_ns_string("/message-push/event")
        app_version = objc.create_ns_string("10.26.0")
        authorization = objc.create_ns_string("")
        udid = objc.create_ns_string("")
        body = objc.create_ns_string('{"report_time":1729768217954,"type":5}')
        signature_version = objc.create_ns_string("1.0")

        result = ns_url_request_class.call_method(
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

        emu.logger.info("x-zse-96: %s", result_str)

        # +[ZHRUIDHelper decryptWithJson:decryptKey:iv:]
        data = objc.create_ns_string("0mGSqs8Wu8UdhQQnQiPsmaW/+rjJ0F21dou7hNNHqjk=")
        key = objc.create_ns_string("19cc5914cb717bb5a4ecd4e2b61b7fbf3013464c6a214141873f40103c0cf1f11b4f5d81b8a527be83bed1d107851161dbc195b0053b263cd363e7adfa0ee030f6c2a211aa78f48d0e224e1d7177581fa4fdcda185d4bd1764243a1ccdb9a9806969193e136e32ad284065876351c510685c0c36600fb0ea5306b844c3a16710c18f7fae7eb4ba865bd57166185da1328f93a63b2747a7927928bb282c6350dcf8b59b587d744c75c71f15a0a308d5d8b37e8a2a")
        iv = objc.create_ns_string("18df3016faf4869c")

        result = zh_ruid_helper_class.call_method("decryptWithJson:decryptKey:iv:", data, key, iv)
        result_str = emu.read_string(objc.msg_send(result, "UTF8String"))

        emu.logger.info("+[ZHRUIDHelper decryptWithJson:decryptKey:iv:] result: %s", result_str)

        # +[ZHWhiteBoxEncryptTool encryptDataBase64String:]
        data = objc.create_ns_data(b"test")

        result = zh_white_box_encrypt_tool_class.call_method("encryptDataBase64String:", data)
        result_str = emu.read_string(objc.msg_send(result, "UTF8String"))

        emu.logger.info("+[ZHWhiteBoxEncryptTool encryptDataBase64String:] result: %s", result_str)


if __name__ == "__main__":
    main()
