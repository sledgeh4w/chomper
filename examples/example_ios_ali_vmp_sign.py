import logging
import os
import uuid

from chomper import Chomper
from chomper.const import ARCH_ARM64, OS_IOS
from chomper.objc import ObjC

base_path = os.path.abspath(os.path.dirname(__file__))

log_format = "%(asctime)s - %(name)s - %(levelname)s: %(message)s"
logging.basicConfig(
    format=log_format,
    level=logging.INFO,
)

logger = logging.getLogger(__name__)


def hook_skip(uc, address, size, user_data):
    pass


def hook_retval(retval):
    def decorator(uc, address, size, user_data):
        return retval

    return decorator


def hook_ns_bundle(emu, objc):
    bundle_identifier = objc.msg_send("NSString", "stringWithUTF8String:", "com.ceair.b2m")

    executable_path = objc.msg_send(
        "NSString",
        "stringWithUTF8String:",
        f"/var/containers/Bundle/Application/{uuid.uuid4()}/com.ceair.b2m/ceair_iOS_branch",
    )

    bundle_info_directory = objc.msg_send(
        "NSMutableDictionary",
        "dictionaryWithObject:forKey:",
        objc.msg_send("NSString", "stringWithUTF8String:", "9.4.7"),
        objc.msg_send("NSString", "stringWithUTF8String:", "CFBundleShortVersionString"),
    )

    objc.msg_send(
        bundle_info_directory,
        "addObject:forKey:",
        executable_path,
        objc.msg_send("NSString", "stringWithUTF8String:", "CFBundleExecutable"),
    )

    emu.add_interceptor("-[NSBundle initWithPath:]", hook_skip)
    emu.add_interceptor("-[NSBundle bundleIdentifier]", hook_retval(bundle_identifier))
    emu.add_interceptor("-[NSBundle executablePath]", hook_retval(executable_path))
    emu.add_interceptor("-[NSBundle infoDictionary]", hook_retval(bundle_info_directory))


def hook_ns_locale(emu, objc):
    preferred_languages = objc.msg_send(
        "NSArray",
        "arrayWithObject:",
        objc.msg_send("NSString", "stringWithUTF8String:", "zh-cn")
    )

    emu.add_interceptor("+[NSLocale preferredLanguages]", hook_retval(preferred_languages))


def hook_ui_device(emu, objc):
    system_version = objc.msg_send("NSString", "stringWithUTF8String:", "14.4.0")
    device_name = objc.msg_send("NSString", "stringWithUTF8String:", "iPhone")
    device_model = objc.msg_send("NSString", "stringWithUTF8String:", "iPhone13,1")

    emu.add_interceptor("-[UIDevice systemVersion]", hook_retval(system_version))
    emu.add_interceptor("-[UIDevice name]", hook_retval(device_name))
    emu.add_interceptor("-[UIDevice model]", hook_retval(device_model))


def main():
    emu = Chomper(
        arch=ARCH_ARM64,
        os_type=OS_IOS,
        logger=logger,
        rootfs_path=os.path.join(base_path, "ios/rootfs"),
        enable_ui_kit=True,
    )

    objc = ObjC(emu)

    hook_ns_bundle(emu, objc)
    hook_ns_locale(emu, objc)
    hook_ui_device(emu, objc)

    # Skip a file operation
    emu.add_interceptor("_fopen", hook_retval(0))

    emu.load_module(os.path.join(base_path, "ios/apps/com.csair.MBP/CSMBP-AppStore-Package"))

    ali_tiger_tally_instance = objc.msg_send("AliTigerTally", "sharedInstance")

    app_key = objc.msg_send(
        "NSString",
        "stringWithUTF8String:",
        "xPEj7uv0KuziQnXUyPIBNUjnDvvHuW09VOYFuLYBcY-jV6fgqmfy5B1y75_iSuRM5U2zNq7MRoR9N1F-UthTEgv-QBWk68gr95BrAySzWuDzt08FrkeBZWQCGyZ0iAybalYLOJEF7nkKBtmDGLewcw==",
    )

    objc.msg_send(ali_tiger_tally_instance, "initialize:", app_key)

    encrypt_str = objc.msg_send("NSString", "stringWithUTF8String:", '{"biClassId":["2","3","4"]}')
    encrypt_bytes = objc.msg_send(encrypt_str, "dataUsingEncoding:", 1)

    vmp_sign = objc.msg_send(ali_tiger_tally_instance, "vmpSign:", encrypt_bytes)
    logger.info("vmp sign: %s", emu.read_string(objc.msg_send(vmp_sign, "cStringUsingEncoding:", 4)))


if __name__ == "__main__":
    main()
