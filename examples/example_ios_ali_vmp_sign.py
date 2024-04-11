import logging
import os
import uuid

from chomper.core import Chomper
from chomper.const import OS_IOS
from chomper.os.ios.options import IosOptions

base_path = os.path.abspath(os.path.dirname(__file__))

log_format = "%(asctime)s - %(name)s - %(levelname)s: %(message)s"
logging.basicConfig(
    format=log_format,
    level=logging.INFO,
)

logger = logging.getLogger(__name__)


def create_emulator():
    options = IosOptions(enable_objc=True, enable_ui_kit=True)
    emu = Chomper(
        os_type=OS_IOS,
        logger=logger,
        rootfs_path=os.path.join(base_path, "ios/rootfs"),
        os_options=options,
    )
    return emu


def objc_get_class(emu, class_name):
    return emu.call_symbol("_objc_getClass", emu.create_string(class_name))


def objc_sel_register_name(emu, sel_name):
    return emu.call_symbol("_sel_registerName", emu.create_string(sel_name))


def create_ns_string(emu, s):
    ns_string_class = objc_get_class(emu, "NSString")
    string_with_utf8_string_sel = objc_sel_register_name(emu, "stringWithUTF8String:")
    obj = emu.call_symbol(
        "_objc_msgSend",
        ns_string_class,
        string_with_utf8_string_sel,
        emu.create_string(s),
    )
    return obj


def read_ns_string(emu, obj):
    c_string_using_encoding_sel = objc_sel_register_name(emu, "cStringUsingEncoding:")
    ptr = emu.call_symbol("_objc_msgSend", obj, c_string_using_encoding_sel, 4)
    return emu.read_string(ptr)


def hook_pass(uc, address, size, user_data):
    pass


def hook_retval(retval):
    def decorator(uc, address, size, user_data):
        return retval

    return decorator


def hook_ns_bundle(emu):
    ns_mutable_dictionary_cls = objc_get_class(emu, "NSMutableDictionary")
    dictionary_with_object_for_key_sel = objc_sel_register_name(emu, "dictionaryWithObject:forKey:")
    add_object_for_key_sel = objc_sel_register_name(emu, "addObject:forKey:")

    bundle_identifier = create_ns_string(emu, "com.ceair.b2m")
    executable_path = create_ns_string(emu, f"/var/containers/Bundle/Application"
                                            f"/{uuid.uuid4()}/com.ceair.b2m/ceair_iOS_branch")

    bundle_info_directory = emu.call_symbol(
        "_objc_msgSend",
        ns_mutable_dictionary_cls,
        dictionary_with_object_for_key_sel,
        create_ns_string(emu, "9.4.7"),
        create_ns_string(emu, "CFBundleShortVersionString"),
    )

    emu.call_symbol(
        "_objc_msgSend",
        bundle_info_directory,
        add_object_for_key_sel,
        executable_path,
        create_ns_string(emu, "CFBundleExecutable"),
    )

    emu.add_interceptor("-[NSBundle initWithPath:]", hook_pass)
    emu.add_interceptor("-[NSBundle bundleIdentifier]", hook_retval(bundle_identifier))
    emu.add_interceptor("-[NSBundle executablePath]", hook_retval(executable_path))
    emu.add_interceptor("-[NSBundle infoDictionary]", hook_retval(bundle_info_directory))


def hook_ns_locale(emu):
    ns_array_cls = objc_get_class(emu, "NSArray")
    array_with_object_sel = objc_sel_register_name(emu, "arrayWithObject:")

    preferred_languages = emu.call_symbol(
        "_objc_msgSend",
        ns_array_cls,
        array_with_object_sel,
        create_ns_string(emu, "zh-cn"),
    )

    emu.add_interceptor("+[NSLocale preferredLanguages]", hook_retval(preferred_languages))


def hook_ui_device(emu):
    system_version = create_ns_string(emu, "14.4.0")
    device_name = create_ns_string(emu, "iPhone")
    device_model = create_ns_string(emu, "iPhone13,1")

    emu.add_interceptor("-[UIDevice systemVersion]", hook_retval(system_version))
    emu.add_interceptor("-[UIDevice name]", hook_retval(device_name))
    emu.add_interceptor("-[UIDevice model]", hook_retval(device_model))


def main():
    emu = create_emulator()

    hook_ns_bundle(emu)
    hook_ns_locale(emu)
    hook_ui_device(emu)

    emu.add_interceptor("_fopen", hook_retval(0))

    emu.load_module(os.path.join(base_path, "ios/apps/com.csair.MBP/CSMBP-AppStore-Package"))

    ali_tiger_tally_class = objc_get_class(emu, "AliTigerTally")

    shared_instance_sel = objc_sel_register_name(emu, "sharedInstance")
    initialize_sel = objc_sel_register_name(emu, "initialize:")
    vmp_sign_sel = objc_sel_register_name(emu, "vmpSign:")
    data_using_encoding_sel = objc_sel_register_name(emu, "dataUsingEncoding:")

    ali_tiger_tally_instance = emu.call_symbol("_objc_msgSend", ali_tiger_tally_class, shared_instance_sel)

    app_key = create_ns_string(emu, "xPEj7uv0KuziQnXUyPIBNUjnDvvHuW09VOYFuLYBcY-jV6fgqmfy5B1y75_iSuRM5U2zNq7MRoR9N1F-UthTEgv-QBWk68gr95BrAySzWuDzt08FrkeBZWQCGyZ0iAybalYLOJEF7nkKBtmDGLewcw==",)
    emu.call_symbol("_objc_msgSend", ali_tiger_tally_instance, initialize_sel, app_key)

    encrypt_str = create_ns_string(emu, '{"biClassId":["2","3","4"]}')
    encrypt_bytes = emu.call_symbol("_objc_msgSend", encrypt_str, data_using_encoding_sel, 1)

    vmp_sign = emu.call_symbol("_objc_msgSend", ali_tiger_tally_instance, vmp_sign_sel, encrypt_bytes)

    logger.info("vmp sign: %s", read_ns_string(emu, vmp_sign))


if __name__ == "__main__":
    main()
