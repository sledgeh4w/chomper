import os

from chomper import Chomper
from chomper.const import ARCH_ARM64, OS_IOS
from chomper.objc import ObjcRuntime

base_path = os.path.abspath(os.path.dirname(__file__))
rootfs_path = os.path.join(base_path, "../rootfs/ios")


def main():
    emu = Chomper(
        arch=ARCH_ARM64,
        os_type=OS_IOS,
        rootfs_path=rootfs_path,
    )

    # Objective-C interface
    objc = ObjcRuntime(emu)

    # Find class
    ns_string_class = objc.find_class("NSString")

    # Call class methods
    ns_str = ns_string_class.call_method("stringWithUTF8String:", "chomper")
    print(f"NSString: {ns_str}")

    # Call instance methods
    raw_str = ns_str.call_method("UTF8String")
    print(f"UTF8String: {emu.read_string(raw_str)}")

    # Utility for creating basic NS/CF objects
    ns_data = objc.create_ns_string("chomper")
    print(f"NSData: {ns_data}")

    cf_dict = objc.create_cf_dictionary({"key": "value"})
    print(f"CFDictionary: {cf_dict}")

    # Automatically release Objective-C objects
    with objc.autorelease_pool():
        objc.msg_send("NSDate", "date")


if __name__ == '__main__':
    main()
