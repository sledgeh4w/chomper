import os

from chomper import Chomper
from chomper.const import ARCH_ARM64, OS_IOS
from chomper.objc import ObjcRuntime

base_path = os.path.abspath(os.path.dirname(__file__))
rootfs_path = os.path.join(base_path, "../../rootfs/ios")


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
    print("NSString: %s" % ns_str)

    # Call instance methods
    raw_str = ns_str.call_method("UTF8String")
    print("UTF8String: %s" % emu.read_string(raw_str))

    # Automatically release Objective-C objects
    with objc.autorelease_pool():
        objc.msg_send("NSDate", "date")

    # Utility for creating basic NS/CF objects
    ns_data = objc.create_ns_data(b"chomper")
    print("NSData: %s" % ns_data)
    cf_dict = objc.create_cf_dictionary({"name": "Chomper"})
    print("CFDictionary: %s" % cf_dict)


if __name__ == '__main__':
    main()
