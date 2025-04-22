import os

from chomper import Chomper
from chomper.const import ARCH_ARM64, OS_IOS
from chomper.objc import ObjC, pyobj2nsobj, pyobj2cfobj

base_path = os.path.abspath(os.path.dirname(__file__))


def main():
    emu = Chomper(
        arch=ARCH_ARM64,
        os_type=OS_IOS,
        rootfs_path=os.path.join(base_path, "../rootfs/ios"),
    )

    # Objective-C interface
    objc = ObjC(emu)

    # Call class methods
    ns_str = objc.msg_send("NSString", "stringWithUTF8String:", "chomper")
    print("NSString: %s" % ns_str)

    # Call instance methods
    raw_str = objc.msg_send(ns_str, "cString")
    print("cString: %s" % emu.read_string(raw_str))

    # Automatically release Objective-C objects
    with objc.autorelease_pool():
        objc.msg_send("NSDate", "date")

    # Utility for creating basic NS objects
    ns_data = pyobj2nsobj(emu, b"chomper")
    print("NSData: %s" % ns_data)

    # Utility for creating basic CF objects
    cf_dict = pyobj2cfobj(emu, {"name": "Chomper"})
    print("CFDictionary: %s" % cf_dict)


if __name__ == '__main__':
    main()
