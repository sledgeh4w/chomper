import binascii
import os

from chomper import Chomper
from chomper.const import ARCH_ARM64, OS_IOS

base_path = os.path.abspath(os.path.dirname(__file__))
rootfs_path = os.path.join(base_path, "../rootfs/ios")


def main():
    emu = Chomper(
        arch=ARCH_ARM64,
        os_type=OS_IOS,
        rootfs_path=rootfs_path,
    )

    s = "chomper"

    # Construct arguments
    data = emu.create_string(s)
    length = len(s)
    output = emu.create_buffer(16)

    # Call function
    emu.call_symbol("_CC_MD5", data, length, output)

    result = emu.read_bytes(output, 16)
    result_hex = binascii.b2a_hex(result).decode("utf-8")
    print(f"CC_MD5: {result_hex}")



if __name__ == '__main__':
    main()
