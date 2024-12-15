import zlib

import pytest


@pytest.mark.usefixtures("libc_arm", "libz_arm")
def test_libdusanwa_v4856_arm(emu_arm, libdusanwa_v4856_arm):
    sample_bytes = b"chomper"

    a1 = emu_arm.create_buffer(32)
    a2 = 32
    a3 = emu_arm.create_buffer(32)
    a4 = emu_arm.create_buffer(32)

    emu_arm.write_bytes(a1, sample_bytes)
    emu_arm.write_bytes(a4, sample_bytes)

    try:
        emu_arm.call_address((libdusanwa_v4856_arm.base + 0xA588) | 1, a1, a2, a3, a4)
        result = emu_arm.read_bytes(a3, a2)
        assert zlib.crc32(result) == 1148403178
    finally:
        emu_arm.free(a1)
        emu_arm.free(a3)
        emu_arm.free(a4)


@pytest.mark.usefixtures("libc_arm64", "libz_arm64")
def test_libszstone_v4945_arm64(emu_arm64, libszstone_v4945_arm64):
    sample_bytes = b"chomper"

    a1 = emu_arm64.create_buffer(len(sample_bytes))
    a2 = len(sample_bytes)
    a3 = emu_arm64.create_buffer(1024)

    emu_arm64.write_bytes(a1, sample_bytes)

    try:
        result_size = emu_arm64.call_address(
            libszstone_v4945_arm64.base + 0x2F1C8, a1, a2, a3
        )
        result = emu_arm64.read_bytes(a3, result_size)
        assert zlib.crc32(result) == 3884391316
    finally:
        emu_arm64.free(a1)
        emu_arm64.free(a3)


@pytest.mark.usefixtures("libc_arm64", "libz_arm64")
def test_libtiny_v73021_arm64(emu_arm64, libtiny_v73021_arm64):
    sample_bytes = b"chomper"

    a1 = emu_arm64.create_buffer(32)
    a2 = emu_arm64.create_buffer(32)
    a3 = emu_arm64.create_buffer(32)

    emu_arm64.write_bytes(a1, sample_bytes * 4)
    emu_arm64.write_bytes(a2, sample_bytes * 4)

    try:
        emu_arm64.call_address(libtiny_v73021_arm64.base + 0x289A4, a1, a2, a3)
        result = emu_arm64.read_bytes(a3, 32)
        assert zlib.crc32(result) == 4192995551
    finally:
        emu_arm64.free(a1)
        emu_arm64.free(a2)
        emu_arm64.free(a3)


# @staticmethod
# def test_duapp_v581(emu_ios, sample_str):
#     duapp = emu_ios.load_module("DUApp")
#
#     a1 = emu_ios.create_string("objc")
#     a2 = emu_ios.create_string(sample_str)
#     a3 = len(sample_str)
#     a4 = emu_ios.create_string(str(uuid.uuid4()))
#     a5 = emu_ios.create_buffer(8)
#     a6 = emu_ios.create_buffer(8)
#     a7 = emu_ios.create_string("com.siwuai.duapp")
#
#     emu_ios.call_address(duapp.base + 0x109322118, a1, a2, a3, a4, a5, a6, a7)
#     result = emu_ios.read_string(emu_ios.read_pointer(a5))
#
#     assert re.match(r"\w{32}\.[\w=]+\.", result)
