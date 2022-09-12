import os
import zlib as _zlib

import pytest

from infernum import Infernum
from infernum.const import ARCH_ARM, ARCH_ARM64
from infernum.exceptions import EmulatorCrashedException

BASE_PATH = os.path.abspath(os.path.dirname(__file__))

LIB_PATH = os.path.join(BASE_PATH, "..", "examples/lib")
LIB64_PATH = os.path.join(BASE_PATH, "..", "examples/lib64")


@pytest.fixture()
def arm_emu():
    yield Infernum(arch=ARCH_ARM)


@pytest.fixture()
def arm_clib(arm_emu):
    yield arm_emu.load_module(os.path.join(LIB_PATH, "libc.so"))


@pytest.fixture()
def arm_zlib(arm_emu):
    yield arm_emu.load_module(os.path.join(LIB_PATH, "libz.so"))


@pytest.fixture()
def arm_dusanwalib(arm_emu):
    yield arm_emu.load_module(
        os.path.join(LIB_PATH, "libdusanwa.so"), exec_init_array=True
    )


@pytest.fixture()
def arm64_emu():
    yield Infernum(arch=ARCH_ARM64)


@pytest.fixture()
def arm64_clib(arm64_emu):
    yield arm64_emu.load_module(os.path.join(LIB64_PATH, "libc.so"))


@pytest.fixture()
def arm64_zlib(arm64_emu):
    yield arm64_emu.load_module(os.path.join(LIB64_PATH, "libz.so"))


@pytest.fixture()
def arm64_szstonelib(arm64_emu):
    yield arm64_emu.load_module(
        os.path.join(LIB64_PATH, "libszstone.so"), exec_init_array=True
    )


@pytest.fixture()
def arm64_tinylib(arm64_emu):
    yield arm64_emu.load_module(os.path.join(LIB64_PATH, "libtiny.so"))


@pytest.mark.usefixtures("arm64_clib")
def test_find_symbol(arm64_emu):
    symbol_name = "malloc"
    symbol = arm64_emu.find_symbol(symbol_name)

    assert symbol.name == symbol_name


def test_locate_module(arm64_emu, arm64_clib):
    address = arm64_clib.base + 0x1000
    module = arm64_emu.locate_module(address)

    assert module.name == "libc.so"


def test_get_back_trace(arm64_emu, arm64_tinylib):
    def hook_code(*_):
        locations = arm64_emu.get_back_trace()
        assert len(locations) != 0

    arm64_emu.add_hook(arm64_tinylib.base + 0x2BA08, hook_code)

    a1 = arm64_emu.create_buffer(32)
    a2 = arm64_emu.create_buffer(32)
    a3 = arm64_emu.create_buffer(32)

    arm64_emu.call_address(arm64_tinylib.base + 0x289A4, a1, a2, a3)


@pytest.mark.usefixtures("arm64_zlib")
def test_add_hook(arm64_emu):
    def hook_code(*_):
        nonlocal trigger
        trigger = True

    symbol = arm64_emu.find_symbol("zlibVersion")

    trigger = False

    arm64_emu.add_hook(symbol.address, hook_code)
    arm64_emu.call_symbol(symbol.name)

    assert trigger


@pytest.mark.usefixtures("arm64_zlib")
def test_set_and_get_argument(arm64_emu):
    arguments = [i for i in range(16)]

    for index, argument in enumerate(arguments):
        arm64_emu.set_argument(index, argument)

    for index, argument in enumerate(arguments):
        assert arm64_emu.get_argument(index) == argument


@pytest.mark.usefixtures("arm64_zlib")
def test_set_and_get_retval(arm64_emu):
    retval = 105

    arm64_emu.set_retval(retval)
    result = arm64_emu.get_retval()

    assert result == retval


@pytest.mark.usefixtures("arm64_zlib")
def test_jump_back(arm64_emu):
    def hook_code_early(*_):
        nonlocal trigger_early
        trigger_early = True
        arm64_emu.jump_back()

    def hook_code_late(*_):
        nonlocal trigger_late
        trigger_late = True

    symbol = arm64_emu.find_symbol("zlibVersion")

    trigger_early = False
    trigger_late = False

    arm64_emu.add_hook(symbol.address, hook_code_early)
    arm64_emu.add_hook(symbol.address + 4, hook_code_late)
    arm64_emu.call_symbol(symbol.name)

    assert trigger_early and not trigger_late


def test_crate_buffer(arm64_emu):
    result = arm64_emu.create_buffer(1024)

    assert result is not None


def test_create_string(arm64_emu):
    result = arm64_emu.create_string("infernum")

    assert result is not None


def test_free(arm64_emu):
    buffer = arm64_emu.create_buffer(1024)
    arm64_emu.free(buffer)


def test_write_and_read_int(arm64_emu):
    buffer = arm64_emu.create_buffer(1024)
    value = 105

    arm64_emu.write_int(buffer, value)
    result = arm64_emu.read_int(buffer)

    assert result == value


def test_write_and_read_bytes(arm64_emu):
    buffer = arm64_emu.create_buffer(1024)
    data = b"infernum"

    arm64_emu.write_bytes(buffer, data)
    result = arm64_emu.read_bytes(buffer, len(data))

    assert result == data


def test_write_and_read_string(arm64_emu):
    buffer = arm64_emu.create_buffer(1024)
    string = "infernum"

    arm64_emu.write_string(buffer, string)
    result = arm64_emu.read_string(buffer)

    assert result == string


@pytest.mark.usefixtures("arm64_zlib")
def test_call_symbol(arm64_emu):
    result = arm64_emu.call_symbol("zlibVersion")

    assert arm64_emu.read_string(result) == "1.2.8"


@pytest.mark.usefixtures("arm64_zlib")
def test_call_address(arm64_emu):
    symbol = arm64_emu.find_symbol("zlibVersion")
    result = arm64_emu.call_address(symbol.address)

    assert arm64_emu.read_string(result) == "1.2.8"


def test_exec_init_array(arm64_emu, arm64_szstonelib):
    assert arm64_emu.read_string(arm64_szstonelib.base + 0x49DD8) == "1.2.3"


# def test_unhandled_system_call_exception(arm64_emu):
#     with pytest.raises(EmulatorCrashedException, match=r"Unhandled system call.*"):
#         arm64_emu._symbol_hooks.pop("malloc")
#         arm64_emu.load_module(os.path.join(LIB64_PATH, "libc.so"))
#         arm64_emu.call_symbol("malloc")


# def test_missing_symbol_required_exception(arm64_emu, arm64_szstonelib):
#     with pytest.raises(EmulatorCrashedException, match=r"Missing symbol.*"):
#         data = b"infernum"
#
#         a1 = arm64_emu.create_buffer(len(data))
#         a2 = len(data)
#         a3 = arm64_emu.create_buffer(1024)
#
#         arm64_emu.write_bytes(a1, data)
#         arm64_emu.call_address(arm64_szstonelib.base + 0x289A4, a1, a2, a3)


def _test_clib(emu):
    # malloc
    size = 1024
    addr = emu.call_symbol("malloc", size)

    data = "infernum"

    # memcpy
    a1 = emu.create_string(data)

    emu.call_symbol("memcpy", addr, a1, len(data) + 1)
    result = emu.read_string(addr)

    assert result == data

    # memcmp
    result = emu.call_symbol("memcmp", addr, a1, len(data) + 1)

    assert result == 0

    # memset
    emu.call_symbol("memset", addr, 0, size)
    result = emu.read_bytes(addr, size)

    assert result == b"\x00" * size

    # strncpy
    a1 = emu.create_string(data)
    a2 = 5

    emu.call_symbol("strncpy", addr, a1, a2)
    result = emu.read_string(addr)

    assert result == data[:a2]

    # strncmp
    result = emu.call_symbol("strncmp", addr, a1, a2)

    assert result == 0

    # strcpy
    emu.call_symbol("strcpy", addr + a2, a1 + a2)
    result = emu.read_string(addr)

    assert result == data

    # strcmp
    result = emu.call_symbol("strcmp", addr, a1)

    assert result == 0

    # strncat
    a1 = emu.create_string(data)
    a2 = 5

    emu.call_symbol("strncat", addr, a1, a2)
    result = emu.read_string(addr)

    assert result == data + data[:a2]

    emu.call_symbol("strcat", addr + a2, a1 + a2)
    result = emu.read_string(addr)

    assert result == data + data

    # strlen
    result = emu.call_symbol("strlen", addr)

    assert result == len(data + data)

    # sprintf
    fmt = "%d%s"

    a1 = emu.create_string(fmt)
    a2 = len(data)
    a3 = emu.create_string(data)

    emu.call_symbol("sprintf", addr, a1, a2, a3)
    result = emu.read_string(addr)

    assert result == f"{len(data)}{data}"

    # free
    emu.call_symbol("free", addr)


@pytest.mark.usefixtures("arm_clib")
def test_clib_arm(arm_emu):
    _test_clib(arm_emu)


@pytest.mark.usefixtures("arm64_clib")
def test_clib_arm64(arm64_emu):
    _test_clib(arm64_emu)


@pytest.mark.usefixtures("arm_zlib")
@pytest.mark.usefixtures("arm_clib")
def test_emulate_arm(arm_emu, arm_dusanwalib):
    # sample 1: sub_A588@libdusanwa.so
    data = b"infernum"

    a1 = arm_emu.create_buffer(32)
    a2 = 32
    a3 = arm_emu.create_buffer(32)
    a4 = arm_emu.create_buffer(32)

    arm_emu.write_bytes(a1, data)
    arm_emu.write_bytes(a4, data)

    arm_emu.call_address((arm_dusanwalib.base + 0xA588) | 1, a1, a2, a3, a4)
    result = arm_emu.read_bytes(a3, a2)

    assert _zlib.crc32(result) == 2152630634


@pytest.mark.usefixtures("arm64_zlib")
@pytest.mark.usefixtures("arm64_clib")
def test_emulate_arm64(arm64_emu, arm64_szstonelib, arm64_tinylib):
    # sample 1: sub_2F1C8@libszstone.so
    data = b"infernum"

    a1 = arm64_emu.create_buffer(len(data))
    a2 = len(data)
    a3 = arm64_emu.create_buffer(1024)

    arm64_emu.write_bytes(a1, data)

    result_size = arm64_emu.call_address(arm64_szstonelib.base + 0x2F1C8, a1, a2, a3)
    result = arm64_emu.read_bytes(a3, result_size)

    assert _zlib.crc32(result) == 588985915

    # sample 2: sub_289A4@libtiny.so
    data = b"infernum"

    a1 = arm64_emu.create_buffer(32)
    a2 = arm64_emu.create_buffer(32)
    a3 = arm64_emu.create_buffer(32)

    arm64_emu.write_bytes(a1, data * 4)
    arm64_emu.write_bytes(a2, data * 4)

    arm64_emu.call_address(arm64_tinylib.base + 0x289A4, a1, a2, a3)
    result = arm64_emu.read_bytes(a3, 32)

    assert _zlib.crc32(result) == 2637469588
