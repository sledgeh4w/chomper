import os
import zlib

import pytest

from .conftest import arm64_path

from chomper import Chomper
from chomper.const import ARCH_ARM64
from chomper.exceptions import EmulatorCrashedException


@pytest.mark.usefixtures("clib_arm64")
def test_find_symbol(emu_arm64):
    symbol_name = "malloc"
    symbol = emu_arm64.find_symbol(symbol_name)

    assert symbol.name == symbol_name


def test_locate_address(emu_arm64, clib_arm64):
    address = clib_arm64.base + 0x1000
    location = emu_arm64.locate_address(address)

    assert location.module.name == clib_arm64.name


def test_backtrace(emu_arm64, tinylib_v73021_arm64):
    def hook_code(*_):
        locations = emu_arm64.backtrace()
        assert len(locations) != 0

    emu_arm64.add_hook(tinylib_v73021_arm64.base + 0x2BA08, hook_code)

    a1 = emu_arm64.alloc_memory(32)
    a2 = emu_arm64.alloc_memory(32)
    a3 = emu_arm64.alloc_memory(32)

    emu_arm64.call_address(tinylib_v73021_arm64.base + 0x289A4, a1, a2, a3)


@pytest.mark.usefixtures("zlib_arm64")
def test_add_hook(emu_arm64):
    def hook_code(*_):
        user_data["hooked"] = True

    symbol = emu_arm64.find_symbol("zlibVersion")
    user_data = {}

    emu_arm64.add_hook(symbol.address, hook_code, user_data=user_data)
    emu_arm64.call_symbol(symbol.name)

    assert user_data.get("hooked")


@pytest.mark.usefixtures("zlib_arm64")
def test_set_and_get_argument(emu_arm64):
    arguments = [i for i in range(16)]

    for index, argument in enumerate(arguments):
        emu_arm64.set_argument(index, argument)

    for index, argument in enumerate(arguments):
        assert emu_arm64.get_argument(index) == argument


@pytest.mark.usefixtures("zlib_arm64")
def test_set_and_get_retval(emu_arm64):
    retval = 105

    emu_arm64.set_retval(retval)
    result = emu_arm64.get_retval()

    assert result == retval


def test_alloc(emu_arm64):
    result = emu_arm64.alloc_memory(1024)

    assert result is not None


def test_alloc_string(emu_arm64, sample_str):
    result = emu_arm64.alloc_string(sample_str)

    assert result is not None


def test_free(emu_arm64):
    addr = emu_arm64.alloc_memory(1024)
    emu_arm64.free_memory(addr)


def test_write_and_read_int(emu_arm64):
    addr = emu_arm64.alloc_memory(1024)
    value = 105

    emu_arm64.write_int(addr, value)
    result = emu_arm64.read_int(addr)

    assert result == value


def test_write_and_read_bytes(emu_arm64, sample_bytes):
    addr = emu_arm64.alloc_memory(1024)

    emu_arm64.write_bytes(addr, sample_bytes)
    result = emu_arm64.read_bytes(addr, len(sample_bytes))

    assert result == sample_bytes


def test_write_and_read_string(emu_arm64, sample_str):
    addr = emu_arm64.alloc_memory(1024)

    emu_arm64.write_string(addr, sample_str)
    result = emu_arm64.read_string(addr)

    assert result == sample_str


@pytest.mark.usefixtures("zlib_arm64")
def test_call_symbol(emu_arm64):
    result = emu_arm64.call_symbol("zlibVersion")

    assert emu_arm64.read_string(result) == "1.2.8"


@pytest.mark.usefixtures("zlib_arm64")
def test_call_address(emu_arm64):
    symbol = emu_arm64.find_symbol("zlibVersion")
    result = emu_arm64.call_address(symbol.address)

    assert emu_arm64.read_string(result) == "1.2.8"


def test_exec_init_array(emu_arm64, szstonelib_v4945_arm64):
    assert emu_arm64.read_string(szstonelib_v4945_arm64.base + 0x49DD8) == "1.2.3"


@pytest.mark.usefixtures("clib_arm", "clib_arm64")
@pytest.mark.parametrize("emu_name", ["emu_arm", "emu_arm64"])
def test_clib_malloc(request, emu_name):
    emu = request.getfixturevalue(emu_name)

    result = emu.call_symbol("malloc", 16)

    assert result != 0


@pytest.mark.usefixtures("clib_arm", "clib_arm64")
@pytest.mark.parametrize("emu_name", ["emu_arm", "emu_arm64"])
def test_clib_free(request, emu_name):
    emu = request.getfixturevalue(emu_name)

    addr = emu.call_symbol("malloc", 16)
    emu.call_symbol("free", addr)


@pytest.mark.usefixtures("clib_arm", "clib_arm64")
@pytest.mark.parametrize("emu_name", ["emu_arm", "emu_arm64"])
def test_clib_memcpy(request, emu_name, sample_str):
    emu = request.getfixturevalue(emu_name)

    v1 = emu.alloc_memory(16)
    v2 = emu.alloc_string(sample_str)

    emu.call_symbol("memcpy", v1, v2, len(sample_str) + 1)
    result = emu.read_string(v1)

    assert result == sample_str


@pytest.mark.usefixtures("clib_arm", "clib_arm64")
@pytest.mark.parametrize("emu_name", ["emu_arm", "emu_arm64"])
def test_clib_memcmp(request, emu_name, sample_str):
    emu = request.getfixturevalue(emu_name)

    v1 = emu.alloc_string(sample_str)
    v2 = emu.alloc_string(sample_str)
    v3 = emu.alloc_string(sample_str[::-1])

    result = emu.call_symbol("memcmp", v1, v2, len(sample_str))

    assert result == 0

    result = emu.call_symbol("memcmp", v1, v3, len(sample_str))

    assert result != 0


@pytest.mark.usefixtures("clib_arm", "clib_arm64")
@pytest.mark.parametrize("emu_name", ["emu_arm", "emu_arm64"])
def test_clib_memset(request, emu_name, sample_str):
    emu = request.getfixturevalue(emu_name)

    size = len(sample_str)

    v1 = emu.alloc_string(sample_str)

    emu.call_symbol("memset", v1, 0, size)
    result = emu.read_bytes(v1, size)

    assert result == b"\x00" * size


@pytest.mark.usefixtures("clib_arm", "clib_arm64")
@pytest.mark.parametrize("emu_name", ["emu_arm", "emu_arm64"])
def test_clib_strncpy(request, emu_name, sample_str):
    emu = request.getfixturevalue(emu_name)

    v1 = emu.alloc_memory(16)
    v2 = emu.alloc_string(sample_str)
    v3 = 5

    emu.call_symbol("strncpy", v1, v2, v3)
    result = emu.read_string(v1)

    assert result == sample_str[:v3]


@pytest.mark.usefixtures("clib_arm", "clib_arm64")
@pytest.mark.parametrize("emu_name", ["emu_arm", "emu_arm64"])
def test_clib_strncmp(request, emu_name, sample_str):
    emu = request.getfixturevalue(emu_name)

    v1 = emu.alloc_string(sample_str)
    v2 = emu.alloc_string(sample_str[:-1] + " ")

    result = emu.call_symbol("strncmp", v1, v2, len(sample_str) - 1)

    assert result == 0

    result = emu.call_symbol("strncmp", v1, v2, len(sample_str))

    assert result != 0


@pytest.mark.usefixtures("clib_arm", "clib_arm64")
@pytest.mark.parametrize("emu_name", ["emu_arm", "emu_arm64"])
def test_clib_strncat(request, emu_name, sample_str):
    emu = request.getfixturevalue(emu_name)

    v1 = emu.alloc_memory(32)
    v2 = emu.alloc_string(sample_str)
    v3 = 5

    emu.write_string(v1, sample_str)

    emu.call_symbol("strncat", v1, v2, v3)
    result = emu.read_string(v1)

    assert result == sample_str + sample_str[:v3]


@pytest.mark.usefixtures("clib_arm", "clib_arm64")
@pytest.mark.parametrize("emu_name", ["emu_arm", "emu_arm64"])
def test_clib_strcpy(request, emu_name, sample_str):
    emu = request.getfixturevalue(emu_name)

    v1 = emu.alloc_memory(16)
    v2 = emu.alloc_string(sample_str)

    emu.call_symbol("strcpy", v1, v2)
    result = emu.read_string(v1)

    assert result == sample_str


@pytest.mark.usefixtures("clib_arm", "clib_arm64")
@pytest.mark.parametrize("emu_name", ["emu_arm", "emu_arm64"])
def test_clib_strcmp(request, emu_name, sample_str):
    emu = request.getfixturevalue(emu_name)

    v1 = emu.alloc_string(sample_str)
    v2 = emu.alloc_string(sample_str)
    v3 = emu.alloc_string(sample_str[:-1] + " ")

    result = emu.call_symbol("strcmp", v1, v2)

    assert result == 0

    result = emu.call_symbol("strcmp", v1, v3)

    assert result != 0


@pytest.mark.usefixtures("clib_arm", "clib_arm64")
@pytest.mark.parametrize("emu_name", ["emu_arm", "emu_arm64"])
def test_clib_strcat(request, emu_name, sample_str):
    emu = request.getfixturevalue(emu_name)

    v1 = emu.alloc_memory(32)
    v2 = emu.alloc_string(sample_str)

    emu.write_string(v1, sample_str)

    emu.call_symbol("strcat", v1, v2)
    result = emu.read_string(v1)

    assert result == sample_str + sample_str


@pytest.mark.usefixtures("clib_arm", "clib_arm64")
@pytest.mark.parametrize("emu_name", ["emu_arm", "emu_arm64"])
def test_clib_strlen(request, emu_name, sample_str):
    emu = request.getfixturevalue(emu_name)

    v1 = emu.alloc_string(sample_str)

    result = emu.call_symbol("strlen", v1)

    assert result == len(sample_str)


@pytest.mark.usefixtures("clib_arm", "clib_arm64")
@pytest.mark.parametrize("emu_name", ["emu_arm", "emu_arm64"])
def test_clib_sprintf(request, emu_name, sample_str):
    emu = request.getfixturevalue(emu_name)

    fmt = "%d%s"

    v1 = emu.alloc_memory(16)
    v2 = emu.alloc_string(fmt)
    v3 = len(sample_str)
    v4 = emu.alloc_string(sample_str)

    emu.call_symbol("sprintf", v1, v2, v3, v4)
    result = emu.read_string(v1)

    assert result == f"{len(sample_str)}{sample_str}"


@pytest.mark.usefixtures("clib_arm", "clib_arm64")
@pytest.mark.parametrize("emu_name", ["emu_arm", "emu_arm64"])
def test_clib_printf(request, emu_name, sample_str):
    emu = request.getfixturevalue(emu_name)

    fmt = "%d%s"

    v1 = emu.alloc_string(fmt)
    v2 = len(sample_str)
    v3 = emu.alloc_string(sample_str)

    emu.call_symbol("printf", v1, v2, v3)


@pytest.mark.usefixtures("clib_arm", "zlib_arm")
def test_emulate_dusanwalib_v4856_arm(emu_arm, dusanwalib_v4856_arm, sample_bytes):
    a1 = emu_arm.alloc_memory(32)
    a2 = 32
    a3 = emu_arm.alloc_memory(32)
    a4 = emu_arm.alloc_memory(32)

    emu_arm.write_bytes(a1, sample_bytes)
    emu_arm.write_bytes(a4, sample_bytes)

    emu_arm.call_address((dusanwalib_v4856_arm.base + 0xA588) | 1, a1, a2, a3, a4)
    result = emu_arm.read_bytes(a3, a2)

    assert zlib.crc32(result) == 2152630634


@pytest.mark.usefixtures("clib_arm64", "zlib_arm64")
def test_emulate_szstonelib_v4945_arm64(
    emu_arm64, szstonelib_v4945_arm64, sample_bytes
):
    a1 = emu_arm64.alloc_memory(len(sample_bytes))
    a2 = len(sample_bytes)
    a3 = emu_arm64.alloc_memory(1024)

    emu_arm64.write_bytes(a1, sample_bytes)

    result_size = emu_arm64.call_address(
        szstonelib_v4945_arm64.base + 0x2F1C8, a1, a2, a3
    )
    result = emu_arm64.read_bytes(a3, result_size)

    assert zlib.crc32(result) == 588985915


@pytest.mark.usefixtures("clib_arm64", "zlib_arm64")
def test_emulate_tinylib_v73021_arm64(emu_arm64, tinylib_v73021_arm64, sample_bytes):
    a1 = emu_arm64.alloc_memory(32)
    a2 = emu_arm64.alloc_memory(32)
    a3 = emu_arm64.alloc_memory(32)

    emu_arm64.write_bytes(a1, sample_bytes * 4)
    emu_arm64.write_bytes(a2, sample_bytes * 4)

    emu_arm64.call_address(tinylib_v73021_arm64.base + 0x289A4, a1, a2, a3)
    result = emu_arm64.read_bytes(a3, 32)

    assert zlib.crc32(result) == 2637469588


def test_unhandled_system_call_exception():
    with pytest.raises(EmulatorCrashedException, match=r"Unhandled system call.*"):
        emu = Chomper(arch=ARCH_ARM64)
        emu._symbol_hooks.pop("malloc")

        emu.load_module(os.path.join(arm64_path, "libc.so"))

        emu.call_symbol("malloc")


def test_missing_symbol_required_exception(sample_bytes):
    with pytest.raises(EmulatorCrashedException, match=r"Missing symbol.*"):
        emu = Chomper(arch=ARCH_ARM64)
        szstonelib = emu.load_module(os.path.join(arm64_path, "libszstone.so"))

        a1 = emu.alloc_memory(len(sample_bytes))
        a2 = len(sample_bytes)
        a3 = emu.alloc_memory(1024)

        emu.write_bytes(a1, sample_bytes)
        emu.call_address(szstonelib.base + 0x289A4, a1, a2, a3)
