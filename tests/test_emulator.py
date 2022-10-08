import zlib

import pytest


@pytest.mark.usefixtures("clib_arm64")
def test_find_symbol(emu_arm64):
    symbol_name = "malloc"
    symbol = emu_arm64.find_symbol(symbol_name)

    assert symbol.name == symbol_name


def test_locate_module(emu_arm64, clib_arm64):
    address = clib_arm64.base + 0x1000
    module = emu_arm64.locate_module(address)

    assert module.name == "libc.so"


def test_get_back_trace(emu_arm64, sample2lib_arm64):
    def hook_code(*_):
        locations = emu_arm64.backtrace()
        assert len(locations) != 0

    emu_arm64.add_hook(sample2lib_arm64.base + 0x2BA08, hook_code)

    a1 = emu_arm64.create_buffer(32)
    a2 = emu_arm64.create_buffer(32)
    a3 = emu_arm64.create_buffer(32)

    emu_arm64.call_address(sample2lib_arm64.base + 0x289A4, a1, a2, a3)


@pytest.mark.usefixtures("zlib_arm64")
def test_add_hook(emu_arm64):
    def hook_code(*_):
        nonlocal trigger
        trigger = True

    symbol = emu_arm64.find_symbol("zlibVersion")

    trigger = False

    emu_arm64.add_hook(symbol.address, hook_code)
    emu_arm64.call_symbol(symbol.name)

    assert trigger


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


@pytest.mark.usefixtures("zlib_arm64")
def test_jump_back(emu_arm64):
    def hook_code_early(*_):
        nonlocal trigger_early
        trigger_early = True
        emu_arm64.jump_back()

    def hook_code_late(*_):
        nonlocal trigger_late
        trigger_late = True

    symbol = emu_arm64.find_symbol("zlibCompileFlags")

    trigger_early = False
    trigger_late = False

    emu_arm64.add_hook(symbol.address, hook_code_early)
    emu_arm64.add_hook(symbol.address + 4, hook_code_late)
    emu_arm64.call_symbol(symbol.name)

    assert trigger_early and not trigger_late


def test_crate_buffer(emu_arm64):
    result = emu_arm64.create_buffer(1024)

    assert result is not None


def test_create_string(emu_arm64):
    result = emu_arm64.create_string("infernum")

    assert result is not None


def test_free(emu_arm64):
    buffer = emu_arm64.create_buffer(1024)
    emu_arm64.free(buffer)


def test_write_and_read_int(emu_arm64):
    buffer = emu_arm64.create_buffer(1024)
    value = 105

    emu_arm64.write_int(buffer, value)
    result = emu_arm64.read_int(buffer)

    assert result == value


def test_write_and_read_bytes(emu_arm64):
    buffer = emu_arm64.create_buffer(1024)
    data = b"infernum"

    emu_arm64.write_bytes(buffer, data)
    result = emu_arm64.read_bytes(buffer, len(data))

    assert result == data


def test_write_and_read_string(emu_arm64):
    buffer = emu_arm64.create_buffer(1024)
    string = "infernum"

    emu_arm64.write_string(buffer, string)
    result = emu_arm64.read_string(buffer)

    assert result == string


@pytest.mark.usefixtures("zlib_arm64")
def test_call_symbol(emu_arm64):
    result = emu_arm64.call_symbol("zlibVersion")

    assert emu_arm64.read_string(result) == "1.2.8"


@pytest.mark.usefixtures("zlib_arm64")
def test_call_address(emu_arm64):
    symbol = emu_arm64.find_symbol("zlibVersion")
    result = emu_arm64.call_address(symbol.address)

    assert emu_arm64.read_string(result) == "1.2.8"


def test_exec_init_array(emu_arm64, sample1lib_arm64):
    assert emu_arm64.read_string(sample1lib_arm64.base + 0x49DD8) == "1.2.3"


@pytest.mark.usefixtures("clib_arm", "clib_arm64")
@pytest.mark.parametrize("emu_name", ["emu_arm", "emu_arm64"])
def test_clib(request, emu_name):
    emu = request.getfixturevalue(emu_name)

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


@pytest.mark.usefixtures("clib_arm", "zlib_arm")
def test_emulate_arm(emu_arm, sample1lib_arm):
    # sub_A588@libsample1.so
    data = b"infernum"

    a1 = emu_arm.create_buffer(32)
    a2 = 32
    a3 = emu_arm.create_buffer(32)
    a4 = emu_arm.create_buffer(32)

    emu_arm.write_bytes(a1, data)
    emu_arm.write_bytes(a4, data)

    emu_arm.call_address((sample1lib_arm.base + 0xA588) | 1, a1, a2, a3, a4)
    result = emu_arm.read_bytes(a3, a2)

    assert zlib.crc32(result) == 2152630634


@pytest.mark.usefixtures("clib_arm64", "zlib_arm64")
def test_emulate_arm64(emu_arm64, sample1lib_arm64, sample2lib_arm64):
    # sub_2F1C8@libsample1.so
    data = b"infernum"

    a1 = emu_arm64.create_buffer(len(data))
    a2 = len(data)
    a3 = emu_arm64.create_buffer(1024)

    emu_arm64.write_bytes(a1, data)

    result_size = emu_arm64.call_address(sample1lib_arm64.base + 0x2F1C8, a1, a2, a3)
    result = emu_arm64.read_bytes(a3, result_size)

    assert zlib.crc32(result) == 588985915

    # sub_289A4@libsample2.so
    data = b"infernum"

    a1 = emu_arm64.create_buffer(32)
    a2 = emu_arm64.create_buffer(32)
    a3 = emu_arm64.create_buffer(32)

    emu_arm64.write_bytes(a1, data * 4)
    emu_arm64.write_bytes(a2, data * 4)

    emu_arm64.call_address(sample2lib_arm64.base + 0x289A4, a1, a2, a3)
    result = emu_arm64.read_bytes(a3, 32)

    assert zlib.crc32(result) == 2637469588
