import os
import zlib as _zlib

import pytest

from infernum import Infernum
from infernum.exceptions import EmulatorCrashedException

BASE_PATH = os.path.abspath(os.path.dirname(__file__))
LIBRARY_PATH = os.path.join(BASE_PATH, "..", "examples/lib64")


@pytest.fixture()
def emulator():
    yield Infernum()


@pytest.fixture()
def clib(emulator):
    yield emulator.load_module(os.path.join(LIBRARY_PATH, "libc.so"))


@pytest.fixture()
def zlib(emulator):
    yield emulator.load_module(os.path.join(LIBRARY_PATH, "libz.so"))


@pytest.fixture()
def szstonelib(emulator):
    yield emulator.load_module(
        os.path.join(LIBRARY_PATH, "libszstone.so"), exec_init_array=True
    )


@pytest.fixture()
def tinylib(emulator):
    yield emulator.load_module(os.path.join(LIBRARY_PATH, "libtiny.so"))


@pytest.mark.usefixtures("clib")
def test_find_symbol(emulator):
    symbol_name = "malloc"
    symbol = emulator.find_symbol(symbol_name)

    assert symbol.name == symbol_name


def test_location_module(emulator, clib):
    address = clib.base + 0x1000
    module = emulator.locate_module(address)

    assert module.name == "libc.so"


def test_get_back_trace(emulator, tinylib):
    def hook_code(*_):
        trace = emulator.get_back_trace()
        assert len(trace.locations) != 0

    emulator.add_hook(tinylib.base + 0x2BA08, hook_code)

    a1 = emulator.create_buffer(32)
    a2 = emulator.create_buffer(32)
    a3 = emulator.create_buffer(32)

    emulator.call_address(tinylib.base + 0x289A4, a1, a2, a3)


@pytest.mark.usefixtures("zlib")
def test_add_hook(emulator):
    def hook_code(*_):
        nonlocal trigger
        trigger = True

    symbol = emulator.find_symbol("zlibVersion")

    trigger = False

    emulator.add_hook(symbol.address, hook_code)
    emulator.call_symbol(symbol.name)

    assert trigger


@pytest.mark.usefixtures("zlib")
def test_set_and_get_argument(emulator):
    arguments = [i for i in range(16)]

    for index, argument in enumerate(arguments):
        emulator.set_argument(index, argument)

    for index, argument in enumerate(arguments):
        assert emulator.get_argument(index) == argument


@pytest.mark.usefixtures("zlib")
def test_set_and_get_retval(emulator):
    retval = 105

    emulator.set_retval(retval)
    result = emulator.get_retval()

    assert result == retval


@pytest.mark.usefixtures("zlib")
def test_jump_back(emulator):
    def hook_code_early(*_):
        nonlocal trigger_early
        trigger_early = True
        emulator.jump_back()

    def hook_code_late(*_):
        nonlocal trigger_late
        trigger_late = True

    symbol = emulator.find_symbol("zlibVersion")

    trigger_early = False
    trigger_late = False

    emulator.add_hook(symbol.address, hook_code_early)
    emulator.add_hook(symbol.address + 4, hook_code_late)
    emulator.call_symbol(symbol.name)

    assert trigger_early and not trigger_late


def test_crate_buffer(emulator):
    result = emulator.create_buffer(1024)

    assert result is not None


def test_create_string(emulator):
    result = emulator.create_string("infernum")

    assert result is not None


def test_write_and_read_int(emulator):
    buffer = emulator.create_buffer(1024)
    value = 105

    emulator.write_int(buffer, value)
    result = emulator.read_int(buffer)

    assert result == value


def test_write_and_read_bytes(emulator):
    buffer = emulator.create_buffer(1024)
    data = b"infernum"

    emulator.write_bytes(buffer, data)
    result = emulator.read_bytes(buffer, len(data))

    assert result == data


def test_write_and_read_string(emulator):
    buffer = emulator.create_buffer(1024)
    string = "infernum"

    emulator.write_string(buffer, string)
    result = emulator.read_string(buffer)

    assert result == string


@pytest.mark.usefixtures("zlib")
def test_call_symbol(emulator):
    result = emulator.call_symbol("zlibVersion")

    assert emulator.read_string(result) == "1.2.8"


@pytest.mark.usefixtures("zlib")
def test_call_address(emulator):
    symbol = emulator.find_symbol("zlibVersion")
    result = emulator.call_address(symbol.address)

    assert emulator.read_string(result) == "1.2.8"


def test_exec_init_array(emulator, szstonelib):
    assert emulator.read_string(szstonelib.base + 0x49DD8) == "1.2.3"


@pytest.mark.usefixtures("zlib")
@pytest.mark.usefixtures("clib")
def test_emulate(emulator, szstonelib, tinylib):
    data = b"infernum"

    # sample: 1
    a1 = emulator.create_buffer(len(data))
    a2 = len(data)
    a3 = emulator.create_buffer(1024)

    emulator.write_bytes(a1, data)

    result_size = emulator.call_address(szstonelib.base + 0x2F1C8, a1, a2, a3)
    result = emulator.read_bytes(a3, result_size)

    assert _zlib.crc32(result) == 588985915

    # sample: 2
    a1 = emulator.create_buffer(32)
    a2 = emulator.create_buffer(32)
    a3 = emulator.create_buffer(32)

    emulator.write_bytes(a1, data * 4)
    emulator.write_bytes(a2, data * 4)

    emulator.call_address(tinylib.base + 0x289A4, a1, a2, a3)
    result = emulator.read_bytes(a3, 32)

    assert _zlib.crc32(result) == 2637469588


def test_unhandled_system_call_exception(emulator):
    with pytest.raises(EmulatorCrashedException, match=r"Unhandled system call.*"):
        emulator._symbol_hooks.pop("malloc")
        emulator.load_module(os.path.join(LIBRARY_PATH, "libc.so"))
        emulator.call_symbol("malloc")


def test_missing_symbol_required_exception(emulator, szstonelib):
    with pytest.raises(EmulatorCrashedException, match=r"Missing symbol.*"):
        data = b"infernum"

        a1 = emulator.create_buffer(len(data))
        a2 = len(data)
        a3 = emulator.create_buffer(1024)

        emulator.write_bytes(a1, data)
        emulator.call_address(szstonelib.base + 0x289A4, a1, a2, a3)
