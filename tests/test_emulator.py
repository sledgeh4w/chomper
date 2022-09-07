import os
import zlib as _zlib

import pytest

from infernum import Infernum
from infernum.hooks import intercept

BASE_PATH = os.path.abspath(os.path.dirname(__file__))
LIB_PATH = os.path.join(BASE_PATH, "..", "examples/lib64")


@pytest.fixture()
def emulator():
    return Infernum()


@pytest.fixture()
def clib(emulator):
    module_file = os.path.join(LIB_PATH, "libc.so")
    return emulator.load_module(module_file)


@pytest.fixture()
def zlib(emulator):
    module_file = os.path.join(LIB_PATH, "libz.so")
    return emulator.load_module(module_file)


@pytest.fixture()
def szstonelib(emulator):
    module_file = os.path.join(LIB_PATH, "libszstone.so")
    return emulator.load_module(module_file, exec_init_array=True)


def test_exec_init_array(emulator, szstonelib):
    assert emulator.read_string(szstonelib.base + 0x49DD8) == "1.2.3"


def test_hook(emulator, zlib):
    symbol = emulator.find_symbol("crc32")
    replaced = 1

    @intercept
    def hook_code(_emulator):
        _emulator.set_retval(replaced)

    emulator.add_hook(symbol.address, hook_code)
    result = emulator.call_symbol(symbol.name, 0, 0, 0)

    assert result == replaced


def test_call_symbol(emulator, zlib):
    data = b"infernum"

    buffer = emulator.create_buffer(len(data))
    emulator.write_bytes(buffer, data)

    result = emulator.call_symbol("crc32", 0, buffer, len(data))

    assert result == _zlib.crc32(data)


def test_call_address(emulator, zlib):
    data = b"infernum"

    buffer = emulator.create_buffer(len(data))
    emulator.write_bytes(buffer, data)

    symbol = emulator.find_symbol("crc32")
    result = emulator.call_address(symbol.address, 0, buffer, len(data))

    assert result == _zlib.crc32(data)
