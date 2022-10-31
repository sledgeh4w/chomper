import os

import pytest

from .conftest import lib64_path

from infernum import Infernum
from infernum.const import ARCH_ARM64
from infernum.exceptions import EmulatorCrashedException


def test_unhandled_system_call_exception():
    with pytest.raises(EmulatorCrashedException, match=r"Unhandled system call.*"):
        emulator = Infernum(arch=ARCH_ARM64)
        emulator._symbol_hooks.pop("malloc")

        emulator.load_module(os.path.join(lib64_path, "libc.so"))

        emulator.call_symbol("malloc")


def test_missing_symbol_required_exception(sample_bytes):
    with pytest.raises(EmulatorCrashedException, match=r"Missing symbol.*"):
        emulator = Infernum(arch=ARCH_ARM64)
        szstonelib = emulator.load_module(
            os.path.join(lib64_path, "com.shizhuang.duapp_v4.94.5_libszstone.so")
        )

        a1 = emulator.create_buffer(len(sample_bytes))
        a2 = len(sample_bytes)
        a3 = emulator.create_buffer(1024)

        emulator.write_bytes(a1, sample_bytes)
        emulator.call_address(szstonelib.base + 0x289A4, a1, a2, a3)
