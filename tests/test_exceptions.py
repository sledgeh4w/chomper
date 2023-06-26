import os

import pytest

from .conftest import arm64_path

from chomper import Chomper
from chomper.const import ARCH_ARM64
from chomper.exceptions import EmulatorCrashedException


def test_unhandled_system_call_exception():
    with pytest.raises(EmulatorCrashedException, match=r"Unhandled system call.*"):
        emulator = Chomper(arch=ARCH_ARM64)
        emulator._symbol_hooks.pop("malloc")

        emulator.load_module(os.path.join(arm64_path, "libc.so"))

        emulator.call_symbol("malloc")


def test_missing_symbol_required_exception(sample_bytes):
    with pytest.raises(EmulatorCrashedException, match=r"Missing symbol.*"):
        emulator = Chomper(arch=ARCH_ARM64)
        szstonelib = emulator.load_module(os.path.join(arm64_path, "libszstone.so"))

        a1 = emulator.alloc(len(sample_bytes))
        a2 = len(sample_bytes)
        a3 = emulator.alloc(1024)

        emulator.write_bytes(a1, sample_bytes)
        emulator.call_address(szstonelib.base + 0x289A4, a1, a2, a3)
