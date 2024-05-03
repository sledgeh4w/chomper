import os

import pytest

from . import conftest

from chomper import Chomper
from chomper.const import ARCH_ARM64
from chomper.exceptions import EmulatorCrashedException


def test_unhandled_system_call_exception():
    with pytest.raises(EmulatorCrashedException, match=r"Unhandled system call.*"):
        emu = Chomper(arch=ARCH_ARM64)
        emu.hooks.pop("malloc")

        emu.load_module(os.path.join(conftest.android_lib64_path, "libc.so"))

        emu.call_symbol("malloc")


def test_missing_symbol_required_exception(input_bytes):
    with pytest.raises(EmulatorCrashedException, match=r"Missing symbol.*"):
        emu = Chomper(arch=ARCH_ARM64)
        libszstone = emu.load_module(
            os.path.join(conftest.com_shizhuang_duapp_path, "libszstone.so")
        )

        a1 = emu.create_buffer(len(input_bytes))
        a2 = len(input_bytes)
        a3 = emu.create_buffer(1024)

        emu.write_bytes(a1, input_bytes)
        emu.call_address(libszstone.base + 0x289A4, a1, a2, a3)
