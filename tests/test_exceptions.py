import os

import pytest

from . import conftest
from .utils import multi_alloc_mem

from chomper import Chomper
from chomper.const import ARCH_ARM64
from chomper.exceptions import EmulatorCrashed, SymbolMissing, ObjCUnrecognizedSelector


def test_unhandled_system_call_exception():
    with pytest.raises(EmulatorCrashed, match=r"Unhandled system call.*"):
        emu = Chomper(arch=ARCH_ARM64)
        emu.hooks.pop("malloc")

        emu.load_module(os.path.join(conftest.android_lib64_path, "libc.so"))

        emu.call_symbol("malloc")


def test_missing_symbol_required_exception():
    with pytest.raises(EmulatorCrashed, match=r"Missing symbol.*"):
        module_path = conftest.download_binary_file(
            binary_path="examples/binaries/android/com.shizhuang.duapp/libszstone.so"
        )

        sample_bytes = b"chomper"

        emu = Chomper(arch=ARCH_ARM64)
        libszstone = emu.load_module(module_path)

        with multi_alloc_mem(emu, sample_bytes, 1024) as (a1, a3):
            emu.call_address(libszstone.base + 0x289A4, a1, len(sample_bytes), a3)


def test_symbol_missing_exception(emu_ios):
    with pytest.raises(SymbolMissing):
        emu_ios.find_symbol("_undefined_symbol")


def test_objc_unrecognized_selector_exception(emu_ios, objc):
    with pytest.raises(ObjCUnrecognizedSelector):
        with objc.autorelease_pool():
            objc.msg_send("NSString", "undefinedSelector")

    with pytest.raises(ObjCUnrecognizedSelector):
        with objc.autorelease_pool():
            string = objc.msg_send("NSString", "stringWithUTF8String:", "")
            objc.msg_send(string, "undefinedSelector")
