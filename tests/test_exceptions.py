import pytest

from chomper.exceptions import (
    EmulatorCrashed,
    SymbolMissing,
    ObjCUnrecognizedSelector,
    ProgramTerminated,
)


def test_unhandled_system_call_exception(emu_ios):
    with pytest.raises(EmulatorCrashed, match=r"Unhandled system call.*"):
        emu_ios.os.syscall_handler.handle_syscall(0x1000)


def test_symbol_missing_exception(emu_ios):
    with pytest.raises(SymbolMissing):
        emu_ios.get_symbol("_undefined")


def test_objc_unrecognized_selector_exception(emu_ios, objc):
    with pytest.raises(
        ObjCUnrecognizedSelector,
        match=r"Unrecognized selector '.*' of class",
    ):
        with objc.autorelease_pool():
            objc.msg_send("NSString", "undefined")

    with pytest.raises(
        ObjCUnrecognizedSelector,
        match=r"Unrecognized selector '.*' of instance",
    ):
        with objc.autorelease_pool():
            string = objc.msg_send("NSString", "stringWithUTF8String:", "")
            objc.msg_send(string, "undefined")


def test_program_terminated_exception(emu_ios):
    with pytest.raises(ProgramTerminated):
        emu_ios.call_symbol("_exit")
