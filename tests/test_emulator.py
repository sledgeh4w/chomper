import pytest


@pytest.mark.usefixtures("libc_arm64")
def test_find_symbol(emu_arm64):
    symbol_name = "malloc"
    symbol = emu_arm64.find_symbol(symbol_name)

    assert symbol.name == symbol_name


def test_backtrace(emu_arm64, libtiny_v73021_arm64):
    def hook_code(uc, address, size, user_data):
        trace_stack = emu_arm64.backtrace()
        assert len(trace_stack) != 0

    emu_arm64.add_hook(libtiny_v73021_arm64.base + 0x2BA08, hook_code)

    a1 = emu_arm64.create_buffer(32)
    a2 = emu_arm64.create_buffer(32)
    a3 = emu_arm64.create_buffer(32)

    emu_arm64.call_address(libtiny_v73021_arm64.base + 0x289A4, a1, a2, a3)


@pytest.mark.usefixtures("libz_arm64")
def test_set_and_get_arg(emu_arm64):
    args = [i for i in range(16)]

    for index, arg in enumerate(args):
        emu_arm64.set_arg(index, arg)

    for index, arg in enumerate(args):
        assert emu_arm64.get_arg(index) == arg


@pytest.mark.usefixtures("libz_arm64")
def test_set_and_get_retval(emu_arm64):
    retval = 105

    emu_arm64.set_retval(retval)
    result = emu_arm64.get_retval()

    assert result == retval


def test_create_buffer(emu_arm64):
    result = emu_arm64.create_buffer(1024)

    assert result is not None


def test_create_string(emu_arm64, input_str):
    result = emu_arm64.create_string(input_str)

    assert result is not None


def test_free(emu_arm64):
    addr = emu_arm64.create_buffer(1024)
    emu_arm64.free(addr)


def test_read_and_write_int(emu_arm64):
    addr = emu_arm64.create_buffer(1024)
    value = 105

    emu_arm64.write_int(addr, value, size=4)
    result = emu_arm64.read_int(addr, size=4)

    assert result == value


def test_read_and_write_bytes(emu_arm64, input_bytes):
    addr = emu_arm64.create_buffer(1024)

    emu_arm64.write_bytes(addr, input_bytes)
    result = emu_arm64.read_bytes(addr, len(input_bytes))

    assert result == input_bytes


def test_read_and_write_string(emu_arm64, input_str):
    addr = emu_arm64.create_buffer(1024)

    emu_arm64.write_string(addr, input_str)
    result = emu_arm64.read_string(addr)

    assert result == input_str


@pytest.mark.usefixtures("libz_arm64")
def test_call_symbol(emu_arm64):
    result = emu_arm64.call_symbol("zlibVersion")

    assert emu_arm64.read_string(result) == "1.2.8"


@pytest.mark.usefixtures("libz_arm64")
def test_call_address(emu_arm64):
    symbol = emu_arm64.find_symbol("zlibVersion")
    result = emu_arm64.call_address(symbol.address)

    assert emu_arm64.read_string(result) == "1.2.8"


def test_exec_init_array(emu_arm64, libszstone_v4945_arm64):
    assert emu_arm64.read_string(libszstone_v4945_arm64.base + 0x49DD8) == "1.2.3"
