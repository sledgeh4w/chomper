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

    try:
        emu_arm64.call_address(libtiny_v73021_arm64.base + 0x289A4, a1, a2, a3)
    finally:
        emu_arm64.free(a1)
        emu_arm64.free(a2)
        emu_arm64.free(a3)


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
    assert result

    emu_arm64.free(result)


def test_create_string(emu_arm64):
    result = emu_arm64.create_string("chomper")
    assert result

    emu_arm64.free(result)


def test_free(emu_arm64):
    addr = emu_arm64.create_buffer(1024)
    emu_arm64.free(addr)


def test_read_and_write_int(emu_arm64):
    addr = emu_arm64.create_buffer(1024)
    value = 105

    try:
        emu_arm64.write_int(addr, value, size=4)
        result = emu_arm64.read_int(addr, size=4)
        assert result == value
    finally:
        emu_arm64.free(addr)


def test_read_and_write_bytes(emu_arm64):
    sample_bytes = b"chomper"

    addr = emu_arm64.create_buffer(1024)

    try:
        emu_arm64.write_bytes(addr, sample_bytes)
        result = emu_arm64.read_bytes(addr, len(sample_bytes))
        assert result == sample_bytes
    finally:
        emu_arm64.free(addr)


def test_read_and_write_string(emu_arm64):
    sample_str = "chomper"

    addr = emu_arm64.create_buffer(1024)

    try:
        emu_arm64.write_string(addr, sample_str)
        result = emu_arm64.read_string(addr)
        assert result == sample_str
    finally:
        emu_arm64.free(addr)


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
