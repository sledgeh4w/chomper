import pytest


@pytest.mark.usefixtures("libc_arm64")
def test_find_symbol(emu_arm64):
    symbol_name = "malloc"
    symbol = emu_arm64.find_symbol(symbol_name)

    assert symbol.name == symbol_name


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
    value = 105

    with emu_arm64.mem_context() as ctx:
        buf = ctx.create_buffer(1024)
        emu_arm64.write_int(buf, value, size=4)

        result = emu_arm64.read_int(buf, size=4)
        assert result == value


def test_read_and_write_bytes(emu_arm64):
    sample_bytes = b"chomper"

    with emu_arm64.mem_context() as ctx:
        buf = ctx.create_buffer(1024)
        emu_arm64.write_bytes(buf, sample_bytes)

        result = emu_arm64.read_bytes(buf, len(sample_bytes))
        assert result == sample_bytes


def test_read_and_write_string(emu_arm64):
    sample_str = "chomper"

    with emu_arm64.mem_context() as ctx:
        buf = ctx.create_buffer(1024)
        emu_arm64.write_string(buf, sample_str)

        result = emu_arm64.read_string(buf)
        assert result == sample_str


@pytest.mark.usefixtures("libz_arm64")
def test_call_symbol(emu_arm64):
    result = emu_arm64.call_symbol("zlibVersion")

    assert emu_arm64.read_string(result) == "1.2.8"


@pytest.mark.usefixtures("libz_arm64")
def test_call_address(emu_arm64):
    symbol = emu_arm64.find_symbol("zlibVersion")
    result = emu_arm64.call_address(symbol.address)

    assert emu_arm64.read_string(result) == "1.2.8"
