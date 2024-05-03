import pytest

from chomper.exceptions import SymbolMissingException

emu_names = ["emu_arm", "emu_arm64", "emu_ios"]


def call_symbol(emu, emu_name, symbol_name, *args):
    if emu_name == "emu_ios":
        symbol_name = f"_{symbol_name}"

        try:
            emu.find_symbol(symbol_name)
        except SymbolMissingException:
            symbol_name = f"__platform{symbol_name}"

    return emu.call_symbol(symbol_name, *args)


@pytest.mark.usefixtures("libc_arm", "libc_arm64")
@pytest.mark.parametrize("emu_name", emu_names)
def test_malloc(request, emu_name):
    emu = request.getfixturevalue(emu_name)

    result = call_symbol(emu, emu_name, "malloc", 16)

    assert result != 0


@pytest.mark.usefixtures("libc_arm", "libc_arm64")
@pytest.mark.parametrize("emu_name", emu_names)
def test_free(request, emu_name):
    emu = request.getfixturevalue(emu_name)

    addr = call_symbol(emu, emu_name, "malloc", 16)
    call_symbol(emu, emu_name, "free", addr)


@pytest.mark.usefixtures("libc_arm", "libc_arm64")
@pytest.mark.parametrize("emu_name", emu_names)
def test_memcpy(request, emu_name, input_str):
    emu = request.getfixturevalue(emu_name)

    v1 = emu.create_buffer(16)
    v2 = emu.create_string(input_str)

    call_symbol(emu, emu_name, "memcpy", v1, v2, len(input_str) + 1)
    result = emu.read_string(v1)

    assert result == input_str


@pytest.mark.usefixtures("libc_arm", "libc_arm64")
@pytest.mark.parametrize("emu_name", emu_names)
def test_memcmp(request, emu_name, input_str):
    emu = request.getfixturevalue(emu_name)

    v1 = emu.create_string(input_str)
    v2 = emu.create_string(input_str)
    v3 = emu.create_string(input_str[::-1])

    result = call_symbol(emu, emu_name, "memcmp", v1, v2, len(input_str))

    assert result == 0

    result = call_symbol(emu, emu_name, "memcmp", v1, v3, len(input_str))

    assert result != 0


@pytest.mark.usefixtures("libc_arm", "libc_arm64")
@pytest.mark.parametrize("emu_name", emu_names)
def test_memset(request, emu_name, input_str):
    emu = request.getfixturevalue(emu_name)

    size = len(input_str)

    v1 = emu.create_string(input_str)

    call_symbol(emu, emu_name, "memset", v1, 0, size)
    result = emu.read_bytes(v1, size)

    assert result == b"\x00" * size


@pytest.mark.usefixtures("libc_arm", "libc_arm64")
@pytest.mark.parametrize("emu_name", emu_names)
def test_strncpy(request, emu_name, input_str):
    emu = request.getfixturevalue(emu_name)

    v1 = emu.create_buffer(16)
    v2 = emu.create_string(input_str)
    v3 = 5

    call_symbol(emu, emu_name, "strncpy", v1, v2, v3)
    result = emu.read_string(v1)

    assert result == input_str[:v3]


@pytest.mark.usefixtures("libc_arm", "libc_arm64")
@pytest.mark.parametrize("emu_name", emu_names)
def test_strncmp(request, emu_name, input_str):
    emu = request.getfixturevalue(emu_name)

    v1 = emu.create_string(input_str)
    v2 = emu.create_string(input_str[:-1] + " ")

    result = call_symbol(emu, emu_name, "strncmp", v1, v2, len(input_str) - 1)

    assert result == 0

    result = call_symbol(emu, emu_name, "strncmp", v1, v2, len(input_str))

    assert result != 0


@pytest.mark.usefixtures("libc_arm", "libc_arm64")
@pytest.mark.parametrize("emu_name", emu_names)
def test_strncat(request, emu_name, input_str):
    emu = request.getfixturevalue(emu_name)

    v1 = emu.create_buffer(32)
    v2 = emu.create_string(input_str)
    v3 = 5

    emu.write_string(v1, input_str)

    call_symbol(emu, emu_name, "strncat", v1, v2, v3)
    result = emu.read_string(v1)

    assert result == input_str + input_str[:v3]


@pytest.mark.usefixtures("libc_arm", "libc_arm64")
@pytest.mark.parametrize("emu_name", emu_names)
def test_strcpy(request, emu_name, input_str):
    emu = request.getfixturevalue(emu_name)

    v1 = emu.create_buffer(16)
    v2 = emu.create_string(input_str)

    call_symbol(emu, emu_name, "strcpy", v1, v2)
    result = emu.read_string(v1)

    assert result == input_str


@pytest.mark.usefixtures("libc_arm", "libc_arm64")
@pytest.mark.parametrize("emu_name", emu_names)
def test_strcmp(request, emu_name, input_str):
    emu = request.getfixturevalue(emu_name)

    v1 = emu.create_string(input_str)
    v2 = emu.create_string(input_str)
    v3 = emu.create_string(input_str[:-1] + " ")

    result = call_symbol(emu, emu_name, "strcmp", v1, v2)

    assert result == 0

    result = call_symbol(emu, emu_name, "strcmp", v1, v3)

    assert result != 0


@pytest.mark.usefixtures("libc_arm", "libc_arm64")
@pytest.mark.parametrize("emu_name", emu_names)
def test_strcat(request, emu_name, input_str):
    emu = request.getfixturevalue(emu_name)

    v1 = emu.create_buffer(32)
    v2 = emu.create_string(input_str)

    emu.write_string(v1, input_str)

    call_symbol(emu, emu_name, "strcat", v1, v2)
    result = emu.read_string(v1)

    assert result == input_str + input_str


@pytest.mark.usefixtures("libc_arm", "libc_arm64")
@pytest.mark.parametrize("emu_name", emu_names)
def test_strlen(request, emu_name, input_str):
    emu = request.getfixturevalue(emu_name)

    v1 = emu.create_string(input_str)

    result = call_symbol(emu, emu_name, "strlen", v1)

    assert result == len(input_str)


@pytest.mark.usefixtures("libc_arm", "libc_arm64")
@pytest.mark.parametrize("emu_name", ["emu_arm", "emu_arm64"])
def test_sprintf(request, emu_name, input_str):
    emu = request.getfixturevalue(emu_name)

    fmt = "%d%s"

    v1 = emu.create_buffer(16)
    v2 = emu.create_string(fmt)
    v3 = len(input_str)
    v4 = emu.create_string(input_str)

    call_symbol(emu, emu_name, "sprintf", v1, v2, v3, v4)
    result = emu.read_string(v1)

    assert result == f"{len(input_str)}{input_str}"


@pytest.mark.usefixtures("libc_arm", "libc_arm64")
@pytest.mark.parametrize("emu_name", ["emu_arm", "emu_arm64"])
def test_printf(request, emu_name, input_str):
    emu = request.getfixturevalue(emu_name)

    fmt = "%d%s"

    v1 = emu.create_string(fmt)
    v2 = len(input_str)
    v3 = emu.create_string(input_str)

    call_symbol(emu, emu_name, "printf", v1, v2, v3)
