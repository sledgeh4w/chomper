import pytest

from chomper.const import OS_IOS
from chomper.exceptions import SymbolMissing

emu_names = ["emu_arm", "emu_arm64", "emu_ios"]


def call_symbol(emu, symbol_name, *args, va_list=None):
    if emu.os_type == OS_IOS:
        symbol_name = f"_{symbol_name}"

        try:
            emu.find_symbol(symbol_name)
        except SymbolMissing:
            symbol_name = f"__platform{symbol_name}"

    return emu.call_symbol(symbol_name, *args, va_list=va_list)


@pytest.mark.usefixtures("libc_arm", "libc_arm64")
@pytest.mark.parametrize("emu_name", emu_names)
def test_malloc(request, emu_name):
    emu = request.getfixturevalue(emu_name)

    result = call_symbol(emu, "malloc", 16)
    assert result

    emu.free(result)


@pytest.mark.usefixtures("libc_arm", "libc_arm64")
@pytest.mark.parametrize("emu_name", emu_names)
def test_free(request, emu_name):
    emu = request.getfixturevalue(emu_name)

    addr = call_symbol(emu, "malloc", 16)
    call_symbol(emu, "free", addr)


@pytest.mark.usefixtures("libc_arm", "libc_arm64")
@pytest.mark.parametrize("emu_name", emu_names)
def test_memcpy(request, emu_name):
    emu = request.getfixturevalue(emu_name)

    sample_str = "chomper"

    v1 = emu.create_buffer(16)
    v2 = emu.create_string(sample_str)

    try:
        call_symbol(emu, "memcpy", v1, v2, len(sample_str) + 1)
        result = emu.read_string(v1)
        assert result == sample_str
    finally:
        emu.free(v1)
        emu.free(v2)


@pytest.mark.usefixtures("libc_arm", "libc_arm64")
@pytest.mark.parametrize("emu_name", emu_names)
def test_memcmp(request, emu_name):
    emu = request.getfixturevalue(emu_name)

    sample_str = "chomper"

    v1 = emu.create_string(sample_str)
    v2 = emu.create_string(sample_str)
    v3 = emu.create_string(sample_str[::-1])

    try:
        result = call_symbol(emu, "memcmp", v1, v2, len(sample_str))
        assert result == 0

        result = call_symbol(emu, "memcmp", v1, v3, len(sample_str))
        assert result != 0
    finally:
        emu.free(v1)
        emu.free(v2)
        emu.free(v3)


@pytest.mark.usefixtures("libc_arm", "libc_arm64")
@pytest.mark.parametrize("emu_name", emu_names)
def test_memset(request, emu_name):
    emu = request.getfixturevalue(emu_name)

    sample_str = "chomper"
    size = len(sample_str)

    v1 = emu.create_string(sample_str)

    try:
        call_symbol(emu, "memset", v1, 0, size)
        result = emu.read_bytes(v1, size)
        assert result == b"\x00" * size
    finally:
        emu.free(v1)


@pytest.mark.usefixtures("libc_arm", "libc_arm64")
@pytest.mark.parametrize("emu_name", emu_names)
def test_strncpy(request, emu_name):
    emu = request.getfixturevalue(emu_name)

    sample_str = "chomper"

    v1 = emu.create_buffer(16)
    v2 = emu.create_string(sample_str)
    v3 = 5

    emu.write_bytes(v1, b"\x00" * 16)

    try:
        call_symbol(emu, "strncpy", v1, v2, v3)
        result = emu.read_string(v1)
        assert result == sample_str[:v3]
    finally:
        emu.free(v1)
        emu.free(v2)


@pytest.mark.usefixtures("libc_arm", "libc_arm64")
@pytest.mark.parametrize("emu_name", emu_names)
def test_strncmp(request, emu_name):
    emu = request.getfixturevalue(emu_name)

    sample_str = "chomper"

    v1 = emu.create_string(sample_str)
    v2 = emu.create_string(sample_str[:-1] + " ")

    try:
        result = call_symbol(emu, "strncmp", v1, v2, len(sample_str) - 1)
        assert result == 0

        result = call_symbol(emu, "strncmp", v1, v2, len(sample_str))
        assert result != 0
    finally:
        emu.free(v1)
        emu.free(v2)


@pytest.mark.usefixtures("libc_arm", "libc_arm64")
@pytest.mark.parametrize("emu_name", emu_names)
def test_strncat(request, emu_name):
    emu = request.getfixturevalue(emu_name)

    sample_str = "chomper"

    v1 = emu.create_buffer(32)
    v2 = emu.create_string(sample_str)
    v3 = 5

    emu.write_string(v1, sample_str)

    try:
        call_symbol(emu, "strncat", v1, v2, v3)
        result = emu.read_string(v1)
        assert result == sample_str + sample_str[:v3]
    finally:
        emu.free(v1)
        emu.free(v2)


@pytest.mark.usefixtures("libc_arm", "libc_arm64")
@pytest.mark.parametrize("emu_name", emu_names)
def test_strcpy(request, emu_name):
    emu = request.getfixturevalue(emu_name)

    sample_str = "chomper"

    v1 = emu.create_buffer(16)
    v2 = emu.create_string(sample_str)

    try:
        call_symbol(emu, "strcpy", v1, v2)
        result = emu.read_string(v1)
        assert result == sample_str
    finally:
        emu.free(v1)
        emu.free(v2)


@pytest.mark.usefixtures("libc_arm", "libc_arm64")
@pytest.mark.parametrize("emu_name", emu_names)
def test_strcmp(request, emu_name):
    emu = request.getfixturevalue(emu_name)

    sample_str = "chomper"

    v1 = emu.create_string(sample_str)
    v2 = emu.create_string(sample_str)
    v3 = emu.create_string(sample_str[:-1] + " ")

    try:
        result = call_symbol(emu, "strcmp", v1, v2)
        assert result == 0

        result = call_symbol(emu, "strcmp", v1, v3)
        assert result != 0
    finally:
        emu.free(v1)
        emu.free(v2)
        emu.free(v3)


@pytest.mark.usefixtures("libc_arm", "libc_arm64")
@pytest.mark.parametrize("emu_name", emu_names)
def test_strcat(request, emu_name):
    emu = request.getfixturevalue(emu_name)

    sample_str = "chomper"

    v1 = emu.create_buffer(32)
    v2 = emu.create_string(sample_str)

    emu.write_string(v1, sample_str)

    try:
        call_symbol(emu, "strcat", v1, v2)
        result = emu.read_string(v1)
        assert result == sample_str + sample_str
    finally:
        emu.free(v1)
        emu.free(v2)


@pytest.mark.usefixtures("libc_arm", "libc_arm64")
@pytest.mark.parametrize("emu_name", emu_names)
def test_strlen(request, emu_name):
    emu = request.getfixturevalue(emu_name)

    sample_str = "chomper"

    v1 = emu.create_string(sample_str)

    try:
        result = call_symbol(emu, "strlen", v1)
        assert result == len(sample_str)
    finally:
        emu.free(v1)


@pytest.mark.usefixtures("libc_arm", "libc_arm64")
@pytest.mark.parametrize("emu_name", emu_names)
def test_sprintf(request, emu_name):
    emu = request.getfixturevalue(emu_name)

    sample_str = "chomper"
    fmt = "%d%s"

    v1 = emu.create_buffer(16)
    v2 = emu.create_string(fmt)
    v3 = len(sample_str)
    v4 = emu.create_string(sample_str)

    try:
        if emu.os_type == OS_IOS:
            call_symbol(emu, "sprintf", v1, v2, va_list=(v3, v4))
        else:
            call_symbol(emu, "sprintf", v1, v2, v3, v4)

        result = emu.read_string(v1)
        assert result == f"{len(sample_str)}{sample_str}"
    finally:
        emu.free(v1)
        emu.free(v2)
        emu.free(v4)


@pytest.mark.usefixtures("libc_arm", "libc_arm64")
@pytest.mark.parametrize("emu_name", ["emu_ios"])
def test_sscanf(request, emu_name):
    emu = request.getfixturevalue(emu_name)

    num = 1024
    s = "chomper"

    fmt = "%d%s"

    v1 = emu.create_string(f"{num}{s}")
    v2 = emu.create_string(fmt)
    v3 = emu.create_buffer(4)
    v4 = emu.create_buffer(64)

    try:
        call_symbol(emu, "sscanf", v1, v2, va_list=(v3, v4))

        result = emu.read_u32(v3)
        assert result == num

        result = emu.read_string(v4)
        assert result == s
    finally:
        emu.free(v1)
        emu.free(v2)
        emu.free(v3)
        emu.free(v4)


@pytest.mark.usefixtures("libc_arm", "libc_arm64")
@pytest.mark.parametrize("emu_name", ["emu_arm", "emu_arm64"])
def test_printf(request, emu_name):
    emu = request.getfixturevalue(emu_name)

    sample_str = "chomper"
    fmt = "%d%s"

    v1 = emu.create_string(fmt)
    v2 = len(sample_str)
    v3 = emu.create_string(sample_str)

    try:
        call_symbol(emu, "printf", v1, v2, v3)
    finally:
        emu.free(v1)
        emu.free(v3)


@pytest.mark.usefixtures("libc_arm", "libc_arm64")
@pytest.mark.parametrize("emu_name", ["emu_ios"])
def test_time(request, emu_name):
    emu = request.getfixturevalue(emu_name)

    result = call_symbol(emu, "time")
    assert result > 0


@pytest.mark.usefixtures("libc_arm", "libc_arm64")
@pytest.mark.parametrize("emu_name", ["emu_ios"])
def test_getcwd(request, emu_name):
    emu = request.getfixturevalue(emu_name)

    size = 1024
    buf = emu.create_buffer(size)

    try:
        result = call_symbol(emu, "getcwd", buf, size)
        assert result
        assert len(emu.read_string(result))
    finally:
        emu.free(buf)
