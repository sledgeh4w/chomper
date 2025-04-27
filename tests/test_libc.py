import os
import time

import pytest

from chomper.const import OS_IOS
from chomper.exceptions import SymbolMissing

from .utils import multi_alloc_mem

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

    s = "chomper"

    with multi_alloc_mem(emu, 16, s) as (v1, v2):
        call_symbol(emu, "memcpy", v1, v2, len(s) + 1)
        result = emu.read_string(v1)
        assert result == s


@pytest.mark.usefixtures("libc_arm", "libc_arm64")
@pytest.mark.parametrize("emu_name", emu_names)
def test_memcmp(request, emu_name):
    emu = request.getfixturevalue(emu_name)

    s = "chomper"

    with multi_alloc_mem(emu, s, s, s[::-1]) as (v1, v2, v3):
        result = call_symbol(emu, "memcmp", v1, v2, len(s))
        assert result == 0

        result = call_symbol(emu, "memcmp", v1, v3, len(s))
        assert result != 0


@pytest.mark.usefixtures("libc_arm", "libc_arm64")
@pytest.mark.parametrize("emu_name", emu_names)
def test_memset(request, emu_name):
    emu = request.getfixturevalue(emu_name)

    s = "chomper"
    n = len(s)

    with multi_alloc_mem(emu, s) as (v1,):
        call_symbol(emu, "memset", v1, 0, n)
        result = emu.read_bytes(v1, n)
        assert result == b"\x00" * n


@pytest.mark.usefixtures("libc_arm", "libc_arm64")
@pytest.mark.parametrize("emu_name", emu_names)
def test_strncpy(request, emu_name):
    emu = request.getfixturevalue(emu_name)

    s = "chomper"
    n = 5

    with multi_alloc_mem(emu, b"\x00" * 16, s) as (v1, v2):
        call_symbol(emu, "strncpy", v1, v2, n)
        result = emu.read_string(v1)
        assert result == s[:n]


@pytest.mark.usefixtures("libc_arm", "libc_arm64")
@pytest.mark.parametrize("emu_name", emu_names)
def test_strncmp(request, emu_name):
    emu = request.getfixturevalue(emu_name)

    s = "chomper"

    with multi_alloc_mem(emu, s, s[:-1] + " ") as (v1, v2):
        result = call_symbol(emu, "strncmp", v1, v2, len(s) - 1)
        assert result == 0

        result = call_symbol(emu, "strncmp", v1, v2, len(s))
        assert result != 0


@pytest.mark.usefixtures("libc_arm", "libc_arm64")
@pytest.mark.parametrize("emu_name", emu_names)
def test_strncat(request, emu_name):
    emu = request.getfixturevalue(emu_name)

    s = "chomper"
    n = 5

    with multi_alloc_mem(emu, 32, s) as (v1, v2):
        emu.write_string(v1, s)

        call_symbol(emu, "strncat", v1, v2, n)
        result = emu.read_string(v1)
        assert result == s + s[:n]


@pytest.mark.usefixtures("libc_arm", "libc_arm64")
@pytest.mark.parametrize("emu_name", emu_names)
def test_strcpy(request, emu_name):
    emu = request.getfixturevalue(emu_name)

    s = "chomper"

    with multi_alloc_mem(emu, 16, s) as (v1, v2):
        call_symbol(emu, "strcpy", v1, v2)
        result = emu.read_string(v1)
        assert result == s


@pytest.mark.usefixtures("libc_arm", "libc_arm64")
@pytest.mark.parametrize("emu_name", emu_names)
def test_strcmp(request, emu_name):
    emu = request.getfixturevalue(emu_name)

    s = "chomper"

    with multi_alloc_mem(emu, s, s, s[::-1] + " ") as (v1, v2, v3):
        result = call_symbol(emu, "strcmp", v1, v2)
        assert result == 0

        result = call_symbol(emu, "strcmp", v1, v3)
        assert result != 0


@pytest.mark.usefixtures("libc_arm", "libc_arm64")
@pytest.mark.parametrize("emu_name", emu_names)
def test_strcat(request, emu_name):
    emu = request.getfixturevalue(emu_name)

    s = "chomper"

    with multi_alloc_mem(emu, 32, s) as (v1, v2):
        emu.write_string(v1, s)

        call_symbol(emu, "strcat", v1, v2)
        result = emu.read_string(v1)
        assert result == s + s


@pytest.mark.usefixtures("libc_arm", "libc_arm64")
@pytest.mark.parametrize("emu_name", emu_names)
def test_strlen(request, emu_name):
    emu = request.getfixturevalue(emu_name)

    s = "chomper"

    with multi_alloc_mem(emu, s) as (v1,):
        result = call_symbol(emu, "strlen", v1)
        assert result == len(s)


@pytest.mark.usefixtures("libc_arm", "libc_arm64")
@pytest.mark.parametrize("emu_name", emu_names)
def test_sprintf(request, emu_name):
    emu = request.getfixturevalue(emu_name)

    s = "chomper"
    fmt = "%d%s"

    with multi_alloc_mem(emu, 16, fmt, s) as (v1, v2, v4):
        v3 = len(s)

        if emu.os_type == OS_IOS:
            call_symbol(emu, "sprintf", v1, v2, va_list=(v3, v4))
        else:
            call_symbol(emu, "sprintf", v1, v2, v3, v4)

        result = emu.read_string(v1)
        assert result == f"{len(s)}{s}"


@pytest.mark.parametrize("emu_name", ["emu_ios"])
def test_sscanf(request, emu_name):
    emu = request.getfixturevalue(emu_name)

    s = "chomper"
    n = len(s)
    fmt = "%d%s"

    with multi_alloc_mem(emu, f"{n}{s}", fmt, 4, 64) as (v1, v2, v3, v4):
        call_symbol(emu, "sscanf", v1, v2, va_list=(v3, v4))

        result = emu.read_u32(v3)
        assert result == n

        result = emu.read_string(v4)
        assert result == s


@pytest.mark.usefixtures("libc_arm", "libc_arm64")
@pytest.mark.parametrize("emu_name", ["emu_arm", "emu_arm64", "emu_ios"])
def test_printf(request, emu_name):
    emu = request.getfixturevalue(emu_name)

    s = "chomper"
    n = len(s)
    fmt = "%d%s"

    with multi_alloc_mem(emu, fmt, s) as (v1, v3):
        call_symbol(emu, "printf", v1, n, v3)


@pytest.mark.parametrize("emu_name", ["emu_ios"])
def test_time(request, emu_name):
    emu = request.getfixturevalue(emu_name)

    result = call_symbol(emu, "time")
    assert result >= 0


@pytest.mark.parametrize("emu_name", ["emu_ios"])
def test_getcwd(request, emu_name):
    emu = request.getfixturevalue(emu_name)

    size = 1024

    with multi_alloc_mem(emu, size) as (buf,):
        result = call_symbol(emu, "getcwd", buf, size)
        assert result
        assert len(emu.read_string(result))


@pytest.mark.parametrize("emu_name", ["emu_ios"])
def test_srandom(request, emu_name):
    emu = request.getfixturevalue(emu_name)

    call_symbol(emu, "srandom", 0)


@pytest.mark.parametrize("emu_name", ["emu_ios"])
def test_random(request, emu_name):
    emu = request.getfixturevalue(emu_name)

    result = call_symbol(emu, "random")
    assert result >= 0


@pytest.mark.parametrize("emu_name", ["emu_ios"])
def test_localtime_r(request, emu_name):
    emu = request.getfixturevalue(emu_name)

    with multi_alloc_mem(emu, 8, 100) as (clock, result):
        emu.write_u64(clock, int(time.time()))

        result = call_symbol(emu, "localtime_r", clock, result)
        assert result


@pytest.mark.parametrize("emu_name", ["emu_ios"])
def test_clock(request, emu_name):
    emu = request.getfixturevalue(emu_name)

    result = call_symbol(emu, "clock")
    assert result >= 0


@pytest.mark.parametrize("emu_name", ["emu_ios"])
def test_getpagesize(request, emu_name):
    emu = request.getfixturevalue(emu_name)

    result = call_symbol(emu, "getpagesize")
    assert result >= 0


@pytest.mark.parametrize("emu_name", ["emu_ios"])
def test_gethostid(request, emu_name):
    emu = request.getfixturevalue(emu_name)

    result = call_symbol(emu, "gethostid")
    assert result >= 0


@pytest.mark.parametrize("emu_name", ["emu_ios"])
def test_gethostname(request, emu_name):
    emu = request.getfixturevalue(emu_name)

    name_len = 256

    with multi_alloc_mem(emu, name_len) as (name,):
        result = call_symbol(emu, "gethostname", name, name_len)
        assert result == 0


@pytest.mark.parametrize("emu_name", ["emu_ios"])
def test_getmntinfo(request, emu_name):
    emu = request.getfixturevalue(emu_name)

    with multi_alloc_mem(emu, 8) as (buf,):
        result = call_symbol(emu, "getmntinfo", buf, 0)
        assert result == 0


@pytest.mark.parametrize("emu_name", ["emu_ios"])
def test_read(request, emu_name):
    emu = request.getfixturevalue(emu_name)

    filepath = "/var/tmp/test_read"
    s = "chomper"

    real_path = f"{emu.os.file_system.rootfs_path}/{filepath[1:]}"

    with open(real_path, "w") as f:
        f.write(s)

    with multi_alloc_mem(emu, filepath, 100) as (path, buf):
        fd = call_symbol(emu, "open", path, 0)
        assert fd

        call_symbol(emu, "read", fd, buf, len(s))
        assert emu.read_string(buf) == s

        call_symbol(emu, "close", fd)

    os.remove(real_path)


@pytest.mark.parametrize("emu_name", ["emu_ios"])
def test_write(request, emu_name):
    emu = request.getfixturevalue(emu_name)

    filepath = "/var/tmp/test_write"
    s = "chomper"

    real_path = f"{emu.os.file_system.rootfs_path}/{filepath[1:]}"

    with multi_alloc_mem(emu, filepath, s) as (path, buf):
        fd = call_symbol(emu, "open", path, 0x601, va_list=(0o666,))
        assert fd

        call_symbol(emu, "write", fd, buf, len(s))
        call_symbol(emu, "close", fd)

    with open(real_path, "r") as f:
        assert f.readline() == s

    os.remove(real_path)


@pytest.mark.parametrize("emu_name", ["emu_ios"])
def test_readdir(request, emu_name):
    emu = request.getfixturevalue(emu_name)

    dir_path = "/usr/lib/system"
    real_path = os.path.join(emu.os.rootfs_path, dir_path[1:])

    filenames = os.listdir(real_path)

    with multi_alloc_mem(emu, dir_path) as (path,):
        dirp = emu.call_symbol("_opendir", path)

        while True:
            entry = emu.call_symbol("_readdir", dirp)
            if not entry:
                break

            filename = emu.read_string(entry + 21)
            assert filename in filenames

            filenames.remove(filename)

        emu.call_symbol("_closedir", dirp)

    assert not filenames
