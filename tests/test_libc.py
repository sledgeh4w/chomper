import os
import time

import pytest

from chomper.const import OS_IOS
from chomper.exceptions import SymbolMissing

from .utils import alloc_variables

emu_names = ["emu_arm", "emu_arm64", "emu_ios"]


def call_symbol(emu, symbol_name, *args, va_list=None):
    if emu.os_type == OS_IOS:
        symbol_name = f"_{symbol_name}"

        try:
            emu.find_symbol(symbol_name)
        except SymbolMissing:
            symbol_name = f"__platform{symbol_name}"

    return emu.call_symbol(symbol_name, *args, va_list=va_list)


@pytest.mark.parametrize("emu_name", emu_names)
def test_malloc(request, emu_name):
    emu = request.getfixturevalue(emu_name)

    result = call_symbol(emu, "malloc", 16)
    assert result

    emu.free(result)


@pytest.mark.parametrize("emu_name", emu_names)
def test_free(request, emu_name):
    emu = request.getfixturevalue(emu_name)

    addr = call_symbol(emu, "malloc", 16)
    call_symbol(emu, "free", addr)


@pytest.mark.parametrize("emu_name", emu_names)
def test_memcpy(request, emu_name):
    emu = request.getfixturevalue(emu_name)

    s = "chomper"

    with alloc_variables(emu, 16, s) as (v1, v2):
        call_symbol(emu, "memcpy", v1, v2, len(s) + 1)
        result = emu.read_string(v1)
        assert result == s


@pytest.mark.parametrize("emu_name", emu_names)
def test_memcmp(request, emu_name):
    emu = request.getfixturevalue(emu_name)

    s = "chomper"

    with alloc_variables(emu, s, s, s[::-1]) as (v1, v2, v3):
        result = call_symbol(emu, "memcmp", v1, v2, len(s))
        assert result == 0

        result = call_symbol(emu, "memcmp", v1, v3, len(s))
        assert result != 0


@pytest.mark.parametrize("emu_name", emu_names)
def test_memset(request, emu_name):
    emu = request.getfixturevalue(emu_name)

    s = "chomper"
    n = len(s)

    with alloc_variables(emu, s) as (v1,):
        call_symbol(emu, "memset", v1, 0, n)
        result = emu.read_bytes(v1, n)
        assert result == b"\x00" * n


@pytest.mark.parametrize("emu_name", emu_names)
def test_strncpy(request, emu_name):
    emu = request.getfixturevalue(emu_name)

    s = "chomper"
    n = 5

    with alloc_variables(emu, b"\x00" * 16, s) as (v1, v2):
        call_symbol(emu, "strncpy", v1, v2, n)
        result = emu.read_string(v1)
        assert result == s[:n]


@pytest.mark.parametrize("emu_name", emu_names)
def test_strncmp(request, emu_name):
    emu = request.getfixturevalue(emu_name)

    s = "chomper"

    with alloc_variables(emu, s, s[:-1] + " ") as (v1, v2):
        result = call_symbol(emu, "strncmp", v1, v2, len(s) - 1)
        assert result == 0

        result = call_symbol(emu, "strncmp", v1, v2, len(s))
        assert result != 0


@pytest.mark.parametrize("emu_name", emu_names)
def test_strncat(request, emu_name):
    emu = request.getfixturevalue(emu_name)

    s = "chomper"
    n = 5

    with alloc_variables(emu, 32, s) as (v1, v2):
        emu.write_string(v1, s)

        call_symbol(emu, "strncat", v1, v2, n)
        result = emu.read_string(v1)
        assert result == s + s[:n]


@pytest.mark.parametrize("emu_name", emu_names)
def test_strcpy(request, emu_name):
    emu = request.getfixturevalue(emu_name)

    s = "chomper"

    with alloc_variables(emu, 16, s) as (v1, v2):
        call_symbol(emu, "strcpy", v1, v2)
        result = emu.read_string(v1)
        assert result == s


@pytest.mark.parametrize("emu_name", emu_names)
def test_strcmp(request, emu_name):
    emu = request.getfixturevalue(emu_name)

    s = "chomper"

    with alloc_variables(emu, s, s, s[::-1] + " ") as (v1, v2, v3):
        result = call_symbol(emu, "strcmp", v1, v2)
        assert result == 0

        result = call_symbol(emu, "strcmp", v1, v3)
        assert result != 0


@pytest.mark.parametrize("emu_name", emu_names)
def test_strcat(request, emu_name):
    emu = request.getfixturevalue(emu_name)

    s = "chomper"

    with alloc_variables(emu, 32, s) as (v1, v2):
        emu.write_string(v1, s)

        call_symbol(emu, "strcat", v1, v2)
        result = emu.read_string(v1)
        assert result == s + s


@pytest.mark.parametrize("emu_name", emu_names)
def test_strlen(request, emu_name):
    emu = request.getfixturevalue(emu_name)

    s = "chomper"

    with alloc_variables(emu, s) as (v1,):
        result = call_symbol(emu, "strlen", v1)
        assert result == len(s)


@pytest.mark.parametrize("emu_name", emu_names)
def test_sprintf(request, emu_name):
    emu = request.getfixturevalue(emu_name)

    s = "chomper"
    fmt = "%d%s"

    with alloc_variables(emu, 16, fmt, s) as (v1, v2, v4):
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

    with alloc_variables(emu, f"{n}{s}", fmt, 4, 64) as (v1, v2, v3, v4):
        call_symbol(emu, "sscanf", v1, v2, va_list=(v3, v4))

        result = emu.read_u32(v3)
        assert result == n

        result = emu.read_string(v4)
        assert result == s


@pytest.mark.parametrize("emu_name", emu_names)
def test_printf(request, emu_name):
    emu = request.getfixturevalue(emu_name)

    s = "chomper"
    n = len(s)
    fmt = "%d%s"

    with alloc_variables(emu, fmt, s) as (v1, v3):
        call_symbol(emu, "printf", v1, n, v3)


@pytest.mark.parametrize("emu_name", ["emu_arm64", "emu_ios"])
def test_time(request, emu_name):
    emu = request.getfixturevalue(emu_name)

    result = call_symbol(emu, "time")
    assert result >= 0


@pytest.mark.parametrize("emu_name", ["emu_arm64", "emu_ios"])
def test_getcwd(request, emu_name):
    emu = request.getfixturevalue(emu_name)

    size = 1024

    with alloc_variables(emu, size) as (buf,):
        result = call_symbol(emu, "getcwd", buf, size)
        result_str = emu.read_string(result)

        assert result_str.startswith("/")


@pytest.mark.parametrize("emu_name", ["emu_arm64", "emu_ios"])
def test_srandom(request, emu_name):
    emu = request.getfixturevalue(emu_name)

    call_symbol(emu, "srandom", 0)


@pytest.mark.parametrize("emu_name", ["emu_arm64", "emu_ios"])
def test_random(request, emu_name):
    emu = request.getfixturevalue(emu_name)

    result = call_symbol(emu, "random")
    assert result >= 0


@pytest.mark.parametrize("emu_name", ["emu_arm64", "emu_ios"])
def test_arc4random(request, emu_name):
    emu = request.getfixturevalue(emu_name)

    result = call_symbol(emu, "arc4random")
    assert result >= 0


@pytest.mark.parametrize("emu_name", ["emu_arm64", "emu_ios"])
def test_localtime_r(request, emu_name):
    emu = request.getfixturevalue(emu_name)

    with alloc_variables(emu, 8, 100) as (clock, result):
        emu.write_u64(clock, int(time.time()))

        result = call_symbol(emu, "localtime_r", clock, result)
        assert result


@pytest.mark.parametrize("emu_name", ["emu_arm64", "emu_ios"])
def test_clock(request, emu_name):
    emu = request.getfixturevalue(emu_name)

    result = call_symbol(emu, "clock")
    assert result >= 0


@pytest.mark.parametrize("emu_name", ["emu_arm64", "emu_ios"])
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

    with alloc_variables(emu, name_len) as (name,):
        result = call_symbol(emu, "gethostname", name, name_len)
        assert result == 0


@pytest.mark.parametrize("emu_name", ["emu_ios"])
def test_getmntinfo(request, emu_name):
    emu = request.getfixturevalue(emu_name)

    with alloc_variables(emu, 8) as (buf,):
        result = call_symbol(emu, "getmntinfo", buf, 0)
        assert result == 0


@pytest.mark.parametrize("emu_name", ["emu_arm64", "emu_ios"])
def test_read(request, emu_name):
    emu = request.getfixturevalue(emu_name)

    filepath = "/private/var/tmp/test_read"
    s = "chomper"

    real_path = f"{emu.os.rootfs_path}/{filepath[1:]}"

    with open(real_path, "w") as f:
        f.write(s)

    with alloc_variables(emu, filepath, 100) as (path, buf):
        fd = call_symbol(emu, "open", path, 0)
        assert fd

        call_symbol(emu, "read", fd, buf, len(s))
        assert emu.read_string(buf) == s

        call_symbol(emu, "close", fd)

    os.remove(real_path)


@pytest.mark.parametrize("emu_name", ["emu_arm64", "emu_ios"])
def test_write(request, emu_name):
    emu = request.getfixturevalue(emu_name)

    filepath = "/private/var/tmp/test_write"
    s = "chomper"

    real_path = f"{emu.os.rootfs_path}/{filepath[1:]}"

    with alloc_variables(emu, filepath, s) as (path, buf):

        if emu.os_type == OS_IOS:
            fd = call_symbol(emu, "open", path, 0x601, va_list=(0o666,))
        else:
            fd = call_symbol(emu, "open", path, 0x241, 0o666)

        assert fd

        call_symbol(emu, "write", fd, buf, len(s))
        call_symbol(emu, "close", fd)

    with open(real_path, "r") as f:
        assert f.readline() == s

    os.remove(real_path)


@pytest.mark.parametrize("emu_name", ["emu_arm64", "emu_ios"])
def test_readdir(request, emu_name):
    emu = request.getfixturevalue(emu_name)

    if emu.os_type == OS_IOS:
        name_offset = 0x15
    else:
        name_offset = 0x13

    dir_path = "/usr/lib/system"
    real_path = os.path.join(emu.os.rootfs_path, dir_path[1:])

    filenames = os.listdir(real_path)

    with alloc_variables(emu, dir_path) as (path,):
        dirp = call_symbol(emu, "opendir", path)

        while True:
            entry = call_symbol(emu, "readdir", dirp)
            if not entry:
                break

            filename = emu.read_string(entry + name_offset)
            assert filename in filenames

            filenames.remove(filename)

        call_symbol(emu, "closedir", dirp)

    assert not filenames


@pytest.mark.parametrize("emu_name", ["emu_arm64", "emu_ios"])
def test_mkdir(request, emu_name):
    emu = request.getfixturevalue(emu_name)

    dir_path = "/private/var/tmp/test_mkdir"
    real_path = os.path.join(emu.os.rootfs_path, dir_path[1:])

    with alloc_variables(emu, dir_path) as (path,):
        call_symbol(emu, "mkdir", path, 0o755)

    assert os.path.isdir(real_path)

    os.rmdir(real_path)


@pytest.mark.parametrize("emu_name", ["emu_arm64", "emu_ios"])
def test_access(request, emu_name):
    emu = request.getfixturevalue(emu_name)

    dir_path = "/private/var/tmp"

    with alloc_variables(emu, dir_path) as (path,):
        result = call_symbol(emu, "access", path, 0x4)
        assert result == 0


@pytest.mark.parametrize("emu_name", ["emu_arm64", "emu_ios"])
def test_getpid(request, emu_name):
    emu = request.getfixturevalue(emu_name)

    result = call_symbol(emu, "getpid")
    assert result > 0


@pytest.mark.parametrize("emu_name", ["emu_arm64", "emu_ios"])
def test_getppid(request, emu_name):
    emu = request.getfixturevalue(emu_name)

    result = call_symbol(emu, "getppid")
    assert result > 0


@pytest.mark.parametrize("emu_name", ["emu_arm64", "emu_ios"])
def test_getuid(request, emu_name):
    emu = request.getfixturevalue(emu_name)

    result = call_symbol(emu, "getuid")
    assert result > 0


@pytest.mark.parametrize("emu_name", ["emu_arm64"])
def test_gettid(request, emu_name):
    emu = request.getfixturevalue(emu_name)

    result = call_symbol(emu, "gettid")
    assert result > 0


@pytest.mark.parametrize("emu_name", ["emu_arm64", "emu_ios"])
def test_getenv(request, emu_name):
    emu = request.getfixturevalue(emu_name)

    name = "HOME"

    with alloc_variables(emu, name) as (v1,):
        call_symbol(emu, "getenv", v1)


@pytest.mark.parametrize("emu_name", ["emu_arm64", "emu_ios"])
def test_link(request, emu_name):
    emu = request.getfixturevalue(emu_name)

    work_dir = "/usr/lib"

    link_src = "libobjc.A.dylib"
    link_dst = "libobjc.A.dylib.1"
    link_dst2 = "libobjc.A.dylib.2"

    with alloc_variables(emu, work_dir, link_src, link_dst, link_dst2) as (
        work_dir_p,
        link_src_p,
        link_dst_p,
        link_dst2_p,
    ):
        call_symbol(emu, "chdir", work_dir_p)

        call_symbol(emu, "link", link_src_p, link_dst_p)

        result = call_symbol(emu, "access", link_dst_p, 0x4)
        assert result

        call_symbol(
            emu,
            "linkat",
            emu.os.AT_FDCWD,
            link_src_p,
            emu.os.AT_FDCWD,
            link_dst2_p,
            0,
        )

        result = call_symbol(emu, "access", link_dst2_p, 0x4)
        assert result


@pytest.mark.parametrize("emu_name", ["emu_ios"])
def test_getprogname(request, emu_name):
    emu = request.getfixturevalue(emu_name)

    result = call_symbol(emu, "getprogname")
    emu.read_string(result)


@pytest.mark.parametrize("emu_name", ["emu_ios"])
def test_pthread_mutex(request, emu_name):
    emu = request.getfixturevalue(emu_name)

    with alloc_variables(emu, 64, 64) as (mutex, lock_attr):
        result = call_symbol(emu, "pthread_mutexattr_init", lock_attr)
        assert result == 0

        # PTHREAD_MUTEX_ERRORCHECK=1
        result = call_symbol(emu, "pthread_mutexattr_settype", lock_attr, 1)
        assert result == 0

        result = call_symbol(emu, "pthread_mutex_init", mutex, lock_attr)
        assert result == 0

        result = call_symbol(emu, "pthread_mutex_lock", mutex)
        assert result == 0

        result = call_symbol(emu, "pthread_mutex_unlock", mutex)
        assert result == 0
