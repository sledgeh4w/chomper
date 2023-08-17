import os
import re
import uuid
import zlib

import pytest

from .conftest import android_arm64_path, ios_arm64_path

from chomper import Chomper
from chomper.const import ARCH_ARM64
from chomper.exceptions import EmulatorCrashedException


class TestEmulator:
    @pytest.mark.usefixtures("libc_arm64")
    def test_find_symbol(self, emu_arm64):
        symbol_name = "malloc"
        symbol = emu_arm64.find_symbol(symbol_name)

        assert symbol.name == symbol_name

    def test_locate_address(self, emu_arm64, libc_arm64):
        address = libc_arm64.base + 0x1000
        location = emu_arm64.locate_address(address)

        assert location.module.name == libc_arm64.name

    def test_backtrace(self, emu_arm64, libtiny_v73021_arm64):
        def hook_code(*_):
            locations = emu_arm64.backtrace()
            assert len(locations) != 0

        emu_arm64.add_hook(libtiny_v73021_arm64.base + 0x2BA08, hook_code)

        a1 = emu_arm64.create_buffer(32)
        a2 = emu_arm64.create_buffer(32)
        a3 = emu_arm64.create_buffer(32)

        emu_arm64.call_address(libtiny_v73021_arm64.base + 0x289A4, a1, a2, a3)

    @pytest.mark.usefixtures("libz_arm64")
    def test_add_hook(self, emu_arm64):
        def hook_code(*_):
            user_data["flag"] = True

        symbol = emu_arm64.find_symbol("zlibVersion")
        user_data = {}

        emu_arm64.add_hook(symbol.address, hook_code, user_data=user_data)
        emu_arm64.call_symbol(symbol.name)

        assert user_data.get("flag")

    @pytest.mark.usefixtures("libz_arm64")
    def test_set_and_get_argument(self, emu_arm64):
        arguments = [i for i in range(16)]

        for index, argument in enumerate(arguments):
            emu_arm64.set_argument(index, argument)

        for index, argument in enumerate(arguments):
            assert emu_arm64.get_argument(index) == argument

    @pytest.mark.usefixtures("libz_arm64")
    def test_set_and_get_retval(self, emu_arm64):
        retval = 105

        emu_arm64.set_retval(retval)
        result = emu_arm64.get_retval()

        assert result == retval

    def test_create_buffer(self, emu_arm64):
        result = emu_arm64.create_buffer(1024)

        assert result is not None

    def test_create_string(self, emu_arm64, sample_str):
        result = emu_arm64.create_string(sample_str)

        assert result is not None

    def test_free(self, emu_arm64):
        addr = emu_arm64.create_buffer(1024)
        emu_arm64.free(addr)

    def test_write_and_read_int(self, emu_arm64):
        addr = emu_arm64.create_buffer(1024)
        value = 105

        emu_arm64.write_int(addr, value, size=4)
        result = emu_arm64.read_int(addr, size=4)

        assert result == value

    def test_write_and_read_bytes(self, emu_arm64, sample_bytes):
        addr = emu_arm64.create_buffer(1024)

        emu_arm64.write_bytes(addr, sample_bytes)
        result = emu_arm64.read_bytes(addr, len(sample_bytes))

        assert result == sample_bytes

    def test_write_and_read_string(self, emu_arm64, sample_str):
        addr = emu_arm64.create_buffer(1024)

        emu_arm64.write_string(addr, sample_str)
        result = emu_arm64.read_string(addr)

        assert result == sample_str

    @pytest.mark.usefixtures("libz_arm64")
    def test_call_symbol(self, emu_arm64):
        result = emu_arm64.call_symbol("zlibVersion")

        assert emu_arm64.read_string(result) == "1.2.8"

    @pytest.mark.usefixtures("libz_arm64")
    def test_call_address(self, emu_arm64):
        symbol = emu_arm64.find_symbol("zlibVersion")
        result = emu_arm64.call_address(symbol.address)

        assert emu_arm64.read_string(result) == "1.2.8"

    def test_exec_init_array(self, emu_arm64, libszstone_v4945_arm64):
        assert emu_arm64.read_string(libszstone_v4945_arm64.base + 0x49DD8) == "1.2.3"


class TestEmulateLibc:
    emu_names = ["emu_arm", "emu_arm64"]

    @pytest.mark.usefixtures("libc_arm", "libc_arm64")
    @pytest.mark.parametrize("emu_name", emu_names)
    def test_malloc(self, request, emu_name):
        emu = request.getfixturevalue(emu_name)

        result = emu.call_symbol("malloc", 16)

        assert result != 0

    @pytest.mark.usefixtures("libc_arm", "libc_arm64")
    @pytest.mark.parametrize("emu_name", emu_names)
    def test_free(self, request, emu_name):
        emu = request.getfixturevalue(emu_name)

        addr = emu.call_symbol("malloc", 16)
        emu.call_symbol("free", addr)

    @pytest.mark.usefixtures("libc_arm", "libc_arm64")
    @pytest.mark.parametrize("emu_name", emu_names)
    def test_memcpy(self, request, emu_name, sample_str):
        emu = request.getfixturevalue(emu_name)

        v1 = emu.create_buffer(16)
        v2 = emu.create_string(sample_str)

        emu.call_symbol("memcpy", v1, v2, len(sample_str) + 1)
        result = emu.read_string(v1)

        assert result == sample_str

    @pytest.mark.usefixtures("libc_arm", "libc_arm64")
    @pytest.mark.parametrize("emu_name", emu_names)
    def test_memcmp(self, request, emu_name, sample_str):
        emu = request.getfixturevalue(emu_name)

        v1 = emu.create_string(sample_str)
        v2 = emu.create_string(sample_str)
        v3 = emu.create_string(sample_str[::-1])

        result = emu.call_symbol("memcmp", v1, v2, len(sample_str))

        assert result == 0

        result = emu.call_symbol("memcmp", v1, v3, len(sample_str))

        assert result != 0

    @pytest.mark.usefixtures("libc_arm", "libc_arm64")
    @pytest.mark.parametrize("emu_name", emu_names)
    def test_memset(self, request, emu_name, sample_str):
        emu = request.getfixturevalue(emu_name)

        size = len(sample_str)

        v1 = emu.create_string(sample_str)

        emu.call_symbol("memset", v1, 0, size)
        result = emu.read_bytes(v1, size)

        assert result == b"\x00" * size

    @pytest.mark.usefixtures("libc_arm", "libc_arm64")
    @pytest.mark.parametrize("emu_name", emu_names)
    def test_strncpy(self, request, emu_name, sample_str):
        emu = request.getfixturevalue(emu_name)

        v1 = emu.create_buffer(16)
        v2 = emu.create_string(sample_str)
        v3 = 5

        emu.call_symbol("strncpy", v1, v2, v3)
        result = emu.read_string(v1)

        assert result == sample_str[:v3]

    @pytest.mark.usefixtures("libc_arm", "libc_arm64")
    @pytest.mark.parametrize("emu_name", emu_names)
    def test_strncmp(self, request, emu_name, sample_str):
        emu = request.getfixturevalue(emu_name)

        v1 = emu.create_string(sample_str)
        v2 = emu.create_string(sample_str[:-1] + " ")

        result = emu.call_symbol("strncmp", v1, v2, len(sample_str) - 1)

        assert result == 0

        result = emu.call_symbol("strncmp", v1, v2, len(sample_str))

        assert result != 0

    @pytest.mark.usefixtures("libc_arm", "libc_arm64")
    @pytest.mark.parametrize("emu_name", emu_names)
    def test_strncat(self, request, emu_name, sample_str):
        emu = request.getfixturevalue(emu_name)

        v1 = emu.create_buffer(32)
        v2 = emu.create_string(sample_str)
        v3 = 5

        emu.write_string(v1, sample_str)

        emu.call_symbol("strncat", v1, v2, v3)
        result = emu.read_string(v1)

        assert result == sample_str + sample_str[:v3]

    @pytest.mark.usefixtures("libc_arm", "libc_arm64")
    @pytest.mark.parametrize("emu_name", emu_names)
    def test_strcpy(self, request, emu_name, sample_str):
        emu = request.getfixturevalue(emu_name)

        v1 = emu.create_buffer(16)
        v2 = emu.create_string(sample_str)

        emu.call_symbol("strcpy", v1, v2)
        result = emu.read_string(v1)

        assert result == sample_str

    @pytest.mark.usefixtures("libc_arm", "libc_arm64")
    @pytest.mark.parametrize("emu_name", emu_names)
    def test_strcmp(self, request, emu_name, sample_str):
        emu = request.getfixturevalue(emu_name)

        v1 = emu.create_string(sample_str)
        v2 = emu.create_string(sample_str)
        v3 = emu.create_string(sample_str[:-1] + " ")

        result = emu.call_symbol("strcmp", v1, v2)

        assert result == 0

        result = emu.call_symbol("strcmp", v1, v3)

        assert result != 0

    @pytest.mark.usefixtures("libc_arm", "libc_arm64")
    @pytest.mark.parametrize("emu_name", emu_names)
    def test_strcat(self, request, emu_name, sample_str):
        emu = request.getfixturevalue(emu_name)

        v1 = emu.create_buffer(32)
        v2 = emu.create_string(sample_str)

        emu.write_string(v1, sample_str)

        emu.call_symbol("strcat", v1, v2)
        result = emu.read_string(v1)

        assert result == sample_str + sample_str

    @pytest.mark.usefixtures("libc_arm", "libc_arm64")
    @pytest.mark.parametrize("emu_name", emu_names)
    def test_strlen(self, request, emu_name, sample_str):
        emu = request.getfixturevalue(emu_name)

        v1 = emu.create_string(sample_str)

        result = emu.call_symbol("strlen", v1)

        assert result == len(sample_str)

    @pytest.mark.usefixtures("libc_arm", "libc_arm64")
    @pytest.mark.parametrize("emu_name", emu_names)
    def test_sprintf(self, request, emu_name, sample_str):
        emu = request.getfixturevalue(emu_name)

        fmt = "%d%s"

        v1 = emu.create_buffer(16)
        v2 = emu.create_string(fmt)
        v3 = len(sample_str)
        v4 = emu.create_string(sample_str)

        emu.call_symbol("sprintf", v1, v2, v3, v4)
        result = emu.read_string(v1)

        assert result == f"{len(sample_str)}{sample_str}"

    @pytest.mark.usefixtures("libc_arm", "libc_arm64")
    @pytest.mark.parametrize("emu_name", emu_names)
    def test_printf(self, request, emu_name, sample_str):
        emu = request.getfixturevalue(emu_name)

        fmt = "%d%s"

        v1 = emu.create_string(fmt)
        v2 = len(sample_str)
        v3 = emu.create_string(sample_str)

        emu.call_symbol("printf", v1, v2, v3)


class TestEmulateExamples:
    @pytest.mark.usefixtures("libc_arm", "libz_arm")
    def test_emulate_libdusanwa_v4856_arm(
        self, emu_arm, libdusanwa_v4856_arm, sample_bytes
    ):
        a1 = emu_arm.create_buffer(32)
        a2 = 32
        a3 = emu_arm.create_buffer(32)
        a4 = emu_arm.create_buffer(32)

        emu_arm.write_bytes(a1, sample_bytes)
        emu_arm.write_bytes(a4, sample_bytes)

        emu_arm.call_address((libdusanwa_v4856_arm.base + 0xA588) | 1, a1, a2, a3, a4)
        result = emu_arm.read_bytes(a3, a2)

        assert zlib.crc32(result) == 1148403178

    @pytest.mark.usefixtures("libc_arm64", "libz_arm64")
    def test_emulate_libszstone_v4945_arm64(
        self, emu_arm64, libszstone_v4945_arm64, sample_bytes
    ):
        a1 = emu_arm64.create_buffer(len(sample_bytes))
        a2 = len(sample_bytes)
        a3 = emu_arm64.create_buffer(1024)

        emu_arm64.write_bytes(a1, sample_bytes)

        result_size = emu_arm64.call_address(
            libszstone_v4945_arm64.base + 0x2F1C8, a1, a2, a3
        )
        result = emu_arm64.read_bytes(a3, result_size)

        assert zlib.crc32(result) == 3884391316

    @pytest.mark.usefixtures("libc_arm64", "libz_arm64")
    def test_emulate_libtiny_v73021_arm64(
        self, emu_arm64, libtiny_v73021_arm64, sample_bytes
    ):
        a1 = emu_arm64.create_buffer(32)
        a2 = emu_arm64.create_buffer(32)
        a3 = emu_arm64.create_buffer(32)

        emu_arm64.write_bytes(a1, sample_bytes * 4)
        emu_arm64.write_bytes(a2, sample_bytes * 4)

        emu_arm64.call_address(libtiny_v73021_arm64.base + 0x289A4, a1, a2, a3)
        result = emu_arm64.read_bytes(a3, 32)

        assert zlib.crc32(result) == 4192995551

    def test_emulate_duapp_v581(self, emu_ios, sample_str):
        duapp = emu_ios.load_module(os.path.join(ios_arm64_path, "DUApp"))

        a1 = emu_ios.create_string("ios")
        a2 = emu_ios.create_string(sample_str)
        a3 = len(sample_str)
        a4 = emu_ios.create_string(str(uuid.uuid4()))
        a5 = emu_ios.create_buffer(8)
        a6 = emu_ios.create_buffer(8)
        a7 = emu_ios.create_string("com.siwuai.duapp")

        emu_ios.call_address(duapp.base + 0x109322118, a1, a2, a3, a4, a5, a6, a7)
        result = emu_ios.read_string(emu_ios.read_address(a5))

        assert re.match(r"\w{32}\.[\w=]+\.", result)


class TestExceptions:
    def test_unhandled_system_call_exception(self):
        with pytest.raises(EmulatorCrashedException, match=r"Unhandled system call.*"):
            emu = Chomper(arch=ARCH_ARM64)
            emu.hooks.pop("malloc")

            emu.load_module(os.path.join(android_arm64_path, "libc.so"))

            emu.call_symbol("malloc")

    def test_missing_symbol_required_exception(self, sample_bytes):
        with pytest.raises(EmulatorCrashedException, match=r"Missing symbol.*"):
            emu = Chomper(arch=ARCH_ARM64)
            libszstone = emu.load_module(
                os.path.join(android_arm64_path, "libszstone.so")
            )

            a1 = emu.create_buffer(len(sample_bytes))
            a2 = len(sample_bytes)
            a3 = emu.create_buffer(1024)

            emu.write_bytes(a1, sample_bytes)
            emu.call_address(libszstone.base + 0x289A4, a1, a2, a3)
