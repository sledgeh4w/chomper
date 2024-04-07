import pytest


class TestCStandardLibrary:
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
    def test_memcpy(self, request, emu_name, str_test):
        emu = request.getfixturevalue(emu_name)

        v1 = emu.create_buffer(16)
        v2 = emu.create_string(str_test)

        emu.call_symbol("memcpy", v1, v2, len(str_test) + 1)
        result = emu.read_string(v1)

        assert result == str_test

    @pytest.mark.usefixtures("libc_arm", "libc_arm64")
    @pytest.mark.parametrize("emu_name", emu_names)
    def test_memcmp(self, request, emu_name, str_test):
        emu = request.getfixturevalue(emu_name)

        v1 = emu.create_string(str_test)
        v2 = emu.create_string(str_test)
        v3 = emu.create_string(str_test[::-1])

        result = emu.call_symbol("memcmp", v1, v2, len(str_test))

        assert result == 0

        result = emu.call_symbol("memcmp", v1, v3, len(str_test))

        assert result != 0

    @pytest.mark.usefixtures("libc_arm", "libc_arm64")
    @pytest.mark.parametrize("emu_name", emu_names)
    def test_memset(self, request, emu_name, str_test):
        emu = request.getfixturevalue(emu_name)

        size = len(str_test)

        v1 = emu.create_string(str_test)

        emu.call_symbol("memset", v1, 0, size)
        result = emu.read_bytes(v1, size)

        assert result == b"\x00" * size

    @pytest.mark.usefixtures("libc_arm", "libc_arm64")
    @pytest.mark.parametrize("emu_name", emu_names)
    def test_strncpy(self, request, emu_name, str_test):
        emu = request.getfixturevalue(emu_name)

        v1 = emu.create_buffer(16)
        v2 = emu.create_string(str_test)
        v3 = 5

        emu.call_symbol("strncpy", v1, v2, v3)
        result = emu.read_string(v1)

        assert result == str_test[:v3]

    @pytest.mark.usefixtures("libc_arm", "libc_arm64")
    @pytest.mark.parametrize("emu_name", emu_names)
    def test_strncmp(self, request, emu_name, str_test):
        emu = request.getfixturevalue(emu_name)

        v1 = emu.create_string(str_test)
        v2 = emu.create_string(str_test[:-1] + " ")

        result = emu.call_symbol("strncmp", v1, v2, len(str_test) - 1)

        assert result == 0

        result = emu.call_symbol("strncmp", v1, v2, len(str_test))

        assert result != 0

    @pytest.mark.usefixtures("libc_arm", "libc_arm64")
    @pytest.mark.parametrize("emu_name", emu_names)
    def test_strncat(self, request, emu_name, str_test):
        emu = request.getfixturevalue(emu_name)

        v1 = emu.create_buffer(32)
        v2 = emu.create_string(str_test)
        v3 = 5

        emu.write_string(v1, str_test)

        emu.call_symbol("strncat", v1, v2, v3)
        result = emu.read_string(v1)

        assert result == str_test + str_test[:v3]

    @pytest.mark.usefixtures("libc_arm", "libc_arm64")
    @pytest.mark.parametrize("emu_name", emu_names)
    def test_strcpy(self, request, emu_name, str_test):
        emu = request.getfixturevalue(emu_name)

        v1 = emu.create_buffer(16)
        v2 = emu.create_string(str_test)

        emu.call_symbol("strcpy", v1, v2)
        result = emu.read_string(v1)

        assert result == str_test

    @pytest.mark.usefixtures("libc_arm", "libc_arm64")
    @pytest.mark.parametrize("emu_name", emu_names)
    def test_strcmp(self, request, emu_name, str_test):
        emu = request.getfixturevalue(emu_name)

        v1 = emu.create_string(str_test)
        v2 = emu.create_string(str_test)
        v3 = emu.create_string(str_test[:-1] + " ")

        result = emu.call_symbol("strcmp", v1, v2)

        assert result == 0

        result = emu.call_symbol("strcmp", v1, v3)

        assert result != 0

    @pytest.mark.usefixtures("libc_arm", "libc_arm64")
    @pytest.mark.parametrize("emu_name", emu_names)
    def test_strcat(self, request, emu_name, str_test):
        emu = request.getfixturevalue(emu_name)

        v1 = emu.create_buffer(32)
        v2 = emu.create_string(str_test)

        emu.write_string(v1, str_test)

        emu.call_symbol("strcat", v1, v2)
        result = emu.read_string(v1)

        assert result == str_test + str_test

    @pytest.mark.usefixtures("libc_arm", "libc_arm64")
    @pytest.mark.parametrize("emu_name", emu_names)
    def test_strlen(self, request, emu_name, str_test):
        emu = request.getfixturevalue(emu_name)

        v1 = emu.create_string(str_test)

        result = emu.call_symbol("strlen", v1)

        assert result == len(str_test)

    @pytest.mark.usefixtures("libc_arm", "libc_arm64")
    @pytest.mark.parametrize("emu_name", emu_names)
    def test_sprintf(self, request, emu_name, str_test):
        emu = request.getfixturevalue(emu_name)

        fmt = "%d%s"

        v1 = emu.create_buffer(16)
        v2 = emu.create_string(fmt)
        v3 = len(str_test)
        v4 = emu.create_string(str_test)

        emu.call_symbol("sprintf", v1, v2, v3, v4)
        result = emu.read_string(v1)

        assert result == f"{len(str_test)}{str_test}"

    @pytest.mark.usefixtures("libc_arm", "libc_arm64")
    @pytest.mark.parametrize("emu_name", emu_names)
    def test_printf(self, request, emu_name, str_test):
        emu = request.getfixturevalue(emu_name)

        fmt = "%d%s"

        v1 = emu.create_string(fmt)
        v2 = len(str_test)
        v3 = emu.create_string(str_test)

        emu.call_symbol("printf", v1, v2, v3)
