import pytest

from chomper.exceptions import SymbolMissingException


class TestCStandardLibrary:
    emu_names = ["emu_arm", "emu_arm64", "emu_ios"]

    @staticmethod
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
    def test_malloc(self, request, emu_name):
        emu = request.getfixturevalue(emu_name)

        result = self.call_symbol(emu, emu_name, "malloc", 16)

        assert result != 0

    @pytest.mark.usefixtures("libc_arm", "libc_arm64")
    @pytest.mark.parametrize("emu_name", emu_names)
    def test_free(self, request, emu_name):
        emu = request.getfixturevalue(emu_name)

        addr = self.call_symbol(emu, emu_name, "malloc", 16)
        self.call_symbol(emu, emu_name, "free", addr)

    @pytest.mark.usefixtures("libc_arm", "libc_arm64")
    @pytest.mark.parametrize("emu_name", emu_names)
    def test_memcpy(self, request, emu_name, str_test):
        emu = request.getfixturevalue(emu_name)

        v1 = emu.create_buffer(16)
        v2 = emu.create_string(str_test)

        self.call_symbol(emu, emu_name, "memcpy", v1, v2, len(str_test) + 1)
        result = emu.read_string(v1)

        assert result == str_test

    @pytest.mark.usefixtures("libc_arm", "libc_arm64")
    @pytest.mark.parametrize("emu_name", emu_names)
    def test_memcmp(self, request, emu_name, str_test):
        emu = request.getfixturevalue(emu_name)

        v1 = emu.create_string(str_test)
        v2 = emu.create_string(str_test)
        v3 = emu.create_string(str_test[::-1])

        result = self.call_symbol(emu, emu_name, "memcmp", v1, v2, len(str_test))

        assert result == 0

        result = self.call_symbol(emu, emu_name, "memcmp", v1, v3, len(str_test))

        assert result != 0

    @pytest.mark.usefixtures("libc_arm", "libc_arm64")
    @pytest.mark.parametrize("emu_name", emu_names)
    def test_memset(self, request, emu_name, str_test):
        emu = request.getfixturevalue(emu_name)

        size = len(str_test)

        v1 = emu.create_string(str_test)

        self.call_symbol(emu, emu_name, "memset", v1, 0, size)
        result = emu.read_bytes(v1, size)

        assert result == b"\x00" * size

    @pytest.mark.usefixtures("libc_arm", "libc_arm64")
    @pytest.mark.parametrize("emu_name", emu_names)
    def test_strncpy(self, request, emu_name, str_test):
        emu = request.getfixturevalue(emu_name)

        v1 = emu.create_buffer(16)
        v2 = emu.create_string(str_test)
        v3 = 5

        self.call_symbol(emu, emu_name, "strncpy", v1, v2, v3)
        result = emu.read_string(v1)

        assert result == str_test[:v3]

    @pytest.mark.usefixtures("libc_arm", "libc_arm64")
    @pytest.mark.parametrize("emu_name", emu_names)
    def test_strncmp(self, request, emu_name, str_test):
        emu = request.getfixturevalue(emu_name)

        v1 = emu.create_string(str_test)
        v2 = emu.create_string(str_test[:-1] + " ")

        result = self.call_symbol(emu, emu_name, "strncmp", v1, v2, len(str_test) - 1)

        assert result == 0

        result = self.call_symbol(emu, emu_name, "strncmp", v1, v2, len(str_test))

        assert result != 0

    @pytest.mark.usefixtures("libc_arm", "libc_arm64")
    @pytest.mark.parametrize("emu_name", emu_names)
    def test_strncat(self, request, emu_name, str_test):
        emu = request.getfixturevalue(emu_name)

        v1 = emu.create_buffer(32)
        v2 = emu.create_string(str_test)
        v3 = 5

        emu.write_string(v1, str_test)

        self.call_symbol(emu, emu_name, "strncat", v1, v2, v3)
        result = emu.read_string(v1)

        assert result == str_test + str_test[:v3]

    @pytest.mark.usefixtures("libc_arm", "libc_arm64")
    @pytest.mark.parametrize("emu_name", emu_names)
    def test_strcpy(self, request, emu_name, str_test):
        emu = request.getfixturevalue(emu_name)

        v1 = emu.create_buffer(16)
        v2 = emu.create_string(str_test)

        self.call_symbol(emu, emu_name, "strcpy", v1, v2)
        result = emu.read_string(v1)

        assert result == str_test

    @pytest.mark.usefixtures("libc_arm", "libc_arm64")
    @pytest.mark.parametrize("emu_name", emu_names)
    def test_strcmp(self, request, emu_name, str_test):
        emu = request.getfixturevalue(emu_name)

        v1 = emu.create_string(str_test)
        v2 = emu.create_string(str_test)
        v3 = emu.create_string(str_test[:-1] + " ")

        result = self.call_symbol(emu, emu_name, "strcmp", v1, v2)

        assert result == 0

        result = self.call_symbol(emu, emu_name, "strcmp", v1, v3)

        assert result != 0

    @pytest.mark.usefixtures("libc_arm", "libc_arm64")
    @pytest.mark.parametrize("emu_name", emu_names)
    def test_strcat(self, request, emu_name, str_test):
        emu = request.getfixturevalue(emu_name)

        v1 = emu.create_buffer(32)
        v2 = emu.create_string(str_test)

        emu.write_string(v1, str_test)

        self.call_symbol(emu, emu_name, "strcat", v1, v2)
        result = emu.read_string(v1)

        assert result == str_test + str_test

    @pytest.mark.usefixtures("libc_arm", "libc_arm64")
    @pytest.mark.parametrize("emu_name", emu_names)
    def test_strlen(self, request, emu_name, str_test):
        emu = request.getfixturevalue(emu_name)

        v1 = emu.create_string(str_test)

        result = self.call_symbol(emu, emu_name, "strlen", v1)

        assert result == len(str_test)

    @pytest.mark.usefixtures("libc_arm", "libc_arm64")
    @pytest.mark.parametrize("emu_name", ["emu_arm", "emu_arm64"])
    def test_sprintf(self, request, emu_name, str_test):
        emu = request.getfixturevalue(emu_name)

        fmt = "%d%s"

        v1 = emu.create_buffer(16)
        v2 = emu.create_string(fmt)
        v3 = len(str_test)
        v4 = emu.create_string(str_test)

        self.call_symbol(emu, emu_name, "sprintf", v1, v2, v3, v4)
        result = emu.read_string(v1)

        assert result == f"{len(str_test)}{str_test}"

    @pytest.mark.usefixtures("libc_arm", "libc_arm64")
    @pytest.mark.parametrize("emu_name", ["emu_arm", "emu_arm64"])
    def test_printf(self, request, emu_name, str_test):
        emu = request.getfixturevalue(emu_name)

        fmt = "%d%s"

        v1 = emu.create_string(fmt)
        v2 = len(str_test)
        v3 = emu.create_string(str_test)

        self.call_symbol(emu, emu_name, "printf", v1, v2, v3)
