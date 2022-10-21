import os

import pytest

from infernum import Infernum
from infernum.const import ARCH_ARM, ARCH_ARM64

base_path = os.path.abspath(os.path.dirname(__file__))

lib_path = os.path.join(base_path, "..", "samples/lib")
lib64_path = os.path.join(base_path, "..", "samples/lib64")


@pytest.fixture(scope="module")
def emu_arm():
    yield Infernum(arch=ARCH_ARM)


@pytest.fixture(scope="module")
def clib_arm(emu_arm):
    yield emu_arm.load_module(os.path.join(lib_path, "libc.so"))


@pytest.fixture(scope="module")
def zlib_arm(emu_arm):
    yield emu_arm.load_module(os.path.join(lib_path, "libz.so"))


@pytest.fixture(scope="module")
def sample1lib_arm(emu_arm):
    yield emu_arm.load_module(
        module_file=os.path.join(lib_path, "libsample1.so"),
        exec_init_array=True,
    )


@pytest.fixture(scope="module")
def emu_arm64():
    yield Infernum(arch=ARCH_ARM64)


@pytest.fixture(scope="module")
def clib_arm64(emu_arm64):
    yield emu_arm64.load_module(os.path.join(lib64_path, "libc.so"))


@pytest.fixture(scope="module")
def zlib_arm64(emu_arm64):
    yield emu_arm64.load_module(os.path.join(lib64_path, "libz.so"))


@pytest.fixture(scope="module")
def sample1lib_arm64(emu_arm64):
    yield emu_arm64.load_module(
        module_file=os.path.join(lib64_path, "libsample1.so"),
        exec_init_array=True,
    )


@pytest.fixture(scope="module")
def sample2lib_arm64(emu_arm64):
    yield emu_arm64.load_module(os.path.join(lib64_path, "libsample2.so"))


@pytest.fixture(scope="module")
def sample_str():
    yield "infernum"


@pytest.fixture(scope="module")
def sample_bytes(sample_str):
    yield sample_str.encode("utf-8")
