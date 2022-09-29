import os

import pytest

from infernum import Infernum
from infernum.const import ARCH_ARM, ARCH_ARM64

base_path = os.path.abspath(os.path.dirname(__file__))

lib_path = os.path.join(base_path, "..", "examples/lib")
lib64_path = os.path.join(base_path, "..", "examples/lib64")


@pytest.fixture(scope="module")
def arm_emu():
    yield Infernum(arch=ARCH_ARM)


@pytest.fixture(scope="module")
def arm_clib(arm_emu):
    yield arm_emu.load_module(os.path.join(lib_path, "libc.so"))


@pytest.fixture(scope="module")
def arm_zlib(arm_emu):
    yield arm_emu.load_module(os.path.join(lib_path, "libz.so"))


@pytest.fixture(scope="module")
def arm_sample1lib(arm_emu):
    yield arm_emu.load_module(
        module_file=os.path.join(lib_path, "libsample1.so"),
        exec_init_array=True,
    )


@pytest.fixture(scope="module")
def arm64_emu():
    yield Infernum(arch=ARCH_ARM64)


@pytest.fixture(scope="module")
def arm64_clib(arm64_emu):
    yield arm64_emu.load_module(os.path.join(lib64_path, "libc.so"))


@pytest.fixture(scope="module")
def arm64_zlib(arm64_emu):
    yield arm64_emu.load_module(os.path.join(lib64_path, "libz.so"))


@pytest.fixture(scope="module")
def arm64_sample1lib(arm64_emu):
    yield arm64_emu.load_module(
        module_file=os.path.join(lib64_path, "libsample1.so"),
        exec_init_array=True,
    )


@pytest.fixture(scope="module")
def arm64_sample2lib(arm64_emu):
    yield arm64_emu.load_module(os.path.join(lib64_path, "libsample2.so"))
