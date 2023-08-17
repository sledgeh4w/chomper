import os

import pytest

from chomper import Chomper
from chomper.const import ARCH_ARM, ARCH_ARM64
from chomper.loaders import MachOLoader

base_path = os.path.abspath(os.path.dirname(__file__))

android_arm_path = os.path.join(base_path, "../examples/android/arm")
android_arm64_path = os.path.join(base_path, "../examples/android/arm64")
ios_arm64_path = os.path.join(base_path, "../examples/ios/arm64")


@pytest.fixture(scope="module")
def sample_str():
    yield "chomper"


@pytest.fixture(scope="module")
def sample_bytes(sample_str):
    yield sample_str.encode("utf-8")


@pytest.fixture(scope="module")
def emu_arm():
    yield Chomper(arch=ARCH_ARM)


@pytest.fixture(scope="module")
def libc_arm(emu_arm):
    yield emu_arm.load_module(os.path.join(android_arm_path, "libc.so"))


@pytest.fixture(scope="module")
def libz_arm(emu_arm):
    yield emu_arm.load_module(os.path.join(android_arm_path, "libz.so"))


@pytest.fixture(scope="module")
def libdusanwa_v4856_arm(emu_arm):
    """From com.shizhuang.duapp 4.85.6"""
    yield emu_arm.load_module(
        os.path.join(android_arm_path, "libdusanwa.so"),
        exec_init_array=True,
    )


@pytest.fixture(scope="module")
def emu_arm64():
    yield Chomper(arch=ARCH_ARM64)


@pytest.fixture(scope="module")
def libc_arm64(emu_arm64):
    yield emu_arm64.load_module(os.path.join(android_arm64_path, "libc.so"))


@pytest.fixture(scope="module")
def libz_arm64(emu_arm64):
    yield emu_arm64.load_module(os.path.join(android_arm64_path, "libz.so"))


@pytest.fixture(scope="module")
def libszstone_v4945_arm64(emu_arm64):
    """From com.shizhuang.duapp 4.94.5"""
    yield emu_arm64.load_module(
        os.path.join(android_arm64_path, "libszstone.so"),
        exec_init_array=True,
    )


@pytest.fixture(scope="module")
def libtiny_v73021_arm64(emu_arm64):
    """From com.xingin.xhs 7.30.2.1"""
    yield emu_arm64.load_module(os.path.join(android_arm64_path, "libtiny.so"))


@pytest.fixture(scope="module")
def emu_ios():
    emu = Chomper(arch=ARCH_ARM64, loader=MachOLoader)

    emu.load_module(os.path.join(ios_arm64_path, "libsystem_platform.dylib"))
    emu.load_module(os.path.join(ios_arm64_path, "libsystem_c.dylib"))
    emu.load_module(os.path.join(ios_arm64_path, "libsystem_kernel.dylib"))

    yield emu
