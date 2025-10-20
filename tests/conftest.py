import os
import pytest

from chomper import Chomper
from chomper.const import ARCH_ARM, ARCH_ARM64, OS_ANDROID, OS_IOS
from chomper.objc import ObjcRuntime

base_path = os.path.abspath(os.path.dirname(__file__))

android_lib_path = os.path.join(base_path, "../rootfs/android/system/lib")
android_lib64_path = os.path.join(base_path, "../rootfs/android/system/lib64")

ios_rootfs_path = os.path.join(base_path, "../rootfs/ios")


@pytest.fixture(scope="module")
def emu_arm():
    emu = Chomper(
        arch=ARCH_ARM,
        os_type=OS_ANDROID,
        rootfs_path=ios_rootfs_path,  # Used for testing file operations
    )
    emu.load_module(os.path.join(android_lib_path, "libc.so"))
    yield emu


@pytest.fixture(scope="module")
def libc_arm(emu_arm):
    yield emu_arm.find_module("libc.so")


@pytest.fixture(scope="module")
def libz_arm(emu_arm):
    yield emu_arm.load_module(os.path.join(android_lib_path, "libz.so"))


@pytest.fixture(scope="module")
def emu_arm64():
    emu = Chomper(
        arch=ARCH_ARM64,
        os_type=OS_ANDROID,
        rootfs_path=ios_rootfs_path,  # Used for testing file operations
    )
    emu.load_module(os.path.join(android_lib64_path, "libc.so"))
    yield emu


@pytest.fixture(scope="module")
def libc_arm64(emu_arm64):
    yield emu_arm64.find_module("libc.so")


@pytest.fixture(scope="module")
def libz_arm64(emu_arm64):
    yield emu_arm64.load_module(os.path.join(android_lib64_path, "libz.so"))


@pytest.fixture(scope="module")
def emu_ios():
    yield Chomper(
        arch=ARCH_ARM64,
        os_type=OS_IOS,
        rootfs_path=ios_rootfs_path,
    )


@pytest.fixture(scope="module")
def objc(emu_ios):
    yield ObjcRuntime(emu_ios)
