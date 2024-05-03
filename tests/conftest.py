import os

import pytest

from chomper import Chomper
from chomper.const import ARCH_ARM, ARCH_ARM64, OS_IOS
from chomper.objc import ObjC

base_path = os.path.abspath(os.path.dirname(__file__))

android_lib_path = os.path.join(base_path, "../examples/android/rootfs/system/lib")
android_lib64_path = os.path.join(base_path, "../examples/android/rootfs/system/lib64")

ios_rootfs_path = os.path.join(base_path, "../examples/ios/rootfs")

com_shizhuang_duapp_path = os.path.join(
    base_path, "../examples/android/apps/com.shizhuang.duapp"
)
com_xingin_xhs_path = os.path.join(base_path, "../examples/android/apps/com.xingin.xhs")


@pytest.fixture(scope="module")
def input_str():
    yield "chomper"


@pytest.fixture(scope="module")
def input_bytes(input_str):
    yield input_str.encode("utf-8")


@pytest.fixture(scope="module")
def emu_arm():
    yield Chomper(arch=ARCH_ARM)


@pytest.fixture(scope="module")
def libc_arm(emu_arm):
    yield emu_arm.load_module(os.path.join(android_lib_path, "libc.so"))


@pytest.fixture(scope="module")
def libz_arm(emu_arm):
    yield emu_arm.load_module(os.path.join(android_lib_path, "libz.so"))


@pytest.fixture(scope="module")
def libdusanwa_v4856_arm(emu_arm):
    """From com.shizhuang.duapp 4.85.6"""
    yield emu_arm.load_module(
        module_file=os.path.join(com_shizhuang_duapp_path, "libdusanwa.so"),
        exec_init_array=True,
    )


@pytest.fixture(scope="module")
def emu_arm64():
    yield Chomper(arch=ARCH_ARM64)


@pytest.fixture(scope="module")
def libc_arm64(emu_arm64):
    yield emu_arm64.load_module(os.path.join(android_lib64_path, "libc.so"))


@pytest.fixture(scope="module")
def libz_arm64(emu_arm64):
    yield emu_arm64.load_module(os.path.join(android_lib64_path, "libz.so"))


@pytest.fixture(scope="module")
def libszstone_v4945_arm64(emu_arm64):
    """From com.shizhuang.duapp 4.94.5"""
    yield emu_arm64.load_module(
        module_file=os.path.join(com_shizhuang_duapp_path, "libszstone.so"),
        exec_init_array=True,
    )


@pytest.fixture(scope="module")
def libtiny_v73021_arm64(emu_arm64):
    """From com.xingin.xhs 7.30.2.1"""
    yield emu_arm64.load_module(os.path.join(com_xingin_xhs_path, "libtiny.so"))


@pytest.fixture(scope="module")
def emu_ios():
    yield Chomper(
        arch=ARCH_ARM64,
        os_type=OS_IOS,
        rootfs_path=ios_rootfs_path,
    )


@pytest.fixture(scope="module")
def objc(emu_ios):
    yield ObjC(emu_ios)
