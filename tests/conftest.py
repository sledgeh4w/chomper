import os
import urllib.request
from pathlib import Path

import pytest

from chomper import Chomper
from chomper.const import ARCH_ARM, ARCH_ARM64, OS_IOS
from chomper.objc import ObjC

base_path = os.path.abspath(os.path.dirname(__file__))

android_lib_path = os.path.join(base_path, "../rootfs/android/system/lib")
android_lib64_path = os.path.join(base_path, "../rootfs/android/system/lib64")

ios_rootfs_path = os.path.join(base_path, "../rootfs/ios")

android_binaries_path = os.path.join(base_path, "../examples/binaries/android")
ios_binaries_path = os.path.join(base_path, "../examples/binaries/ios")


def download_binary_file(binary_path: str) -> str:
    filepath = os.path.join(base_path, "..", binary_path)

    path = Path(filepath).resolve()
    if path.exists():
        return filepath

    if not path.parent.exists():
        path.parent.mkdir(parents=True)

    url = "https://sourceforge.net/projects/chomper-emu/files/%s/download" % binary_path

    print(f"Downloading file: {url}")
    urllib.request.urlretrieve(url, path)

    return filepath


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
    """From com.shizhuang.duapp v4.85.6"""
    module_path = download_binary_file(
        binary_path="examples/binaries/android/com.shizhuang.duapp/libdusanwa.so"
    )

    yield emu_arm.load_module(
        module_file=module_path,
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
    """From com.shizhuang.duapp v4.94.5"""
    module_path = download_binary_file(
        binary_path="examples/binaries/android/com.shizhuang.duapp/libszstone.so"
    )

    yield emu_arm64.load_module(
        module_file=module_path,
        exec_init_array=True,
    )


@pytest.fixture(scope="module")
def libtiny_v73021_arm64(emu_arm64):
    """From com.xingin.xhs v7.30.2.1"""
    module_path = download_binary_file(
        binary_path="examples/binaries/android/com.xingin.xhs/libtiny.so"
    )

    yield emu_arm64.load_module(module_path)


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
