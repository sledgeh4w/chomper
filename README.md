# Chomper

[![build](https://github.com/sledgeh4w/chomper/actions/workflows/tests.yml/badge.svg)](https://github.com/sledgeh4w/chomper/actions/workflows/tests.yml)
![PyPI](https://img.shields.io/pypi/v/chomper)
![PyPI - Python Version](https://img.shields.io/pypi/pyversions/chomper)
[![GitHub license](https://img.shields.io/github/license/sledgeh4w/chomper)](https://github.com/sledgeh4w/chomper/blob/main/LICENSE)

Chomper is a lightweight emulation framework based on [Unicorn](https://github.com/unicorn-engine/unicorn). It is mainly used to emulate security algorithms in iOS executables and libraries. In addition, it also provides limited support for Android native libraries.

## Features

- Emulation of ELF and Mach-O binaries
- Support for a subset of iOS system libraries (from iOS 14.4.0)

## Requirements

- Python 3.9+
- Unicorn 2.0.0+

## Installation

Install the stable version from PyPI:

```
$ pip install chomper
```

Or install the latest version from GitHub:

```
$ pip install git+https://github.com/sledgeh4w/chomper.git
```

Clone rootfs repository:

```
$ git clone https://github.com/sledgeh4w/rootfs.git
```

## Usage

Emulate iOS executables.

```python
from chomper import Chomper
from chomper.const import ARCH_ARM64, OS_IOS

# For iOS, system libraries will be automatically loaded from `rootfs_path`
emu = Chomper(
    arch=ARCH_ARM64,
    os_type=OS_IOS,
    rootfs_path="rootfs/ios",
)

# Load program
discover = emu.load_module("examples/binaries/ios/com.xingin.discover/8.74/discover")

s = "chomper"

# Construct arguments
a1 = emu.create_string(s)
a2 = len(s)
a3 = emu.create_buffer(120)
a4 = 120
a5 = emu.create_buffer(8)

# Call function
emu.call_address(discover.base + 0x324ef10, a1, a2, a3, a4, a5)
result = emu.read_string(a3)
```

Working with Objective-C.

```python
from chomper import Chomper
from chomper.const import ARCH_ARM64, OS_IOS
from chomper.objc import ObjcRuntime

emu = Chomper(
    arch=ARCH_ARM64,
    os_type=OS_IOS,
    rootfs_path="rootfs/ios",
)

objc = ObjcRuntime(emu)

emu.load_module("examples/binaries/ios/cn.com.scal.sichuanair/zsch")

# Use this context manager to ensure that Objective-C objects can be automatically released
with objc.autorelease_pool():
    # Find class
    zsch_rsa_class = objc.find_class("ZSCHRSA")

    # Create NSString object
    a1 = objc.create_ns_string("chomper")

    # Call Objective-C method
    req_sign = zsch_rsa_class.call_method("getReqSign:", a1)

    # Convert NSString object to C string
    result_ptr = req_sign.call_method("UTF8String")
    result = emu.read_string(result_ptr)
```

Emulate Android native libraries.

```python
from chomper import Chomper
from chomper.const import ARCH_ARM64, OS_ANDROID

emu = Chomper(
    arch=ARCH_ARM64,
    os_type=OS_ANDROID,
    rootfs_path="rootfs/android",
)

# Load dependency libraries
emu.load_module("rootfs/android/system/lib64/libz.so")

libszstone = emu.load_module("examples/binaries/android/com.shizhuang.duapp/libszstone.so")

s = "chomper"

a1 = emu.create_string(s)
a2 = len(s)
a3 = emu.create_buffer(1024)

result_size = emu.call_address(libszstone.base + 0x2F1C8, a1, a2, a3)
result = emu.read_bytes(a3, result_size)
```

## Examples
There are some security algorithm emulation codes in [algorithms](https://github.com/sledgeh4w/chomper/tree/main/examples/algorithms).
