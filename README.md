# Chomper

[![build](https://github.com/sledgeh4w/chomper/actions/workflows/tests.yml/badge.svg)](https://github.com/sledgeh4w/chomper/actions/workflows/tests.yml)
![PyPI](https://img.shields.io/pypi/v/chomper)
![PyPI - Python Version](https://img.shields.io/pypi/pyversions/chomper)
[![GitHub license](https://img.shields.io/github/license/sledgeh4w/chomper)](https://github.com/sledgeh4w/chomper/blob/main/LICENSE)

Chomper is a lightweight emulation framework based on [Unicorn](https://github.com/unicorn-engine/unicorn). It is mainly used to emulate iOS executables and libraries. In addition, it also provides limited support for Android native libraries.

## Features

- Basic emulation for ELF and Mach-O
- Support for a set of iOS system libraries (from iOS 14.4.0)

## Requirements

- Python 3.8+
- Unicorn 2.0.0+

## Installation

```
$ pip install chomper
```

## Usage

Emulate iOS executables.

```python
import uuid

from chomper import Chomper
from chomper.const import ARCH_ARM64, OS_IOS

# For iOS, system libraries will be automatically loaded from `rootfs_path`
emu = Chomper(
    arch=ARCH_ARM64,
    os_type=OS_IOS,
    rootfs_path="examples/ios/rootfs",
)

# Load main program
duapp = emu.load_module("examples/ios/apps/com.siwuai.duapp/DUApp")

s = "chomper"

# Construct arguments
a1 = emu.create_string("objc")
a2 = emu.create_string(s)
a3 = len(s)
a4 = emu.create_string(str(uuid.uuid4()))
a5 = emu.create_buffer(8)
a6 = emu.create_buffer(8)
a7 = emu.create_string("com.siwuai.duapp")

# Call function
emu.call_address(duapp.base + 0x109322118, a1, a2, a3, a4, a5, a6, a7)
result = emu.read_string(emu.read_pointer(a5))
```

Working with Objective-C.

```python
from chomper import Chomper
from chomper.const import ARCH_ARM64, OS_IOS
from chomper.objc import ObjC

emu = Chomper(
    arch=ARCH_ARM64,
    os_type=OS_IOS,
    rootfs_path="examples/ios/rootfs",
)

objc = ObjC(emu)

emu.load_module("examples/ios/apps/cn.com.scal.sichuanair/zsch")

# Use this context manager to ensure that Objective-C objects can be automatically released
with objc.autorelease_pool():
    # Construct NSString object
    a1 = objc.msg_send("NSString", "stringWithUTF8String:", "test")

    # Call Objective-C method
    req_sign = objc.msg_send("ZSCHRSA", "getReqSign:", a1)

    # Convert NSString object to C string
    result_ptr = objc.msg_send(req_sign, "cStringUsingEncoding:", 4)
    result = emu.read_string(result_ptr)
```

Emulate Android native libraries.

```python
from chomper import Chomper
from chomper.const import ARCH_ARM64, OS_ANDROID

emu = Chomper(arch=ARCH_ARM64, os_type=OS_ANDROID)

# Load C standard and other libraries
emu.load_module("examples/android/rootfs/system/lib64/libc.so")
emu.load_module("examples/android/rootfs/system/lib64/libz.so")

libszstone = emu.load_module(
    "examples/android/apps/com.shizhuang.duapp/libszstone.so",
    exec_init_array=True,
)

s = "chomper"

a1 = emu.create_string(s)
a2 = len(s)
a3 = emu.create_buffer(1024)

result_size = emu.call_address(libszstone.base + 0x2F1C8, a1, a2, a3)
result = emu.read_bytes(a3, result_size)
```

## Examples
[Here](https://github.com/sledgeh4w/chomper/tree/main/examples) are some encryption emulation examples for security vendors.
