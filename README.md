# Chomper

[![build](https://github.com/sledgeh4w/chomper/actions/workflows/tests.yml/badge.svg)](https://github.com/sledgeh4w/chomper/actions/workflows/tests.yml)
![PyPI](https://img.shields.io/pypi/v/chomper)
![PyPI - Python Version](https://img.shields.io/pypi/pyversions/chomper)
[![GitHub license](https://img.shields.io/github/license/sledgeh4w/chomper)](https://github.com/sledgeh4w/chomper/blob/main/LICENSE)

Chomper is a lightweight emulation framework for mobile platform (Android, iOS) based on [Unicorn](https://github.com/unicorn-engine/unicorn). It focused on performing encryption or decryption, so it doesn't provide support for JNI, Objective-C and file system. It supports architecture ARM and ARM64.

## Requirements

- Python 3.7+
- Unicorn 2.0.0+

## Installation

```
$ pip install chomper
```

## Usage

Emulate Android native libraries.

```python
from chomper import Chomper
from chomper.const import ARCH_ARM64

# Initialize emulator
emu = Chomper(ARCH_ARM64)

# Load C standard and other libraries
emu.load_module("examples/android/arm64/libc.so")
emu.load_module("examples/android/arm64/libz.so")

# Load main library
libszstone = emu.load_module(
    "examples/android/arm64/libszstone.so", 
    exec_init_array=True,
)

s = "chomper"

# Construct arguments
a1 = emu.create_string(s)
a2 = len(s)
a3 = emu.create_buffer(1024)

# Call function
result_size = emu.call_address(libszstone.base + 0x2F1C8, a1, a2, a3)
result = emu.read_bytes(a3, result_size)
```


Emulate iOS executable files.

```python
import uuid

from chomper import Chomper
from chomper.const import ARCH_ARM64
from chomper.loaders import MachOLoader

emu = Chomper(ARCH_ARM64, loader=MachOLoader)

# C standard libraries on iOS
emu.load_module("examples/ios/arm64/libsystem_platform.dylib")
emu.load_module("examples/ios/arm64/libsystem_c.dylib")
emu.load_module("examples/ios/arm64/libsystem_kernel.dylib")

duapp = emu.load_module("examples/ios/arm64/DUApp")

s = "chomper"

a1 = emu.create_string("ios")
a2 = emu.create_string(s)
a3 = len(s)
a4 = emu.create_string(str(uuid.uuid4()))
a5 = emu.create_buffer(8)
a6 = emu.create_buffer(8)
a7 = emu.create_string("com.siwuai.duapp")

emu.call_address(duapp.base + 0x109322118, a1, a2, a3, a4, a5, a6, a7)
result = emu.read_string(emu.read_address(a5))
```

Hook instructions.

```python
def hook_code(uc, address, size, user_data):
    pass

symbol = emu.find_symbol("strlen")
emu.add_hook(symbol.address, hook_code)
```

Trace instructions.

```python
# Trace all instructions
emu = Chomper(ARCH_ARM64, trace_instr=True)

# Trace instructions in this module
emu.load_module("examples/android/arm64/libz.so", trace_instr=True)
```

Execute initialization functions in section `.init_array`.

```python
emu.load_module("examples/android/arm64/libszstone.so", exec_init_array=True)
```
