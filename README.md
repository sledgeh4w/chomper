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

Load modules and call functions.

```python
from chomper import Chomper
from chomper.const import ARCH_ARM64

# Initialize emulator
emu = Chomper(ARCH_ARM64)

# Load modules
emu.load_module("examples/android/arm64/libz.so")

# Construct arguments
s = "chomper"

addr = emu.create_string(s)
size = len(s)

# Call function
emu.call_symbol("crc32", 0, addr, size)
```

Emulate arch ARM.

```python
from chomper import Chomper
from chomper.const import ARCH_ARM

emu = Chomper(ARCH_ARM)
```

Emulate executable files on iOS.

```python
from chomper import Chomper
from chomper.const import ARCH_ARM64
from chomper.loaders import MachOLoader

emu = Chomper(ARCH_ARM64, loader=MachOLoader)

# C standard libraries on iOS
emu.load_module("examples/ios/arm64/libsystem_platform.dylib")
emu.load_module("examples/ios/arm64/libsystem_c.dylib")
emu.load_module("examples/ios/arm64/libsystem_kernel.dylib")
```

Read/Write data.

```python
addr = emu.create_buffer(64)

emu.write_int(addr, 1, size=4)
emu.read_int(addr, size=4)

emu.write_bytes(addr, b"chomper")
emu.read_bytes(addr, 7)

emu.write_string(addr, "chomper")
emu.read_string(addr)
```

Hook instructions.

```python
def hook_code(uc, address, size, user_data):
    pass

symbol = emu.find_symbol("zlibVersion")
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
