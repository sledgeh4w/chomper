# Chomper

[![build](https://github.com/sledgeh4w/chomper/actions/workflows/tests.yml/badge.svg)](https://github.com/sledgeh4w/chomper/actions/workflows/tests.yml)
![PyPI](https://img.shields.io/pypi/v/chomper)
![PyPI - Python Version](https://img.shields.io/pypi/pyversions/chomper)
[![GitHub license](https://img.shields.io/github/license/sledgeh4w/chomper)](https://github.com/sledgeh4w/chomper/blob/main/LICENSE)

Chomper is a lightweight Android native library emulation framework based on [Unicorn](https://github.com/unicorn-engine/unicorn). It focused on performing encryption or decryption, so it doesn't provide support for JNI and file system. It supports architecture ARM and ARM64.

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
emulator = Chomper(ARCH_ARM64)

# Load modules
emulator.load_module("examples/arm64/libz.so")

# Construct arguments
data = b"chomper"

addr = emulator.alloc(data)
size = len(data)

# Call function
emulator.call_symbol("crc32", 0, addr, size)
```

Emulate arch ARM.

```python
from chomper import Chomper
from chomper.const import ARCH_ARM

emulator = Chomper(ARCH_ARM)
```

Read/Write data.

```python
v1 = emulator.alloc(64)
v2 = emulator.alloc_string("chomper")

emulator.write_int(v1, 1)
emulator.read_int(v1)

emulator.write_bytes(v1, b"chomper")
emulator.read_bytes(v1, 8)

emulator.write_string(v2, "chomper")
emulator.read_string(v2)
```

Hook instructions.

```python
def hook_code(uc, address, size, user_data):
    emu = user_data["emulator"]

symbol = emulator.find_symbol("zlibVersion")
emulator.add_hook(symbol.address, hook_code)
```

Trace instructions.

```python
# Trace all instructions
emulator = Chomper(ARCH_ARM64, trace_instr=True)

# Trace instructions in this module
emulator.load_module("examples/arm64/libz.so", trace_instr=True)
```

Execute initialization functions in section `.init_array`.

```python
emulator.load_module("examples/arm64/libszstone.so", exec_init_array=True)
```
