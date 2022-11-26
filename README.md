# Chomper

[![build](https://github.com/sh4w1/chomper/actions/workflows/tests.yml/badge.svg)](https://github.com/sh4w1/chomper/actions/workflows/tests.yml)
![PyPI](https://img.shields.io/pypi/v/chomper)
![PyPI - Python Version](https://img.shields.io/pypi/pyversions/chomper)
[![GitHub license](https://img.shields.io/github/license/sh4w1/chomper)](https://github.com/sh4w1/chomper/blob/main/LICENSE)

Chomper is a lightweight Android native library emulation framework based on [Unicorn](https://github.com/unicorn-engine/unicorn). It is mainly used to execute the encryption algorithm, so it doesn't provide JNI or file system support. It supports arch ARM and ARM64.

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
emulator.load_module("lib64/libz.so")

# Construct arguments
data = b"chomper"

v1 = emulator.create_buffer(len(data))
v2 = len(data)

emulator.write_bytes(v1, data)

# Call function by symbol
emulator.call_symbol("crc32", 0, v1, v2)

# Call function by address
symbol = emulator.find_symbol("crc32")
emulator.call_address(symbol.address, 0, v1, v2)
```

Emulate arch ARM.

```python
from chomper import Chomper
from chomper.const import ARCH_ARM

emulator = Chomper(ARCH_ARM)
```

Read/Write data.

```python
# Create buffer
v1 = emulator.create_buffer(64)
v2 = emulator.create_string("chomper")

# Write data
emulator.write_int(v1, 1)
emulator.write_bytes(v1, b"chomper")
emulator.write_string(v2, "chomper")

# Read data
emulator.read_int(v1)
emulator.read_bytes(v1, 8)
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
emulator = Chomper(ARCH_ARM64, trace_inst=True)

# Trace instructions in this module
emulator.load_module("lib64/libz.so", trace_inst=True)
```

Execute initialization functions in section `.init_array`.

```python
emulator.load_module("lib64/libsample1.so", exec_init_array=True)
```
