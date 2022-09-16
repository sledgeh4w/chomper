# Infernum

[![build](https://github.com/Sh4ww/infernum/actions/workflows/tests.yml/badge.svg)](https://github.com/Sh4ww/infernum/actions/workflows/tests.yml)
![PyPI](https://img.shields.io/pypi/v/infernum)
![PyPI - Python Version](https://img.shields.io/pypi/pyversions/infernum)
[![GitHub license](https://img.shields.io/github/license/Sh4ww/infernum)](https://github.com/Sh4ww/infernum/blob/main/LICENSE)

Infernum is a lightweight Android native library emulation framework based on [Unicorn](https://github.com/unicorn-engine/unicorn). It is mainly used to execute the pure algorithm, so it will not provide JNI or file system support. It supports arch ARM and ARM64.

## Requirements

- Python 3.7+
- Unicorn 2.0.0+

## Installation

```
$ pip install infernum
```

## Examples

Load modules and call functions.

```python
from infernum import Infernum
from infernum.const import ARCH_ARM64

# Initialize emulator
emulator = Infernum(ARCH_ARM64)

# Load modules
emulator.load_module("lib64/libz.so")

# Construct arguments
data = b"infernum"

a1 = 0
a2 = emulator.create_buffer(len(data))
a3 = len(data)

emulator.write_bytes(a2, data)

# Call function
result = emulator.call_symbol("crc32", a1, a2, a3)

emulator.logger.info(hex(result))
```

Trace instructions.

```python
from infernum import Infernum
from infernum.const import ARCH_ARM64

# Trace all instructions.
emulator = Infernum(ARCH_ARM64, trace_inst=True)

# Trace instructions in this module.
emulator.load_module("lib64/libz.so", trace_inst=True)
```
