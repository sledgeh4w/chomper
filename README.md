# Infernum

Infernum is a lightweight Android ELF emulation framework. It is mainly used to emulate native algorithm, so it will not provide JNI environment or file system support. It only supports arch ARM64 for now.

## Requirements

- Python 3.7+

## Installation

```
$ pip install infernum
```

## Examples

Load modules and call functions.

```python
from infernum import Infernum

# Initialize emulator
emulator = Infernum()

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

print(hex(result))
```

Trace instructions.

```python
from infernum import Infernum

# Trace all instructions.
emulator = Infernum(trace_all_inst=True)

# Trace instructions in this module.
emulator.load_module("lib64/libz.so", trace_inst=True)
```
