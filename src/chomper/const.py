import sys

if sys.version_info >= (3, 8):
    from typing import Literal
else:
    from typing_extensions import Literal

# Endian type
EndianType = Literal["little", "big"]

BIG_ENDIAN: Literal["big"] = "big"
LITTLE_ENDIAN: Literal["little"] = "little"

# Supported arch
ARCH_ARM = 1
ARCH_ARM64 = 2

MODE_ARM = 1
MODE_THUMB = 2

# Supported os type
OS_ANDROID = 1
OS_IOS = 2

# The address of thread local storage (TLS)
TLS_ADDRESS = 0x10000
TLS_SIZE = 0x10000

# The address of stack
STACK_ADDRESS = 0x50000
STACK_SIZE = 0x50000

# The address of module
MODULE_ADDRESS = 0x10000000

# The address of heap
HEAP_ADDRESS = 0x8000000

# Minimum size of memory pool
MINIMUM_POOL_SIZE = 2**16

# Memory hook type
HOOK_MEM_READ = 0
HOOK_MEM_WRITE = 1