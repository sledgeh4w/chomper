from __future__ import annotations

import ctypes
from typing import Callable, Optional, TypedDict, Union, TYPE_CHECKING

from unicorn import Uc

if TYPE_CHECKING:
    from chomper.core import Chomper


class HookContext(TypedDict):
    emu: Chomper
    return_addr: Optional[int]


HookFuncCallable = Union[
    Callable[[Uc, int, int, HookContext], int],
    Callable[[Uc, int, int, HookContext], None],
]

HookMemCallable = Callable[[Uc, int, int, int, int, HookContext], None]

SyscallHandleCallable = Callable[["Chomper"], int]

SysctlReturnValue = Union[int, str, ctypes.Structure]

CFObjConvertible = Union[int, str, bytes, list, dict]
NSObjConvertible = CFObjConvertible
