from __future__ import annotations

import ctypes
from typing import Callable, TypedDict, Union, TYPE_CHECKING

from unicorn import Uc

if TYPE_CHECKING:
    from chomper.core import Chomper


class UserData(TypedDict):
    emu: Chomper


HookFuncCallable = Union[
    Callable[[Uc, int, int, UserData], int], Callable[[Uc, int, int, UserData], None]
]

SyscallHandleCallable = Callable[["Chomper"], int]

SysctlReturnValue = Union[int, str, ctypes.Structure]

CFObjConvertible = Union[str, bytes, list, dict]
NSObjConvertible = CFObjConvertible
