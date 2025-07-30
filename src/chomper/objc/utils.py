from __future__ import annotations

from typing import TYPE_CHECKING

from chomper.typing import CFObjConvertible, NSObjConvertible

from .runtime import ObjcRuntime

if TYPE_CHECKING:
    from chomper.core import Chomper


# Deprecated
def pyobj2nsobj(emu: Chomper, obj: NSObjConvertible) -> int:
    """Convert Python object to NS object.

    Raises:
        TypeError: If object type is not supported.
    """
    objc = ObjcRuntime(emu)
    return objc._create_ns_object(obj)  # type: ignore


# Deprecated
def pyobj2cfobj(emu: Chomper, obj: CFObjConvertible) -> int:
    """Convert Python object to CF object.

    Raises:
        TypeError: If object type is not supported.
    """
    objc = ObjcRuntime(emu)
    return objc._create_cf_object(obj)
