class ChomperException(Exception):
    """Base class for all Chomper exceptions."""


class EmulatorCrashed(ChomperException):
    """Emulate failed when calling functions."""


class SymbolMissing(ChomperException):
    """Symbol not found from loaded modules."""


class ObjCUnrecognizedSelector(ChomperException):
    """Unrecognized selector sent when calling ObjC."""
