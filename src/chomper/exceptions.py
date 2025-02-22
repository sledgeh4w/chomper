class ChomperException(Exception):
    """Base class for all Chomper exceptions."""


class EmulatorCrashed(ChomperException):
    """Emulate failed when calling functions."""


class SymbolMissing(ChomperException):
    """Symbol not found from loaded modules."""


class ObjCUnrecognizedSelector(ChomperException):
    """Unrecognized selector sent when calling ObjC."""


class FileNotExist(ChomperException):
    """No such file or directory."""


class FileBadDescriptor(ChomperException):
    """Bad file descriptor."""


class FilePermissionDenied(ChomperException):
    """File access permission denied."""
