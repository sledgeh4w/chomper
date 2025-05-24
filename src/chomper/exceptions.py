class ChomperException(Exception):
    """Base class for all emulator exceptions."""


class EmulatorCrashed(ChomperException):
    """Emulate failed when calling functions."""


class SymbolMissing(ChomperException):
    """Symbol not found from loaded modules."""


class ObjCUnrecognizedSelector(ChomperException):
    """Unrecognized selector sent when calling ObjC."""


class SystemOperationFailed(ChomperException):
    """System operation failed."""

    def __init__(self, message, error_type):
        super().__init__(message)

        self.error_type = error_type


class ProgramTerminated(ChomperException):
    """Program terminated on its own.

    For example, the system call `exit` may throw this exception.
    """
