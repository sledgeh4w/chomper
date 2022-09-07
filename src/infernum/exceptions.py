class SymbolNotFoundException(Exception):
    """Symbol not found from loaded modules."""


class EmulatorCrashedException(Exception):
    """Emulate failed when calling functions."""
