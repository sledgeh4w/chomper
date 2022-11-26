class EmulatorCrashedException(Exception):
    """Emulate failed when calling functions."""


class SymbolMissingException(Exception):
    """Symbol not found from loaded modules."""
