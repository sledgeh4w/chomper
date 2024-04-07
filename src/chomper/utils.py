from ctypes import addressof, create_string_buffer, sizeof, memmove, Structure


def aligned(x: int, n: int) -> int:
    """Align `x` based on `n`."""
    return ((x - 1) // n + 1) * n


def struct2bytes(st: Structure) -> bytes:
    """Convert struct to bytes."""
    buffer = create_string_buffer(sizeof(st))
    memmove(buffer, addressof(st), sizeof(st))
    return buffer.raw
