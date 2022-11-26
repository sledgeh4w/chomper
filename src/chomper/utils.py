def aligned(x: int, n: int) -> int:
    """Align ``x`` based on ``n``."""
    return ((x - 1) // n + 1) * n
