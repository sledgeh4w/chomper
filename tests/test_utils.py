import pytest

from chomper.utils import aligned, to_signed


@pytest.mark.parametrize(
    "x,n,expected",
    [
        (0, 1024, 0),
        (1, 1024, 1024),
        (1024, 1024, 1024),
        (1025, 1024, 2048),
    ],
)
def test_aligned(x, n, expected):
    result = aligned(x, n)

    assert result == expected


@pytest.mark.parametrize(
    "value,size,expected",
    [
        (0xFFFFFFFD, 4, -0x3),
        (0xFFFFFFFFFFFFFFF6, 8, -0xA),
        (0xFFFFFFFFFFFFFFF4, 8, -0xC),
    ],
)
def test_to_signed(value, size, expected):
    result = to_signed(value, size)

    assert result == expected
