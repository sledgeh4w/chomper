import pytest

from chomper.utils import aligned


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
