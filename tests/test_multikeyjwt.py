"""Package level tests"""
from multikeyjwt import __version__


def test_version() -> None:
    """Make sure version matches expected"""
    assert __version__ == "1.4.2"
