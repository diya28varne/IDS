"""Smoke tests for the ThreatLens package foundation."""

from threatlens import __version__


def test_package_version_is_set() -> None:
    assert __version__ == "0.1.0"


def test_package_importable() -> None:
    import threatlens

    assert threatlens.__name__ == "threatlens"
