"""Path and reproducibility conventions for recorded network-flow data."""

from __future__ import annotations

from pathlib import Path

# Fixed seed for any shuffle/split in this package. Training code should reuse it.
DEFAULT_RANDOM_SEED = 42

# Relative to the repository root (the folder that contains pyproject.toml).
RAW_DATA_DIRNAME = "data"
RAW_SUBDIR = "raw"


def project_root() -> Path:
    """Return the repository root (parent of ``src/``)."""
    # src/threatlens/data/config.py -> parents: data, threatlens, src, repo
    return Path(__file__).resolve().parents[3]


def raw_data_dir() -> Path:
    """Directory where large recorded datasets should be placed locally.

    Files here are gitignored. Tests use small fixtures under ``tests/fixtures/``.
    """
    return project_root() / RAW_DATA_DIRNAME / RAW_SUBDIR


def processed_data_dir() -> Path:
    """Directory for cleaned CSV copies. Raw files are never written here."""
    return project_root() / RAW_DATA_DIRNAME / "processed"
