"""ThreatLens web UI assets (Mycelium-inspired investigation console)."""

from pathlib import Path

WEB_DIR = Path(__file__).resolve().parent
STATIC_DIR = WEB_DIR / "static"
INDEX_HTML = WEB_DIR / "index.html"
LIMITS_HTML = WEB_DIR / "limits.html"

__all__ = ["WEB_DIR", "STATIC_DIR", "INDEX_HTML", "LIMITS_HTML"]
