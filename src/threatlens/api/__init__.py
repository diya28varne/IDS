"""Minimal HTTP API for ThreatLens inference.

Start with: ``uvicorn threatlens.api.app:app --host 0.0.0.0 --port 8000``
"""

from threatlens.api.app import create_app

__all__ = ["create_app"]
