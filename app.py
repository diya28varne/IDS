"""Vercel / uvicorn entrypoint for the ThreatLens FastAPI app."""

from threatlens.api.app import app

__all__ = ["app"]
