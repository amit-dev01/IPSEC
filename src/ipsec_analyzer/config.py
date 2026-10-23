"""Backwards-compatible re-export; canonical settings live in `core.config`."""

from ipsec_analyzer.core.config import Environment, Settings, get_settings

__all__ = ["Environment", "Settings", "get_settings"]
