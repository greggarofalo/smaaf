"""Compatibility wrapper for the refactored IOC/YARA engine."""
from __future__ import annotations

from .ioc import extract_iocs_and_yara

__all__ = ["extract_iocs_and_yara"]
