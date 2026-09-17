"""Governed async vulnerability assessment with bounded active validation."""
from __future__ import annotations

from .engine import run_scan, run_scan_sync
from .scope import Scope, ScopeError, guard
from .findings import Finding, Report

__version__ = '2.0.0'
__all__ = ['run_scan','run_scan_sync','Scope','ScopeError','guard','Finding','Report']
