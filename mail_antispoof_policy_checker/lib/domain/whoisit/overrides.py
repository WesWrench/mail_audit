"""
RDAP endpoint overrides for TLDs not listed (or incorrectly listed) in the
IANA bootstrap data.  The authoritative data now lives in:

    whoisit/data/rdap_overrides.json

This module loads that file at import time and exposes ``iana_overrides`` for
backward-compatibility with the rest of the codebase.
"""

import json
from pathlib import Path

_path = Path(__file__).parent / "data" / "rdap_overrides.json"

try:
    iana_overrides: dict = json.loads(_path.read_text(encoding="utf-8"))
except FileNotFoundError:
    iana_overrides = {}
except Exception as exc:
    import warnings
    warnings.warn(f"Failed to load rdap_overrides.json: {exc}")
    iana_overrides = {}
