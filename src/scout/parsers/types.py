from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional


@dataclass(frozen=True)
class ParsedKV:
    """ A normalized key-value pair from a file."""
    key: str
    value: Any
    line: Optional[int] = None