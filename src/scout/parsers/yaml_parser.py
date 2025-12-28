from __future__ import annotations

from typing import Any, List

from scout.parsers.common import flatten
from scout.parsers.errors import StructuredParseError
from scout.parsers.types import ParsedKV

try:
    import yaml
except Exception:  # pragma: no cover
    yaml = None


def parse_yaml(text: str) -> List[ParsedKV]:
    if yaml is None:
        raise StructuredParseError("Missing dependency: pyyaml")

    try:
        obj = yaml.safe_load(text)
    except Exception as e:
        raise StructuredParseError(f"YAML parse failed: {e}") from e

    # YAML may be a scalar/list; flatten handles it
    kvs = flatten(obj)
    return [ParsedKV(key=k, value=v, line=None) for (k, v) in kvs if k]