from __future__ import annotations

from typing import Any, List

from scout.parsers.common import flatten
from scout.parsers.errors import StructuredParseError
from scout.parsers.types import ParsedKV

try:
    import tomllib  # py3.11+
except ModuleNotFoundError:  # pragma: no cover
    import tomli as tomllib  # type: ignore


def parse_toml(text: str) -> List[ParsedKV]:
    try:
        obj = tomllib.loads(text)
    except Exception as e:
        raise StructuredParseError(f"TOML parse failed: {e}") from e

    kvs = flatten(obj)
    return [ParsedKV(key=k, value=v, line=None) for (k, v) in kvs if k]