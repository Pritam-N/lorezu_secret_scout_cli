from __future__ import annotations

import json
from typing import List

from scout.parsers.common import flatten
from scout.parsers.errors import StructuredParseError
from scout.parsers.types import ParsedKV


def parse_json(text: str) -> List[ParsedKV]:
    try:
        obj = json.loads(text)
    except Exception as e:
        raise StructuredParseError(f"JSON parse failed: {e}") from e

    kvs = flatten(obj)
    return [ParsedKV(key=k, value=v, line=None) for (k, v) in kvs if k]