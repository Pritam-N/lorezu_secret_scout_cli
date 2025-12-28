from __future__ import annotations

import configparser
from typing import List

from scout.parsers.errors import StructuredParseError
from scout.parsers.types import ParsedKV


def parse_ini(text: str) -> List[ParsedKV]:
    """
    INI -> entries like:
      section.key = value
      DEFAULT.key = value (if present)
    """
    cp = configparser.ConfigParser(interpolation=None)
    try:
        cp.read_string(text)
    except Exception as e:
        raise StructuredParseError(f"INI parse failed: {e}") from e

    out: List[ParsedKV] = []

    # DEFAULT section
    for k, v in cp.defaults().items():
        out.append(ParsedKV(key=f"DEFAULT.{k}", value=v, line=None))

    for section in cp.sections():
        for k, v in cp.items(section):
            out.append(ParsedKV(key=f"{section}.{k}", value=v, line=None))

    return out