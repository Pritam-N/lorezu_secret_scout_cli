from __future__ import annotations

import re
from typing import Any, List

from scout.parsers.errors import StructuredParseError
from scout.parsers.types import ParsedKV


_KEY_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def _unquote(val: str) -> str:
    v = val.strip()
    if len(v) >= 2 and ((v[0] == v[-1] == '"') or (v[0] == v[-1] == "'")):
        v = v[1:-1]
    return v


def parse_dotenv(text: str) -> List[ParsedKV]:
    """
    Parse dotenv files into ParsedKV entries.

    Supported:
      KEY=VALUE
      export KEY=VALUE
      comments (# ...) and blank lines
    """
    out: List[ParsedKV] = []
    if text is None:
        return out

    for idx, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue

        if line.startswith("export "):
            line = line[len("export "):].strip()

        if "=" not in line:
            continue

        key, val = line.split("=", 1)
        key = key.strip()
        val = val.strip()

        # remove trailing inline comments: KEY=val # comment
        # keep if inside quotes (best-effort)
        if "#" in val:
            m = re.match(r"""^(".*?"|'.*?'|[^#]*)(\s+#.*)?$""", val)
            if m:
                val = (m.group(1) or "").strip()

        if not key or not _KEY_RE.match(key):
            continue

        out.append(ParsedKV(key=key, value=_unquote(val), line=idx))

    return out