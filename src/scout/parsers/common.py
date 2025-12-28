from __future__ import annotations

from typing import Any, List, Tuple


def flatten(obj: Any, *, prefix: str = "") -> List[Tuple[str, Any]]:
    """
    Flatten nested dict/list objects into dot-path keys.

    Examples:
      {"a": {"b": 1}}         -> [("a.b", 1)]
      {"a": [ {"b": 2} ]}     -> [("a[0].b", 2)]
    """
    out: List[Tuple[str, Any]] = []

    def _join(p: str, k: str) -> str:
        return k if not p else f"{p}.{k}"

    if isinstance(obj, dict):
        for k, v in obj.items():
            k = str(k)
            out.extend(flatten(v, prefix=_join(prefix, k)))
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            out.extend(flatten(v, prefix=f"{prefix}[{i}]" if prefix else f"[{i}]"))
    else:
        out.append((prefix or "", obj))

    return out


def normalize_key(key: str, *, case_insensitive: bool) -> str:
    k = (key or "").strip()
    return k.lower() if case_insensitive else k