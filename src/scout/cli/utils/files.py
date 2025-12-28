from __future__ import annotations

from pathlib import Path


def ensure_dir(p: Path) -> None:
    p.mkdir(parents=True, exist_ok=True)


def write_file(path: Path, content: str, *, force: bool) -> None:
    if path.exists() and not force:
        return
    path.write_text(content, encoding="utf-8")
