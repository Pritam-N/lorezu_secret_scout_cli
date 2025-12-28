from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Optional

from scout.core.models import ScanConfig, UIConfig

# Python 3.11+ has tomllib; for 3.9/3.10 use tomli
try:
    import tomllib  # type: ignore
except ModuleNotFoundError:  # pragma: no cover
    import tomli as tomllib  # type: ignore


# Repo-local config (checked into the repo being scanned)
DEFAULT_REPO_CONFIG_FILES = (
    ".secret-scout/config.toml",
    ".secret-scout/config.toml.example",  # optional convention
)

# Global config (applies on this machine for all scans)
DEFAULT_GLOBAL_CONFIG_FILES = (
    "~/.config/secret-scout/config.toml",
    "~/.secret-scout/config.toml",
)


def _read_toml(path: Path) -> Dict[str, Any]:
    data = tomllib.loads(path.read_text(encoding="utf-8", errors="replace"))
    if not isinstance(data, dict):
        return {}
    return data


def _deep_merge(base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
    """
    Deep-merge override into base (dict-only). Lists/scalars are replaced.
    """
    out = dict(base)
    for k, v in override.items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _deep_merge(out[k], v)  # type: ignore[arg-type]
        else:
            out[k] = v
    return out


def _expand_paths(paths: tuple[str, ...]) -> list[Path]:
    return [Path(p).expanduser().resolve() for p in paths]


def find_repo_config(start_dir: Path) -> Optional[Path]:
    """
    Walk upward to find a repo-local config (works even without git).
    Finds the closest config in parent chain.
    """
    cur = start_dir.resolve()
    for parent in [cur, *cur.parents]:
        for rel in DEFAULT_REPO_CONFIG_FILES:
            p = (parent / rel).resolve()
            if p.exists() and p.is_file():
                return p
    return None


def find_global_config() -> Optional[Path]:
    for p in _expand_paths(DEFAULT_GLOBAL_CONFIG_FILES):
        if p.exists() and p.is_file():
            return p
    return None


@dataclass(frozen=True)
class LoadedConfig:
    config: ScanConfig
    ui_config: UIConfig
    global_path: Optional[Path]
    repo_path: Optional[Path]


def load_scan_config(
    start_dir: Path,
    cli_overrides: Optional[Dict[str, Any]] = None,
) -> LoadedConfig:
    """
    Precedence (lowest -> highest):
      defaults (ScanConfig) ->
      global config ->
      repo config (closest) ->
      cli_overrides
    """
    cli_overrides = cli_overrides or {}

    global_path = find_global_config()
    repo_path = find_repo_config(start_dir)

    merged: Dict[str, Any] = {}

    # Global
    if global_path:
        merged = _deep_merge(merged, _read_toml(global_path))

    # Repo
    if repo_path:
        merged = _deep_merge(merged, _read_toml(repo_path))

    # CLI overrides are expected to be in the same shape as TOML (namespaced)
    merged = _deep_merge(merged, cli_overrides)

    # Extract [scan] section for ScanConfig
    scan_dict = merged.get("scan") or {}
    if not isinstance(scan_dict, dict):
        scan_dict = {}
    config = ScanConfig.model_validate(scan_dict)

    # Extract [ui] section for UIConfig
    ui_dict = merged.get("ui") or {}
    if not isinstance(ui_dict, dict):
        ui_dict = {}
    ui_config = UIConfig.model_validate(ui_dict)

    return LoadedConfig(
        config=config,
        ui_config=ui_config,
        global_path=global_path,
        repo_path=repo_path,
    )
