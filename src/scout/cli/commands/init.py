from __future__ import annotations

from pathlib import Path
import typer

from scout.cli.utils.files import ensure_dir, write_file

app = typer.Typer(help="Initialize scout config in the current repo.")


DEFAULT_CONFIG_TOML = """\
[scan]
max_file_bytes = 2000000
redact = true
include_ignored = false
deterministic = true
skip_dirs = [
  ".git",
  ".venv",
  "venv",
  "node_modules",
  "dist",
  "build",
  ".tox",
  ".mypy_cache",
  ".pytest_cache",
  ".ruff_cache",
]

[ui]
# preferred editor launchers (first available wins)
editors = ["cursor", "code", "subl", "zed", "nvim", "vim"]
"""

DEFAULT_RULES_YAML = """\
metadata:
  name: "repo-overrides"
  version: "1"
  description: "Repo-specific overrides for scout. Builtin rules always run; this file can override/extend them."

rules:
  # Example: allowlist template env files
  # - id: "filename.env-files"
  #   type: "filename"
  #   severity: "high"
  #   description: "Detect .env files"
  #   filename:
  #     pattern_type: "regex"
  #     pattern: "(^|/)\\\\.env($|\\\\.)|(^|/).*\\\\.env$|(^|/)env\\\\..+"
  #   allow_paths:
  #     - "**/.env.example"
  #     - "**/.env.template"
  #     - "**/.env.sample"
"""


DEFAULT_GITIGNORE = """\
# secret-scout local artifacts
.secret-scout/.cache/
.secret-scout/cache/
.secret-scout/tmp/

# Baselines (optional: commit if you want)
.secret-scout/baseline.json
.secret-scout/baseline*.json
"""


DEFAULT_README = """\
# scout configuration

This repo uses `scout` to prevent accidental commits of secrets (.env files, private keys, tokens, etc.)

## Files

- `config.toml` — scan behavior
- `rules.yaml` — repo-specific rules/overrides

## Usage

```bash
scout scan path .
```
"""


@app.command("repo")
def init_repo(
    path: Path = typer.Argument(Path("."), help="Repo path to initialize."),
    force: bool = typer.Option(False, "--force", help="Overwrite existing files."),
) -> None:
    root = path.resolve()
    cfg_dir = root / ".secret-scout"
    ensure_dir(cfg_dir)

    write_file(cfg_dir / "config.toml", DEFAULT_CONFIG_TOML, force=force)
    write_file(cfg_dir / "rules.yaml", DEFAULT_RULES_YAML, force=force)
    write_file(cfg_dir / ".gitignore", DEFAULT_GITIGNORE, force=force)
    write_file(cfg_dir / "README.md", DEFAULT_README, force=force)

    typer.echo(f"Initialized {cfg_dir}")
