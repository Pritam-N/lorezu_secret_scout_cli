# Configuration

Secret Scout uses a layered configuration system with the following precedence (lowest to highest):

1. **Built-in defaults**
2. **Global config** (`~/.config/secret-scout/`)
3. **Repo config** (`.secret-scout/`)
4. **CLI options**

## Config File

Create `.secret-scout/config.toml` in your repository:

```toml
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
]

[ui]
# Preferred editor launchers. First match wins.
# You can also override at runtime with SCOUT_EDITOR, VISUAL, or EDITOR.
editors = ["cursor", "code", "subl", "zed", "nvim", "vim"]
```

### Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `max_file_bytes` | int | `2000000` | Skip files larger than this |
| `redact` | bool | `true` | Redact secret values in output |
| `include_ignored` | bool | `false` | Scan git-ignored files |
| `deterministic` | bool | `true` | Sort output for reproducibility |
| `skip_dirs` | list | (see above) | Directories to skip |

### UI Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `editors` | list | `["cursor", "code", "subl", "zed", "nvim", "vim"]` | Preferred editor launchers for opening findings. First match wins. Can also override at runtime with `SCOUT_EDITOR`, `VISUAL`, or `EDITOR` environment variables. |

---

## Rules File

Create `.secret-scout/rules.yaml` to customize or override rules:

```yaml
metadata:
  name: "repo-overrides"
  version: "1"
  description: "Repo-specific rule overrides"

rules:
  # Disable a built-in rule
  - id: "regex.generic-secret-assignments"
    enabled: false

  # Lower severity for this repo
  - id: "filename.env-files"
    type: "filename"
    severity: "medium"
    description: "Downgraded for this repo"
    tags: ["env", "filename"]
    filename:
      pattern_type: "regex"
      pattern: "(^|/)\\.env($|\\.)|(^|/).*\\.env$|(^|/)env\\..+"
    allow_paths:
      - "**/.env.example"
      - "**/.env.template"
```

---

## Rule Types

### Filename Rules

Match files by name pattern:

```yaml
- id: "my-filename-rule"
  type: "filename"
  severity: "high"
  description: "Detect sensitive files"
  filename:
    pattern_type: "regex"  # or "glob"
    pattern: "\\.secret$"
  allow_paths:
    - "**/test/**"
```

### Regex Rules

Match file content with regular expressions:

```yaml
- id: "my-regex-rule"
  type: "regex"
  severity: "high"
  description: "Detect API keys"
  regex:
    regex: "\\bAPI_KEY=[A-Za-z0-9]{32}\\b"
    scope: "line"  # or "file"
    max_matches: 5
    multiline: false
```

### Structured Rules

Parse and inspect structured files:

```yaml
- id: "my-structured-rule"
  type: "structured"
  severity: "high"
  description: "Detect secrets in config files"
  include:
    - "**/.env"
    - "**/*.env"
  structured:
    format: "dotenv"  # or yaml, json, toml, ini
    value_policy: "non_empty"
    forbidden_keys:
      - "SECRET_KEY"
      - "API_TOKEN"
```

---

## Severity Levels

| Level | Description |
|-------|-------------|
| `critical` | Immediate security risk (private keys, credentials) |
| `high` | Likely secrets (API keys, tokens) |
| `medium` | Possible secrets (heuristic matches) |
| `low` | Informational findings |

---

## Allowlists

Reduce false positives with allowlists:

```yaml
- id: "my-rule"
  # ... rule config ...
  allow_paths:
    - "**/test/**"
    - "**/*.example"
  allow_regexes:
    - "^placeholder$"
    - "^dummy_"
```

