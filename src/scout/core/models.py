from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Literal, Optional

from pydantic import BaseModel, Field, HttpUrl, field_validator, model_validator


# ================================
# Enums
# ================================


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class RuleType(str, Enum):
    FILENAME = "filename"
    REGEX = "regex"
    STRUCTURED = "structured"


class MatchScope(str, Enum):
    LINE = "line"
    BLOCK = "block"
    FILE = "file"


class StructuredFormat(str, Enum):
    DOTENV = "dotenv"
    YAML = "yaml"
    JSON = "json"
    TOML = "toml"
    INI = "ini"


class TargetKind(str, Enum):
    LOCAL = "local"
    GITHUB = "github"


class FindingKind(str, Enum):
    FILENAME = "filename"
    CONTENT = "content"
    STRUCTURED = "structured"
    ERROR = "error"


class ValuePolicy(str, Enum):
    ANY = "any"
    NON_EMPTY = "non_empty"
    PLAINTEXT = "plaintext"
    MUST_REFERENCE_ENV = "must_reference_env"
    MUST_REFERENCE_VAULT = "must_reference_vault"


# ================================
# Rule sub-configs
# ================================


class FilenameRuleConfig(BaseModel):
    pattern: str = Field(
        ..., min_length=1, description="Pattern to match against rel_path"
    )
    pattern_type: Literal["regex", "glob"] = Field(default="regex")


class RegexRuleConfig(BaseModel):
    regex: str = Field(
        ..., min_length=1, description="Regex pattern to match against content"
    )
    scope: MatchScope = Field(default=MatchScope.LINE)
    max_matches: int = Field(default=3, ge=1, le=100)
    multiline: bool = Field(
        default=False, description="If scope=file, allow multiline patterns"
    )


class StructuredRuleConfig(BaseModel):
    format: StructuredFormat = Field(...)
    forbidden_keys: List[str] = Field(default_factory=list)
    allowed_keys: List[str] = Field(default_factory=list)
    key_prefixes: List[str] = Field(default_factory=list)

    value_policy: ValuePolicy = Field(default=ValuePolicy.ANY)
    case_insensitive_keys: bool = Field(default=True)


# ================================
# Rule + RuleSet
# ================================


class Rule(BaseModel):
    id: str = Field(..., min_length=3, max_length=200)
    type: RuleType
    severity: Severity = Severity.MEDIUM
    description: str = Field(default="", max_length=2000)
    tags: List[str] = Field(default_factory=list)

    include: List[str] = Field(default_factory=list)
    exclude: List[str] = Field(default_factory=list)

    allow_paths: List[str] = Field(default_factory=list)
    allow_regexes: List[str] = Field(default_factory=list)

    filename: Optional[FilenameRuleConfig] = None
    regex: Optional[RegexRuleConfig] = None
    structured: Optional[StructuredRuleConfig] = None

    enabled: bool = True

    @field_validator("id")
    @classmethod
    def _rule_id_must_be_simple(cls, v: str) -> str:
        if any(c.isspace() for c in v):
            raise ValueError("rule.id must not contain whitespace")
        return v

    @model_validator(mode="after")
    def _validate_type_config(self) -> "Rule":
        if self.type == RuleType.FILENAME and not self.filename:
            raise ValueError("type=filename requires `filename` config")
        if self.type == RuleType.REGEX and not self.regex:
            raise ValueError("type=regex requires `regex` config")
        if self.type == RuleType.STRUCTURED and not self.structured:
            raise ValueError("type=structured requires `structured` config")

        # Ensure only relevant config is set
        if self.type != RuleType.FILENAME and self.filename is not None:
            raise ValueError("`filename` config set but rule.type is not filename")
        if self.type != RuleType.REGEX and self.regex is not None:
            raise ValueError("`regex` config set but rule.type is not regex")
        if self.type != RuleType.STRUCTURED and self.structured is not None:
            raise ValueError("`structured` config set but rule.type is not structured")
        return self


class RulePackMetadata(BaseModel):
    name: str = "custom"
    version: str = "0"
    source: Optional[str] = None
    description: str = ""


class RulePack(BaseModel):
    metadata: RulePackMetadata = Field(default_factory=RulePackMetadata)
    rules: List[Rule] = Field(default_factory=list)


class RuleSet(BaseModel):
    rules: List[Rule] = Field(default_factory=list)

    def by_id(self) -> Dict[str, Rule]:
        return {r.id: r for r in self.rules}

    def enabled(self) -> List[Rule]:
        return [r for r in self.rules if r.enabled]


# ================================
# Scan Targets + file candidates
# ================================


class GitHubTargetMeta(BaseModel):
    org: Optional[str] = None
    user: Optional[str] = None
    repos: Optional[List[str]] = None
    api_base: HttpUrl = "https://api.github.com"  # type: ignore[assignment]


class ScanTarget(BaseModel):
    name: str
    kind: TargetKind
    root_path: str
    meta: Dict[str, Any] = Field(default_factory=dict)


class FileCandidate(BaseModel):
    abs_path: str
    rel_path: str
    size_bytes: int
    is_binary: bool = False

    mime: Optional[str] = None
    extension: Optional[str] = None
    encoding: Optional[str] = None


# ================================
# Findings + results
# ================================


class Finding(BaseModel):
    target: str
    file: str
    kind: FindingKind
    rule_id: str
    severity: Severity

    message: str = ""
    line: Optional[int] = None

    sample: Optional[str] = None
    match_hash: Optional[str] = None

    key: Optional[str] = None
    value_hint: Optional[str] = None

    error: Optional[str] = None


class ScanStats(BaseModel):
    files_considered: int = 0
    files_scanned: int = 0
    files_skipped_binary: int = 0
    files_skipped_too_large: int = 0
    findings: int = 0
    duration_ms: int = 0


class ScanError(BaseModel):
    target: str
    message: str
    detail: Optional[str] = None


class ScanResult(BaseModel):
    started_at: datetime = Field(default_factory=datetime.utcnow)
    finished_at: Optional[datetime] = None

    targets: List[ScanTarget] = Field(default_factory=list)
    findings: List[Finding] = Field(default_factory=list)
    errors: List[ScanError] = Field(default_factory=list)
    stats: ScanStats = Field(default_factory=ScanStats)

    @model_validator(mode="after")
    def _fixup_counts(self) -> "ScanResult":
        self.stats.findings = len(self.findings)
        return self


# ================================
# Scan config (defaults only)
# ================================

DEFAULT_SKIP_DIRS = [
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

DEFAULT_MAX_FILE_BYTES = 2_000_000


class ScanConfig(BaseModel):
    """
    Defaults live here.
    Repo/global/CLI overrides are merged by core/config.py (do NOT load config in defaults).
    """

    max_file_bytes: int = Field(default=DEFAULT_MAX_FILE_BYTES, ge=1)
    skip_dirs: List[str] = Field(default_factory=lambda: list(DEFAULT_SKIP_DIRS))
    redact: bool = True
    include_ignored: bool = False
    deterministic: bool = True


# ================================
# UI config (defaults only)
# ================================

DEFAULT_EDITORS = ["cursor", "code", "subl", "zed", "nvim", "vim"]


class UIConfig(BaseModel):
    """
    UI preferences. Defaults live here.
    Repo/global/CLI overrides are merged by core/config.py.
    """

    editors: List[str] = Field(
        default_factory=lambda: list(DEFAULT_EDITORS),
        description="Preferred editor launchers. First match wins. Can also override at runtime with SCOUT_EDITOR, VISUAL, or EDITOR.",
    )
