from __future__ import annotations

import json
import re
from typing import Callable, Dict, Iterable, List, Optional

from scout.core.matcher import (
    any_glob_match,
    is_path_included,
    normalize_rel_path,
    regex_finditer,
    regex_search,
)
from scout.core.models import (
    FileCandidate,
    Finding,
    FindingKind,
    MatchScope,
    Rule,
    RuleSet,
    RuleType,
    ScanConfig,
    ValuePolicy,
)
from scout.core.redaction import redact_value, stable_hash, truncate

# Structured parsing expects normalized entries (key, value, optional line)
# Keep this protocol minimal so parsers can live outside core.
class ParsedKV:
    __slots__ = ("key", "value", "line")

    def __init__(self, key: str, value: object, line: Optional[int] = None) -> None:
        self.key = key
        self.value = value
        self.line = line


TextReader = Callable[[FileCandidate], Optional[str]]
StructuredParser = Callable[[str], Iterable[ParsedKV]]  # <-- IMPORTANT


def _candidate_rel_path(c: FileCandidate) -> str:
    # support both attribute spellings
    rel = getattr(c, "rel_path", None) or getattr(c, "relative_path", None) or ""
    return normalize_rel_path(str(rel))


def _candidate_abs_path(c: FileCandidate) -> str:
    return str(getattr(c, "abs_path", None) or getattr(c, "absolute_path", None) or "")


def evaluate_file(
    *,
    target_name: str,
    candidate: FileCandidate,
    ruleset: RuleSet,
    config: ScanConfig,
    read_text: TextReader,
    structured_parsers: Optional[Dict[str, StructuredParser]] = None,
) -> List[Finding]:
    """
    Evaluate a single file candidate against enabled rules.

    Notes:
    - Never returns raw secrets if config.redact=True.
    - Always attaches match_hash for baselines/deduping.
    """
    findings: List[Finding] = []
    rel = _candidate_rel_path(candidate)

    for rule in ruleset.enabled():
        # include/exclude filters
        if not is_path_included(rel, rule.include, rule.exclude):
            continue

        # allow-path suppressions
        if rule.allow_paths and any_glob_match(rel, rule.allow_paths):
            continue

        if rule.type == RuleType.FILENAME:
            findings.extend(_eval_filename_rule(target_name, rel, rule))

        elif rule.type == RuleType.REGEX:
            text = read_text(candidate)
            if not text:
                continue
            findings.extend(_eval_regex_rule(target_name, rel, rule, text, redact=config.redact))

        elif rule.type == RuleType.STRUCTURED:
            if not rule.structured or not structured_parsers:
                continue

            fmt = getattr(rule.structured.format, "value", str(rule.structured.format))
            parser = structured_parsers.get(fmt)
            if parser is None:
                continue

            text = read_text(candidate)
            if not text:
                continue

            findings.extend(
                _eval_structured_rule(
                    target=target_name,
                    rel_path=rel,
                    rule=rule,
                    text=text,
                    parser=parser,
                    redact=config.redact,
                )
            )

    return findings


# ----------------------------
# Filename rule
# ----------------------------

def _eval_filename_rule(target: str, rel_path: str, rule: Rule) -> List[Finding]:
    assert rule.filename is not None

    if rule.filename.pattern_type == "glob":
        matched = any_glob_match(rel_path, [rule.filename.pattern])
    else:
        matched = regex_search(rule.filename.pattern, rel_path) is not None

    if not matched:
        return []

    return [
        Finding(
            target=target,
            file=rel_path,
            kind=FindingKind.FILENAME,
            rule_id=rule.id,
            severity=rule.severity,
            message=rule.description or "Suspicious filename detected",
            match_hash=stable_hash(rule.id, rel_path, "filename"),
        )
    ]


# ----------------------------
# Regex rule helpers
# ----------------------------

def _allow_regex_suppresses(rule: Rule, text: str) -> bool:
    if not rule.allow_regexes:
        return False
    for arx in rule.allow_regexes:
        try:
            if re.search(arx, text, flags=re.IGNORECASE):
                return True
        except re.error:
            # allowlist regex should already be validated; ignore safely
            continue
    return False


def _safe_sample(sample: str, *, redact: bool) -> str:
    s = truncate((sample or "").strip(), max_len=160)
    return redact_value(s) if redact else s


def _flags_for_regex(rule: Rule) -> int:
    assert rule.regex is not None
    flags = re.IGNORECASE
    # model field is multi_line (not multiline)
    if getattr(rule.regex, "multi_line", False):
        flags |= re.MULTILINE | re.DOTALL
    return flags


def _line_for_offset(text: str, offset: int) -> int:
    # best-effort: count newlines before offset
    if offset <= 0:
        return 1
    return text.count("\n", 0, offset) + 1


def _eval_regex_rule(target: str, rel_path: str, rule: Rule, text: str, *, redact: bool) -> List[Finding]:
    assert rule.regex is not None

    flags = _flags_for_regex(rule)
    out: List[Finding] = []

    scope = rule.regex.scope

        # Backward/forward compatibility
    scope_val = getattr(scope, "value", str(scope)).lower()
    if scope_val not in ("line", "block", "file"):
        scope_val = "line"

    # FILE scope: match against whole file string (no line numbers)
    if scope == MatchScope.FILE:
        count = 0
        for m in regex_finditer(rule.regex.regex, text, flags=flags):
            raw = m.group(0)
            if _allow_regex_suppresses(rule, raw):
                continue

            out.append(
                Finding(
                    target=target,
                    file=rel_path,
                    kind=FindingKind.CONTENT,
                    rule_id=rule.id,
                    severity=rule.severity,
                    message=rule.description or "Secret-like pattern detected",
                    sample=_safe_sample(raw, redact=redact),
                    match_hash=stable_hash(rule.id, rel_path, "content", "file", raw),
                )
            )
            count += 1
            if count >= rule.regex.max_matches:
                break

        return out

    # BLOCK scope: match against whole file, but compute best-effort line numbers
    if scope == MatchScope.BLOCK:
        count = 0
        for m in regex_finditer(rule.regex.regex, text, flags=flags):
            raw = m.group(0)
            if _allow_regex_suppresses(rule, raw):
                continue

            line = _line_for_offset(text, m.start())

            out.append(
                Finding(
                    target=target,
                    file=rel_path,
                    kind=FindingKind.CONTENT,
                    rule_id=rule.id,
                    severity=rule.severity,
                    message=rule.description or "Secret-like block detected",
                    line=line,
                    sample=_safe_sample(raw, redact=redact),
                    match_hash=stable_hash(rule.id, rel_path, "content", "block", str(line), raw),
                )
            )
            count += 1
            if count >= rule.regex.max_matches:
                break

        return out

    # LINE scope: find matches per line (better diagnostics)
    count = 0
    for idx, line in enumerate(text.splitlines(), start=1):
        if not line or len(line) < 4:
            continue

        # allowlist can suppress whole line
        if _allow_regex_suppresses(rule, line):
            continue

        for m in regex_finditer(rule.regex.regex, line, flags=flags):
            raw = m.group(0)
            if _allow_regex_suppresses(rule, raw):
                continue

            out.append(
                Finding(
                    target=target,
                    file=rel_path,
                    kind=FindingKind.CONTENT,
                    rule_id=rule.id,
                    severity=rule.severity,
                    message=rule.description or "Secret-like pattern detected",
                    line=idx,
                    sample=_safe_sample(raw, redact=redact),
                    match_hash=stable_hash(rule.id, rel_path, "content", "line", str(idx), raw),
                )
            )
            count += 1
            if count >= rule.regex.max_matches:
                return out

    return out


# ----------------------------
# Structured rule helpers
# ----------------------------

def _looks_plaintext_secret(v: str) -> bool:
    """
    Heuristic: long-ish token with entropy-like charset and not obviously a reference.
    """
    s = (v or "").strip()
    if not s:
        return False
    if s.startswith("${") or s.startswith("$") or s.startswith("vault://"):
        return False
    if len(s) < 12:
        return False
    has_alpha = any(c.isalpha() for c in s)
    has_other = any(c.isdigit() or c in "_-+/=." for c in s)
    return has_alpha and has_other


def _value_violates_policy(policy: ValuePolicy, value: object) -> bool:
    """
    Returns True if the key/value should be flagged under this policy.
    """
    # Policy ANY means: key presence is enough (for matched keys)
    if policy == ValuePolicy.ANY:
        return True

    s = "" if value is None else str(value).strip()

    if policy == ValuePolicy.NON_EMPTY:
        return bool(s)

    if policy == ValuePolicy.MUST_REFERENCE_ENV:
        # allow $VAR or ${VAR}
        return not (s.startswith("$") or s.startswith("${"))

    if policy == ValuePolicy.MUST_REFERENCE_VAULT:
        return not s.startswith("vault://")

    if policy == ValuePolicy.PLAINTEXT:
        return _looks_plaintext_secret(s)

    # default: be conservative
    return True


def _safe_value_hint(v: object, *, redact: bool) -> Optional[str]:
    if v is None:
        return None

    if isinstance(v, (dict, list)):
        try:
            s = json.dumps(v, ensure_ascii=False)
        except Exception:
            s = str(v)
    else:
        s = str(v)

    return _safe_sample(s, redact=redact)


def _eval_structured_rule(
    *,
    target: str,
    rel_path: str,
    rule: Rule,
    text: str,
    parser: StructuredParser,
    redact: bool,
) -> List[Finding]:
    """
    Parse file into ParsedKV entries and apply forbidden/allowed/prefix + value policy.
    """
    assert rule.structured is not None
    cfg = rule.structured

    # Normalize key comparisons
    def norm(k: str) -> str:
        k2 = (k or "").strip()
        return k2.lower() if getattr(cfg, "case_insensitive", True) else k2

    forbidden = {norm(k) for k in (cfg.forbidden_keys or []) if k}
    allowed = {norm(k) for k in (cfg.allowed_keys or []) if k}
    prefixes = [norm(p) for p in (cfg.key_prefixes or []) if p]

    # Safety: if user provided no selectors, do nothing (prevents "flag everything")
    if not forbidden and not prefixes:
        return []

    try:
        entries = list(parser(text))
    except Exception:
        # parsing failures should not kill scans
        return []

    out: List[Finding] = []

    for kv in entries:
        key = str(getattr(kv, "key", "") or "")
        if not key:
            continue

        nk = norm(key)

        # Allowed keys win
        if allowed and nk in allowed:
            continue

        # Match selectors
        matched = False
        if forbidden and nk in forbidden:
            matched = True
        if not matched and prefixes:
            for p in prefixes:
                if nk.startswith(p):
                    matched = True
                    break
        if not matched:
            continue

        value = getattr(kv, "value", None)

        # Apply value policy
        if not _value_violates_policy(cfg.value_policy, value):
            continue

        hint = _safe_value_hint(value, redact=redact)
        line = getattr(kv, "line", None)

        out.append(
            Finding(
                target=target,
                file=rel_path,
                kind=FindingKind.STRUCTURED,
                rule_id=rule.id,
                severity=rule.severity,
                message=rule.description or "Forbidden key/value detected",
                key=key,
                value_hint=hint,
                line=int(line) if isinstance(line, int) else None,
                match_hash=stable_hash(rule.id, rel_path, "structured", nk, str(value)),
            )
        )

    return out