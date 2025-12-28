from __future__ import annotations

import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Callable, Dict, Iterable, List, Optional, Protocol, Tuple

from scout.core.models import (
    FileCandidate,
    Finding,
    ScanConfig,
    ScanError,
    ScanResult,
    ScanStats,
    ScanTarget,
    RuleSet,
)
from scout.core.policy import TextReader, evaluate_file


class Baseline(Protocol):
    """
    Optional baseline interface. Implement later in core/baseline.py.
    """
    def suppress(self, findings: List[Finding]) -> List[Finding]: ...


@dataclass(frozen=True)
class EngineInput:
    target: ScanTarget
    candidates: List[FileCandidate]


# Structured parsing: parser returns normalized key/value entries (ParsedKV-like objects).
StructuredParser = Callable[[str], Iterable[object]]


def _default_structured_parsers() -> Dict[str, StructuredParser]:
    """
    Lazily load built-in parsers.

    This avoids import-time failures if optional deps aren't installed.
    If deps are missing, structured scanning is simply skipped.
    """
    try:
        from scout.parsers import PARSERS  # {StructuredFormat: ParserFn}
        # Convert enum keys -> string keys used in rules (fmt.value)
        return {fmt.value: fn for fmt, fn in PARSERS.items()}
    except Exception:
        return {}


def _candidate_rel_path(c: FileCandidate) -> str:
    # support both attribute spellings
    return str(getattr(c, "rel_path", None) or getattr(c, "relative_path", None) or "")


def _dedupe_findings(findings: List[Finding]) -> List[Finding]:
    """
    Deduplicate findings to avoid noisy repeats.
    Key is designed to be stable & deterministic.
    """
    seen: set[Tuple[str, str, str, str, str]] = set()
    out: List[Finding] = []

    for f in findings:
        key = (
            f.target,
            f.file,
            f.rule_id,
            str(getattr(f, "line", None) or getattr(f, "line_number", None) or ""),
            str(f.match_hash or ""),
        )
        if key in seen:
            continue
        seen.add(key)
        out.append(f)

    # Stable sort (helps CI diffs)
    out.sort(key=lambda x: (x.file or "", x.rule_id or "", (x.line or 0), x.match_hash or ""))
    return out


def run_scan(
    *,
    target: ScanTarget,
    candidates: Iterable[FileCandidate],
    ruleset: RuleSet,
    config: ScanConfig,
    read_text: TextReader,
    baseline: Optional[Baseline] = None,
    structured_parsers: Optional[Dict[str, StructuredParser]] = None,
    dedupe: bool = True,
) -> ScanResult:
    """
    Orchestrate a scan:
    enumerate candidates -> policy eval -> optional baseline -> optional dedupe -> ScanResult.
    """
    t0 = time.perf_counter()
    started_at = datetime.now(timezone.utc)

    # If caller didn't provide structured parsers, use defaults.
    if structured_parsers is None:
        structured_parsers = _default_structured_parsers()

    cand_list = list(candidates)
    if config.deterministic:
        cand_list.sort(key=lambda c: (_candidate_rel_path(c) or ""))

    result = ScanResult(
        started_at=started_at,
        targets=[target],
        stats=ScanStats(),
    )
    result.stats.files_considered = len(cand_list)

    findings: List[Finding] = []

    for c in cand_list:
        try:
            # scanners should set these; engine respects them
            if getattr(c, "is_binary", False):
                result.stats.files_skipped_binary += 1
                continue
            if int(getattr(c, "size_bytes", 0) or 0) > int(config.max_file_bytes):
                result.stats.files_skipped_too_large += 1
                continue

            result.stats.files_scanned += 1

            f = evaluate_file(
                target_name=target.name,
                candidate=c,
                ruleset=ruleset,
                config=config,
                read_text=read_text,
                structured_parsers=structured_parsers,
            )
            findings.extend(f)

        except Exception as e:
            # Non-fatal per-file error; keep scanning
            result.errors.append(
                ScanError(
                    target=target.name,
                    message=f"Failed scanning file: {_candidate_rel_path(c)}",
                    detail=str(e),
                )
            )

    # Baseline suppression (optional)
    if baseline is not None:
        try:
            findings = baseline.suppress(findings)
        except Exception as e:
            result.errors.append(
                ScanError(
                    target=target.name,
                    message="Baseline suppression failed",
                    detail=str(e),
                )
            )

    if dedupe:
        findings = _dedupe_findings(findings)

    result.findings = findings
    result.stats.findings = len(findings)
    result.stats.duration_ms = int((time.perf_counter() - t0) * 1000)
    result.finished_at = datetime.now(timezone.utc)
    return result