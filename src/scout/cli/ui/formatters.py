from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass
from typing import Iterable, List, Optional, Sequence, Tuple

from rich.console import Console
from rich.table import Table
from rich.text import Text

from scout.core.models import Finding, ScanError, ScanResult


# ----------------------------
# Severity helpers
# ----------------------------

_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def severity_value(sev: object) -> str:
    # sev could be Enum or str
    return getattr(sev, "value", str(sev)).lower()


def severity_sort_key(sev: object) -> int:
    return _SEV_ORDER.get(severity_value(sev), 9)


def severity_style(sev: object) -> str:
    s = severity_value(sev)
    if s in ("critical", "high", "medium", "low"):
        return f"sev.{s}"
    return "muted"


def _short(s: str, max_len: int = 140) -> str:
    s = s or ""
    if len(s) <= max_len:
        return s
    return s[:max_len] + "…"


# ----------------------------
# Findings tables
# ----------------------------

@dataclass(frozen=True)
class FindingsRenderOptions:
    title: Optional[str] = None
    group_by_target: bool = False
    max_rows: Optional[int] = None  # show only first N rows (still prints count)
    show_samples: bool = True       # samples are already redacted upstream


def render_findings_table(
    console: Console,
    findings: Sequence[Finding],
    *,
    opts: Optional[FindingsRenderOptions] = None,
) -> None:
    opts = opts or FindingsRenderOptions()

    if not findings:
        console.print("[ok]✅ No findings.[/ok]")
        return

    # stable sort
    sorted_findings = sorted(
        findings,
        key=lambda f: (
            f.target or "",
            f.file or "",
            severity_sort_key(f.severity),
            f.rule_id or "",
            f.line or 0,
            f.match_hash or "",
        ),
    )

    total = len(sorted_findings)
    show = sorted_findings
    if opts.max_rows is not None:
        show = sorted_findings[: int(opts.max_rows)]

    title = opts.title or f"Findings ({total})"
    table = Table(title=title, show_lines=False)

    if opts.group_by_target:
        table.add_column("Target", style="bold", no_wrap=True)
    table.add_column("Severity", style="bold", no_wrap=True)
    table.add_column("File", style="path")
    table.add_column("Line", justify="right", no_wrap=True)
    table.add_column("Rule", style="rule", no_wrap=True)
    table.add_column("Message")
    table.add_column("Sample/Hint")

    for f in show:
        sev = severity_value(f.severity)
        sev_txt = Text(sev, style=severity_style(f.severity))

        sample = ""
        if opts.show_samples:
            # filename findings typically have no sample
            sample = f.sample or f.value_hint or ""

        row = []
        if opts.group_by_target:
            row.append(f.target or "")
        row.extend(
            [
                sev_txt,
                f.file or "",
                str(f.line or ""),
                f.rule_id or "",
                _short(f.message or "", 120),
                _short(sample, 120),
            ]
        )
        table.add_row(*row)

    console.print(table)

    if opts.max_rows is not None and total > len(show):
        console.print(f"[muted]… showing {len(show)} of {total} findings (use --verbose or remove limits).[/muted]")


# ----------------------------
# Errors
# ----------------------------

def render_errors(
    console: Console,
    errors: Sequence[ScanError],
    *,
    max_items: int = 25,
    verbose: bool = False,
) -> None:
    if not errors:
        return

    console.print(f"[warn]⚠️  {len(errors)} error(s) occurred while scanning.[/warn]")

    if not verbose:
        console.print("[muted]Run with --verbose to see error details.[/muted]")
        return

    shown = list(errors)[:max_items]
    for e in shown:
        detail = getattr(e, "detail", None) or ""
        msg = f"- {e.target}: {e.message}"
        if detail:
            msg += f" ({_short(detail, 160)})"
        console.print(msg)

    if len(errors) > len(shown):
        console.print(f"[muted]… and {len(errors) - len(shown)} more[/muted]")


# ----------------------------
# Summaries / stats
# ----------------------------

# def render_scan_summary(
#     console: Console,
#     result: ScanResult,
#     *,
#     header: str = "Summary",
#     extra_lines: Optional[List[str]] = None,
# ) -> None:
#     console.print()
#     console.print(f"[bold]{header}:[/bold]")

#     scanner = ""
#     if result.targets and result.targets[0].meta:
#         scanner = str(result.targets[0].meta.get("scanner", ""))

#     s = result.stats
#     console.print(f"  scanner:          {scanner or '-'}")
#     console.print(f"  files_considered: {s.files_considered}")
#     console.print(f"  files_scanned:    {s.files_scanned}")
#     console.print(f"  skipped_binary:   {getattr(s, 'files_skipped_binary', 0)}")
#     console.print(f"  skipped_large:    {getattr(s, 'files_skipped_too_large', 0)}")
#     console.print(f"  findings:         {s.findings}")
#     console.print(f"  duration_ms:      {s.duration_ms}")

#     if extra_lines:
#         for line in extra_lines:
#             console.print(f"  {line}")

def render_scan_summary(
    console: Console,
    result: ScanResult,
    *,
    header: str = "Summary",
    extra_lines: Optional[List[str]] = None,
) -> None:
    extra_lines = extra_lines or []

    # infer scanner
    scanner = "-"
    try:
        if result.targets and result.targets[0].meta:
            scanner = str(result.targets[0].meta.get("scanner", "-"))
    except Exception:
        scanner = "-"

    s = result.stats

    cols: List[str] = [
        "scanner",
        "files_considered",
        "files_scanned",
        "skipped_binary",
        "skipped_large",
        "findings",
        "errors",
        "duration_ms",
    ]

    vals: List[str] = [
        scanner,
        str(getattr(s, "files_considered", 0)),
        str(getattr(s, "files_scanned", 0)),
        str(getattr(s, "files_skipped_binary", 0)),
        str(getattr(s, "files_skipped_too_large", 0)),
        str(len(result.findings)),
        str(len(result.errors)),
        str(getattr(s, "duration_ms", 0)),
    ]

    # Allow optional extras like "workspace: /tmp/..." as additional columns
    for line in extra_lines:
        if ":" in line:
            k, v = line.split(":", 1)
            cols.append(k.strip())
            vals.append(v.strip())
        else:
            cols.append("note")
            vals.append(line)

    table = Table(title=header, show_header=True, show_lines=False)
    for c in cols:
        table.add_column(c, style="bold", no_wrap=True)
    table.add_row(*vals)

    console.print()
    console.print(table)

# ----------------------------
# Top offenders (repos / files / rules)
# ----------------------------

@dataclass(frozen=True)
class Offenders:
    by_target: List[Tuple[str, int]]
    by_file: List[Tuple[str, int]]
    by_rule: List[Tuple[str, int]]


def compute_offenders(findings: Iterable[Finding], *, top_n: int = 10) -> Offenders:
    ft = Counter()
    ff = Counter()
    fr = Counter()

    for f in findings:
        ft[f.target or ""] += 1
        ff[f"{f.target or ''}:{f.file or ''}"] += 1
        fr[f.rule_id or ""] += 1

    return Offenders(
        by_target=ft.most_common(top_n),
        by_file=ff.most_common(top_n),
        by_rule=fr.most_common(top_n),
    )


def render_offenders(
    console: Console,
    offenders: Offenders,
    *,
    title: str = "Top offenders",
) -> None:
    console.print()
    console.print(f"[bold]{title}[/bold]")

    def _table(name: str, rows: List[Tuple[str, int]]) -> Table:
        t = Table(title=name, show_lines=False)
        t.add_column("Item")
        t.add_column("Count", justify="right")
        for k, v in rows:
            t.add_row(k or "-", str(v))
        return t

    console.print(_table("Repos/Targets", offenders.by_target))
    console.print(_table("Files (target:file)", offenders.by_file))
    console.print(_table("Rules", offenders.by_rule))