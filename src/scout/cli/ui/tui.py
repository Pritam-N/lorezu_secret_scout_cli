from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import os
import shlex
import shutil
import subprocess
import sys

from rich.console import Group
from rich.panel import Panel
from rich.table import Table
from textual import events
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Container, Horizontal, VerticalScroll
from textual.reactive import reactive
from textual.widgets import (
    DataTable,
    Footer,
    Header,
    Input,
    Static,
    TabbedContent,
    TabPane,
)

from scout.cli.ui.formatters import compute_offenders
from scout.core.models import Finding, ScanError, ScanResult, UIConfig


def _sev(v: object) -> str:
    return getattr(v, "value", str(v)).lower()


def _short(s: Optional[str], n: int = 160) -> str:
    s = s or ""
    return s if len(s) <= n else s[:n] + "…"


def _count_by_severity(findings: List[Finding]) -> Dict[str, int]:
    out = {"critical": 0, "high": 0, "medium": 0, "low": 0, "other": 0}
    for f in findings:
        s = _sev(f.severity)
        if s in out:
            out[s] += 1
        else:
            out["other"] += 1
    return out


def _top_counts(items: List[str], top_n: int = 10) -> List[Tuple[str, int]]:
    counts: Dict[str, int] = {}
    for x in items:
        counts[x] = counts.get(x, 0) + 1
    return sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))[:top_n]


class SummaryView(Static):
    """A scrollable summary view rendered as Rich tables/panels."""

    def __init__(self) -> None:
        super().__init__()
        self._findings: List[Finding] = []
        self._errors: List[ScanError] = []
        self._result: Optional[ScanResult] = None

    def set_data(
        self,
        findings: List[Finding],
        errors: List[ScanError],
        result: Optional[ScanResult],
    ) -> None:
        self._findings = findings
        self._errors = errors
        self._result = result
        self.refresh()

    def render(self):
        findings = self._findings
        errors = self._errors
        result = self._result

        targets = set()
        for f in findings:
            if f.target:
                targets.add(f.target)
        for e in errors:
            if getattr(e, "target", None):
                targets.add(getattr(e, "target", None))

        sev_counts = _count_by_severity(findings)

        overview = Table(show_header=False, box=None, pad_edge=False)
        overview.add_column("k", style="bold")
        overview.add_column("v")
        overview.add_row("Targets", str(len(targets)) if targets else "-")
        overview.add_row("Findings", str(len(findings)))
        overview.add_row("Errors", str(len(errors)))

        if result is not None and getattr(result, "stats", None) is not None:
            s = result.stats
            scanner = "-"
            try:
                if result.targets and result.targets[0].meta:
                    scanner = str(result.targets[0].meta.get("scanner", "-"))
            except Exception:
                scanner = "-"

            stats = Table(show_header=False, box=None, pad_edge=False)
            stats.add_column("k", style="bold")
            stats.add_column("v")
            stats.add_row("Scanner", scanner)
            stats.add_row("Files considered", str(getattr(s, "files_considered", 0)))
            stats.add_row("Files scanned", str(getattr(s, "files_scanned", 0)))
            stats.add_row("Skipped binary", str(getattr(s, "files_skipped_binary", 0)))
            stats.add_row(
                "Skipped too large", str(getattr(s, "files_skipped_too_large", 0))
            )
            stats.add_row("Duration (ms)", str(getattr(s, "duration_ms", 0)))
        else:
            stats = Table(show_header=False, box=None, pad_edge=False)
            stats.add_column("k", style="bold")
            stats.add_column("v")
            stats.add_row("Scanner", "-")
            stats.add_row("Files considered", "-")
            stats.add_row("Files scanned", "-")
            stats.add_row("Duration (ms)", "-")

        sev_table = Table(show_header=True, box=None, pad_edge=False)
        sev_table.add_column("Severity", style="bold")
        sev_table.add_column("Count", justify="right")
        for k in ["critical", "high", "medium", "low", "other"]:
            v = sev_counts.get(k, 0)
            if v:
                sev_table.add_row(k, str(v))
        if sev_table.row_count == 0:
            sev_table.add_row("—", "0")

        top_targets = _top_counts([f.target or "-" for f in findings], top_n=10)
        top_files = _top_counts(
            [f"{f.target or '-'}:{f.file or '-'}" for f in findings], top_n=10
        )
        top_rules = _top_counts([f.rule_id or "-" for f in findings], top_n=10)

        top_t = Table(show_header=True, box=None, pad_edge=False)
        top_t.add_column("Top targets", style="bold")
        top_t.add_column("Findings", justify="right")
        if top_targets:
            for name, cnt in top_targets:
                top_t.add_row(_short(name, 60), str(cnt))
        else:
            top_t.add_row("—", "0")

        top_f = Table(show_header=True, box=None, pad_edge=False)
        top_f.add_column("Top files", style="bold")
        top_f.add_column("Findings", justify="right")
        if top_files:
            for name, cnt in top_files:
                top_f.add_row(_short(name, 80), str(cnt))
        else:
            top_f.add_row("—", "0")

        top_r = Table(show_header=True, box=None, pad_edge=False)
        top_r.add_column("Top rules", style="bold")
        top_r.add_column("Findings", justify="right")
        if top_rules:
            for name, cnt in top_rules:
                top_r.add_row(_short(name, 80), str(cnt))
        else:
            top_r.add_row("—", "0")

        return Group(
            Panel(overview, title="Overview", border_style="blue"),
            Panel(stats, title="Scan stats", border_style="blue"),
            Panel(sev_table, title="Severity breakdown", border_style="blue"),
            Panel(top_t, title="Top targets", border_style="blue"),
            Panel(top_f, title="Top files", border_style="blue"),
            Panel(top_r, title="Top rules", border_style="blue"),
        )


@dataclass(frozen=True)
class TUIData:
    findings: List[Finding]
    errors: List[ScanError]
    result: Optional[ScanResult] = None
    ui_config: Optional[UIConfig] = None


class ResultsTUI(App):
    """
    Fixes included:
    - Search Input always *shows* typed text (safe CSS; correct height for bordered input).
    - Keys never get stolen from Input (bindings set priority=False; also ignores keys when Input focused).
    - Search change handler only reacts to #search, avoids accidental triggers.
    - '/' focuses search, Esc clears (and keeps focus), Enter opens only when not typing.
    - Cmd+Click open (meta+click) plus 'o' fallback.
    - Opening handles missing root_path / missing file / no selection gracefully.
    - Editor spawn handles SCOUT_EDITOR like "cursor --wait" via shlex split.
    """

    CSS = """
    Screen { overflow: hidden; }

    #toolbar { height: 3; padding: 0 1; }
    #filters { height: 4; padding: 0 1; }

    #search {
        width: 1fr;
        min-width: 30;
        height: 3;
        margin: 0 1;
        padding: 0 1;
        border: solid $accent;
        background: #222222;
        color: #ffffff;
    }
    #search:focus {
        border: solid $accent;
    }

    DataTable { height: 1fr; }
    .pill { padding: 0 1; border: solid $panel; }
    #summary_scroll { height: 1fr; }
    """

    # Reactive attribute for search - triggers watcher when changed
    search_query = reactive("")

    BINDINGS = [
        Binding("q", "quit", "Quit", show=True, priority=False),
        Binding("/", "focus_search", "Search", show=True, priority=False),
        Binding("escape", "clear_search", "Clear search", show=True, priority=False),
        Binding("o", "open_selected", "Open in editor", show=True, priority=False),
        Binding(
            "enter",
            "open_selected",
            "Open (when not typing)",
            show=False,
            priority=False,
        ),
        Binding("tab", "focus_next", "Next focus", show=False, priority=False),
        Binding(
            "shift+tab", "focus_previous", "Prev focus", show=False, priority=False
        ),
    ]

    def __init__(self, data: TUIData, **kwargs):
        super().__init__(**kwargs)
        self.data = data
        self._visible_findings: List[Finding] = []
        self._mounted = False

    def compose(self) -> ComposeResult:
        yield Header()

        with Container(id="toolbar"):
            yield Static(
                "scout — Results   (/ search · Tab focus · o open · Esc clear · q quit · ⌘+Click open)",
                classes="pill",
            )

        with Container(id="filters"):
            with Horizontal():
                yield Static("Search:", classes="pill")
                yield Input(
                    placeholder="filter by repo/file/rule/message…", id="search"
                )
                yield Static("Query: —", id="search-status", classes="pill")

        with TabbedContent():
            with TabPane("Findings", id="tab_findings"):
                yield DataTable(id="findings_table")

            with TabPane("Errors", id="tab_errors"):
                yield DataTable(id="errors_table")

            with TabPane("Top offenders", id="tab_offenders"):
                yield DataTable(id="offenders_repos")
                yield DataTable(id="offenders_files")
                yield DataTable(id="offenders_rules")

            with TabPane("Summary", id="tab_summary"):
                with VerticalScroll(id="summary_scroll"):
                    yield SummaryView()

        yield Footer()

    def on_mount(self) -> None:
        self._setup_findings_table()
        self._setup_errors_table()
        self._setup_offenders_tables()

        self._refresh_findings()
        self._refresh_errors()
        self._refresh_offenders()
        self._refresh_summary()

        self._mounted = True

        # Default focus: findings table (search still works via / or Tab)
        self.set_focus(self.query_one("#findings_table", DataTable))

    # ----------------------------
    # Focus / actions
    # ----------------------------

    def _search_input(self) -> Input:
        return self.query_one("#search", Input)

    def action_focus_search(self) -> None:
        inp = self._search_input()
        inp.focus()

    def action_clear_search(self) -> None:
        inp = self._search_input()
        inp.value = ""
        self.search_query = ""
        self._refresh_summary()
        # Keep focus in search after clearing (nice UX)
        inp.focus()

    def action_open_selected(self) -> None:
        # If user is typing in the Input, Enter / o should not yank focus / open.
        focused = self.focused
        if isinstance(focused, Input) and focused.id == "search":
            return
        self._open_current_finding(reason="key")

    # ----------------------------
    # Mouse: ⌘+Click to open (meta)
    # ----------------------------

    def on_click(self, event: events.Click) -> None:
        if not getattr(event, "meta", False):
            return

        focused = self.focused
        if not isinstance(focused, DataTable) or focused.id != "findings_table":
            return

        # Let table update cursor row, then open
        self.call_after_refresh(lambda: self._open_current_finding(reason="cmd-click"))

    # ----------------------------
    # Search input handling
    # ----------------------------

    def on_input_changed(self, event: Input.Changed) -> None:
        """Update the reactive search_query when input changes."""
        self.search_query = (event.value or "").strip().lower()

    def watch_search_query(self, query: str) -> None:
        """Watcher method called when search_query changes - refreshes tables and status."""
        if not self._mounted:
            return

        try:
            status = self.query_one("#search-status", Static)
            status.update(f"Query: {query or '—'}")
        except Exception:
            pass

        self._refresh_findings()
        self._refresh_errors()
        self._refresh_offenders()

    def _match(self, *parts: str) -> bool:
        if not self.search_query:
            return True
        blob = " ".join([p for p in parts if p]).lower()
        return self.search_query in blob

    # ----------------------------
    # Setup tables
    # ----------------------------

    def _setup_findings_table(self) -> None:
        t = self.query_one("#findings_table", DataTable)
        t.cursor_type = "row"
        t.zebra_stripes = True
        t.add_columns(
            "Repo", "Severity", "File", "Line", "Rule", "Message", "Sample/Hint"
        )

    def _setup_errors_table(self) -> None:
        t = self.query_one("#errors_table", DataTable)
        t.cursor_type = "row"
        t.zebra_stripes = True
        t.add_columns("Target", "Message", "Detail")

    def _setup_offenders_tables(self) -> None:
        tr = self.query_one("#offenders_repos", DataTable)
        tf = self.query_one("#offenders_files", DataTable)
        tu = self.query_one("#offenders_rules", DataTable)

        for t in (tr, tf, tu):
            t.cursor_type = "row"
            t.zebra_stripes = True

        tr.add_columns("Repos/Targets", "Count")
        tf.add_columns("Files (target:file)", "Count")
        tu.add_columns("Rules", "Count")

    # ----------------------------
    # Refresh tables
    # ----------------------------

    def _refresh_findings(self) -> None:
        t = self.query_one("#findings_table", DataTable)
        t.clear()
        self._visible_findings = []

        rows = sorted(
            self.data.findings,
            key=lambda f: (
                f.target or "",
                f.file or "",
                {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(
                    _sev(f.severity), 9
                ),
                f.rule_id or "",
                getattr(f, "line", None) or getattr(f, "line_number", None) or 0,
            ),
        )

        for f in rows:
            sev = _sev(f.severity)
            sample = f.sample or f.value_hint or ""
            kind = getattr(f.kind, "value", str(f.kind))
            if kind == "filename":
                sample = ""

            if not self._match(
                f.target or "",
                f.file or "",
                f.rule_id or "",
                f.message or "",
                sample,
                sev,
            ):
                continue

            self._visible_findings.append(f)

            t.add_row(
                f.target or "",
                sev,
                f.file or "",
                str(self._get_line(f) if kind != "filename" else ""),
                f.rule_id or "",
                _short(f.message, 140),
                _short(sample, 140),
            )

    def _refresh_errors(self) -> None:
        t = self.query_one("#errors_table", DataTable)
        t.clear()

        for e in self.data.errors:
            detail = getattr(e, "detail", None) or ""
            if not self._match(e.target or "", e.message or "", detail):
                continue
            t.add_row(e.target or "", _short(e.message, 180), _short(detail, 180))

    def _refresh_offenders(self) -> None:
        offenders = compute_offenders(self.data.findings, top_n=15)

        tr = self.query_one("#offenders_repos", DataTable)
        tf = self.query_one("#offenders_files", DataTable)
        tu = self.query_one("#offenders_rules", DataTable)

        tr.clear()
        tf.clear()
        tu.clear()

        for name, count in offenders.by_target:
            if self._match(name):
                tr.add_row(name or "-", str(count))

        for name, count in offenders.by_file:
            if self._match(name):
                tf.add_row(name or "-", str(count))

        for name, count in offenders.by_rule:
            if self._match(name):
                tu.add_row(name or "-", str(count))

    def _refresh_summary(self) -> None:
        view = self.query_one(SummaryView)
        view.set_data(self.data.findings, self.data.errors, self.data.result)

    # ----------------------------
    # Open helpers
    # ----------------------------

    def _get_line(self, f: Finding) -> int:
        ln = getattr(f, "line", None)
        if ln is None:
            ln = getattr(f, "line_number", None)
        try:
            return int(ln or 1)
        except Exception:
            return 1

    def _abs_path_for_finding(self, f: Finding) -> Optional[Path]:
        # Works best for scan-path; degrade gracefully for other scanners.
        if not self.data.result or not getattr(self.data.result, "targets", None):
            return None
        if not self.data.result.targets:
            return None

        root_path = getattr(self.data.result.targets[0], "root_path", None)
        if not root_path:
            return None

        root = Path(root_path)
        rel = getattr(f, "file", None) or ""
        if not rel:
            return None

        try:
            p = (root / rel).resolve()
        except Exception:
            return None
        return p if p.exists() else None

    def _spawn_editor(self, file_path: Path, line: int) -> bool:
        """
        Open file in an editor at line.
        Handles:
        - SCOUT_EDITOR / VISUAL / EDITOR with args (uses shlex)
        - common editors: cursor, code, subl, zed, vim/nvim
        - macOS fallback: open
        """
        editor_env = (
            os.environ.get("SCOUT_EDITOR")
            or os.environ.get("VISUAL")
            or os.environ.get("EDITOR")
        )

        def _popen(cmd: List[str]) -> bool:
            try:
                subprocess.Popen(cmd)  # nosec
                return True
            except Exception:
                return False

        def _with_line(base_cmd: List[str], exe_name: str) -> List[str]:
            exe = shutil.which(exe_name) or exe_name
            low = exe_name.lower()

            if low in ("code", "cursor", "subl", "zed"):
                return [exe, "-g", f"{file_path}:{line}"] + base_cmd[1:]
            if low in ("vim", "nvim"):
                return [exe, f"+{line}", str(file_path)] + base_cmd[1:]
            return [exe, str(file_path)] + base_cmd[1:]

        if editor_env:
            try:
                parts = shlex.split(editor_env)
            except Exception:
                parts = editor_env.strip().split()

            if parts:
                exe_name = parts[0]
                cmd = _with_line(parts, exe_name)
                return _popen(cmd)

        editors_to_try: List[str]
        if self.data.ui_config and getattr(self.data.ui_config, "editors", None):
            try:
                editors_to_try = list(self.data.ui_config.editors)  # type: ignore[arg-type]
            except Exception:
                editors_to_try = ["cursor", "code", "subl", "zed", "nvim", "vim"]
        else:
            editors_to_try = ["cursor", "code", "subl", "zed", "nvim", "vim"]

        for editor_name in editors_to_try:
            p = shutil.which(editor_name)
            if not p:
                continue
            low = editor_name.lower()
            if low in ("code", "cursor", "subl", "zed"):
                return _popen([p, "-g", f"{file_path}:{line}"])
            if low in ("vim", "nvim"):
                return _popen([p, f"+{line}", str(file_path)])
            return _popen([p, str(file_path)])

        if sys.platform == "darwin":
            return _popen(["open", str(file_path)])

        # Linux: xdg-open as last resort
        xdg = shutil.which("xdg-open")
        if xdg:
            return _popen([xdg, str(file_path)])

        return False

    def _open_current_finding(self, *, reason: str) -> None:
        table = self.query_one("#findings_table", DataTable)

        row_index = table.cursor_row
        if (
            row_index is None
            or row_index < 0
            or row_index >= len(self._visible_findings)
        ):
            self.notify("No finding selected.", severity="warning")
            return

        f = self._visible_findings[row_index]
        abs_path = self._abs_path_for_finding(f)
        if not abs_path:
            self.notify(
                "Cannot resolve file path for this finding.", severity="warning"
            )
            return

        line = self._get_line(f)
        if not self._spawn_editor(abs_path, line):
            self.notify(
                "Could not open editor. Set SCOUT_EDITOR or EDITOR.", severity="error"
            )
            return

        self.notify(f"Opened {abs_path.name}:{line}", severity="information")


def run_tui(
    *,
    findings: List[Finding],
    errors: List[ScanError],
    result: Optional[ScanResult] = None,
    ui_config: Optional[UIConfig] = None,
) -> None:
    ResultsTUI(
        TUIData(findings=findings, errors=errors, result=result, ui_config=ui_config)
    ).run()
