from __future__ import annotations

import queue
import sys
import threading
from pathlib import Path
from typing import List, Optional, Tuple, cast

import typer

from scout.cli.ui import (
    FindingsRenderOptions,
    compute_offenders,
    get_ui,
    render_errors,
    render_findings_table,
    render_offenders,
)
from scout.cli.ui.progress import build_progress, bump, init_tasks
from scout.cli.ui.tui import run_tui
from scout.core.config import find_global_config, load_scan_config
from scout.core.errors import ExitCode
from scout.core.models import Finding, ScanError
from scout.scanners.github import (
    GitHubClient,
    GitHubScanOptions,
    RepoFilter,
    scan_github,
)

app = typer.Typer(help="Scan GitHub org/user repos (clones to a temp workspace).")


def _should_use_tui(plain: bool) -> bool:
    if plain:
        return False
    return sys.stdout.isatty()


@app.command("github")
def scan_github_cmd(
    org: Optional[str] = typer.Option(None, "--org", help="GitHub org to scan."),
    user: Optional[str] = typer.Option(None, "--user", help="GitHub username to scan."),
    token: Optional[str] = typer.Option(
        None,
        "--token",
        envvar="GITHUB_TOKEN",
        help="GitHub token (or set GITHUB_TOKEN).",
    ),
    api_base: str = typer.Option(
        "https://api.github.com", "--api-base", help="GitHub API base URL."
    ),
    include: List[str] = typer.Option(
        [], "--include", help="Glob(s) to include by repo full_name (repeatable)."
    ),
    exclude: List[str] = typer.Option(
        [], "--exclude", help="Glob(s) to exclude by repo full_name (repeatable)."
    ),
    repo: List[str] = typer.Option(
        [],
        "--repo",
        help="Explicit repo full_name allowlist (repeatable, e.g. org/repo).",
    ),
    include_private: bool = typer.Option(
        True,
        "--include-private/--no-include-private",
        help="Include private repos (needs token).",
    ),
    include_archived: bool = typer.Option(
        False, "--include-archived", help="Include archived repos."
    ),
    include_forks: bool = typer.Option(
        False, "--include-forks", help="Include forked repos."
    ),
    max_repos: Optional[int] = typer.Option(
        None, "--max-repos", help="Limit number of repos scanned."
    ),
    ignore: List[str] = typer.Option(
        [], "--ignore", help="Glob(s) to ignore within repos (repeatable)."
    ),
    builtin: str = typer.Option(
        "default", "--builtin", help="Builtin rule pack to use (default/strict)."
    ),
    rules_file: List[Path] = typer.Option(
        [],
        "--rules",
        exists=True,
        dir_okay=False,
        help="Extra rule files (repeatable).",
    ),
    concurrency: int = typer.Option(
        4, "--concurrency", min=1, max=32, help="Parallel clone+scan workers."
    ),
    shallow: bool = typer.Option(
        True, "--shallow/--no-shallow", help="Use shallow clones."
    ),
    blobless: bool = typer.Option(
        True, "--blobless/--no-blobless", help="Use blobless clones (faster)."
    ),
    include_untracked: bool = typer.Option(
        True,
        "--include-untracked/--no-include-untracked",
        help="Include untracked files in repos.",
    ),
    include_ignored: Optional[bool] = typer.Option(
        None,
        "--include-ignored/--no-include-ignored",
        help="Include gitignored files in repos.",
    ),
    tmp_dir: Optional[Path] = typer.Option(
        None, "--tmp-dir", help="Workspace directory (defaults to temp dir)."
    ),
    keep_clones: bool = typer.Option(
        False, "--keep-clones", help="Do not delete workspace when using temp dir."
    ),
    plain: bool = typer.Option(
        False, "--plain", help="Disable TUI; print Rich output (CI-friendly)."
    ),
    fail: bool = typer.Option(
        True, "--fail/--no-fail", help="Exit 1 if findings are present (CI mode)."
    ),
    ignore_errors: bool = typer.Option(
        False, "--ignore-errors", help="Exit 0/1 even if some repos error."
    ),
    verbose: bool = typer.Option(False, "--verbose", help="Print scan summary."),
) -> None:
    ui = get_ui(verbose=verbose)
    console = ui.console

    if not org and not user:
        raise typer.BadParameter("Provide either --org or --user.")

    client = GitHubClient(token=token, api_base=api_base)

    repo_filter = RepoFilter(
        include=include,
        exclude=exclude,
        repos=repo,
        include_archived=include_archived,
        include_forks=include_forks,
        include_disabled=False,
        max_repos=max_repos,
    )

    opts = GitHubScanOptions(
        org=org,
        user=user,
        include_private=include_private,
        include_untracked=include_untracked,
        include_ignored=include_ignored,
        shallow=shallow,
        blobless=blobless,
        concurrency=concurrency,
        tmp_dir=tmp_dir,
        keep_clones=keep_clones,
    )

    # List repos first so progress totals are correct
    if org:
        repos = client.list_org_repos(org, include_private=include_private)
    else:
        repos = client.list_user_repos(user or "", include_private=include_private)
    repos = repo_filter.apply(repos)

    if not repos:
        console.print("[warn]No repositories matched your filters.[/warn]")
        raise typer.Exit(code=int(ExitCode.OK))

    # Thread-safe event queue (worker threads enqueue; main thread updates progress)
    q: "queue.Queue[Tuple[str, str, str]]" = queue.Queue()
    done = threading.Event()

    cloned = 0
    scanned = 0
    errored = 0

    def on_event(ev: str, repo_full_name: str, msg: str) -> None:
        q.put((ev, repo_full_name, msg))

    results_holder: dict[str, object] = {}

    def _runner() -> None:
        try:
            results, workspace = scan_github(
                client=client,
                repo_filter=repo_filter,
                opts=opts,
                builtin=builtin,
                rules_files=rules_file,
                ignore_globs=ignore,
                on_event=on_event,  # requires updated scanners/github/scan.py
            )
            results_holder["results"] = results
            results_holder["workspace"] = workspace
        finally:
            done.set()

    t = threading.Thread(target=_runner, daemon=True)

    progress = build_progress(console)
    with progress:
        tasks = init_tasks(progress, total_repos=len(repos))
        t.start()

        while not done.is_set() or not q.empty():
            try:
                ev, _name, _msg = q.get(timeout=0.1)
            except queue.Empty:
                continue

            if ev == "clone_done":
                cloned += 1
                bump(progress, tasks.cloning, 1)
            elif ev == "scan_done":
                scanned += 1
                bump(progress, tasks.scanning, 1)
                bump(progress, tasks.overall, 1)
            elif ev == "repo_error":
                errored += 1
                bump(progress, tasks.overall, 1)

    results = cast(list, results_holder.get("results", []))
    workspace = cast(Path, results_holder.get("workspace", Path.cwd()))

    # Aggregate
    all_findings: List[Finding] = []
    all_errors: List[ScanError] = []
    total_targets = 0

    for r in results:
        total_targets += len(getattr(r, "targets", []) or [])
        all_findings.extend(getattr(r, "findings", []) or [])
        all_errors.extend(getattr(r, "errors", []) or [])

    # Load UI config (from global config, if available)
    ui_config = None
    try:
        # Use current directory as start_dir to find config
        start_dir = Path.cwd()
        loaded_cfg = load_scan_config(start_dir=start_dir, cli_overrides={})
        ui_config = loaded_cfg.ui_config
    except Exception:
        # If config loading fails, just use defaults
        pass

    # Default: TUI for humans (interactive terminals only)
    if _should_use_tui(plain):
        run_tui(
            findings=all_findings, errors=all_errors, result=None, ui_config=ui_config
        )
    else:
        render_findings_table(
            console,
            all_findings,
            opts=FindingsRenderOptions(
                title=f"Findings ({len(all_findings)})", group_by_target=True
            ),
        )
        render_errors(console, all_errors, verbose=ui.verbose)
        if all_findings:
            render_offenders(
                console, compute_offenders(all_findings), title="Top offenders"
            )

        if verbose:
            console.print()
            console.print("[bold]Summary:[/bold]")
            console.print(f"  repos_selected: {len(repos)}")
            console.print(f"  repos_scanned:  {total_targets}")
            console.print(f"  findings:       {len(all_findings)}")
            console.print(f"  errors:         {len(all_errors)}")
            console.print(f"  cloned:         {cloned}")
            console.print(f"  scanned:        {scanned}")
            console.print(f"  errored:        {errored}")
            console.print(f"  workspace:      {workspace}")

    # Exit codes always apply even if TUI was shown
    if all_errors and not ignore_errors:
        raise typer.Exit(code=int(ExitCode.ERROR))

    if all_findings and fail:
        raise typer.Exit(code=int(ExitCode.FINDINGS))

    raise typer.Exit(code=int(ExitCode.OK))
