"""
cli.py

    unslop scan requirements.txt
    unslop scan package.json --json report.json
    unslop scan requirements.txt package.json --base origin/main --markdown comment.md

Exit codes (so CI can tell the cases apart):
    0  nothing blocked
    1  at least one package blocked
    2  Unslop could not run (bad git ref, unreadable manifest, ...)
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import click

from .gitdiff import GitError, added_packages
from .heuristics import HallucinationEngine
from .report import render_markdown, safe_name
from .scanner import ScanReport, scan_manifest, ecosystem_for

VERDICT_COLOR = {"block": "red", "warn": "yellow", "pass": "green"}
VERDICT_ICON = {"block": "\u2717 BLOCK", "warn": "\u26a0 WARN", "pass": "\u2713 PASS"}


@click.group()
def main():
    """Unslop - catch AI-hallucinated (slopsquatted) package names before they get installed."""
    pass


def _fail(message: str) -> None:
    click.secho(f"Error: {message}", fg="red", err=True)
    sys.exit(2)


@main.command()
@click.argument("manifests", nargs=-1, required=True, type=click.Path(exists=True, path_type=Path))
@click.option("--base", "base_ref", default=None,
              help="Only scan packages added since this git ref (e.g. origin/main).")
@click.option("--only", default=None,
              help="Comma-separated package names to check; everything else is skipped.")
@click.option("--json", "json_out", type=click.Path(path_type=Path), default=None,
              help="Write the full scan report as JSON to this path.")
@click.option("--markdown", "md_out", type=click.Path(path_type=Path), default=None,
              help="Write a Markdown report (for a PR comment) to this path.")
@click.option("--fail-on-block/--no-fail-on-block", default=True,
              help="Exit with status 1 if any package is blocked (for CI gating).")
def scan(manifests, base_ref, only, json_out, md_out, fail_on_block):
    """Scan dependency manifests (requirements.txt, package.json) for slopsquatting risk."""
    only_list = [x.strip() for x in only.split(",")] if only else None
    engine = HallucinationEngine()
    reports: list[ScanReport] = []

    for manifest in manifests:
        try:
            ecosystem_for(manifest)
            names = only_list
            if base_ref:
                names = added_packages(manifest, base_ref)
                if only_list is not None:
                    keep = {n.lower() for n in only_list}
                    names = [n for n in names if n.lower() in keep]
            click.echo(f"Scanning {manifest}" + (f" (new since {base_ref})" if base_ref else "") + " ...")
            reports.append(scan_manifest(manifest, engine=engine, only_new=names))
        except GitError as e:
            _fail(str(e))
        except ValueError as e:
            _fail(f"{manifest}: {e}")

    click.echo()
    for report in reports:
        click.echo(f"{report.manifest}  |  ecosystem: {report.ecosystem}  |  packages checked: {report.total_packages}")
        click.echo("-" * 60)
        if report.total_packages == 0:
            click.echo("No packages to scan.\n")
        for group, assessments in (("block", report.blocked), ("warn", report.warned), ("pass", report.passed)):
            for a in assessments:
                click.secho(f"{VERDICT_ICON[group]}  {safe_name(a.package)}  (risk: {a.risk_score}/100)",
                            fg=VERDICT_COLOR[group], bold=True)
                for reason in a.reasons:
                    click.echo(f"    - {reason}")
                click.echo()

    blocked = sum(len(r.blocked) for r in reports)
    warned = sum(len(r.warned) for r in reports)
    passed = sum(len(r.passed) for r in reports)
    click.echo("-" * 60)
    click.echo(f"Summary: {blocked} blocked, {warned} warned, {passed} passed.")

    if json_out:
        payload = {
            "summary": {"blocked": blocked, "warned": warned, "passed": passed},
            "reports": [r.to_dict() for r in reports],
        }
        json_out.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")
        click.echo(f"JSON report written to {json_out}")
    if md_out:
        md_out.write_text(render_markdown(reports), encoding="utf-8")
        click.echo(f"Markdown report written to {md_out}")

    if fail_on_block and blocked:
        click.secho("\nBuild gate: FAILED (blocked packages found)", fg="red", bold=True)
        sys.exit(1)
    click.secho("\nBuild gate: PASSED", fg="green", bold=True)


if __name__ == "__main__":
    main()
