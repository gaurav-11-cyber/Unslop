"""
cli.py

Command-line entry point:
    unslop scan requirements.txt
    unslop scan package.json --json report.json
    unslop scan requirements.txt --only cool-utils,another-pkg
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import click

from .scanner import scan_manifest

VERDICT_COLOR = {"block": "red", "warn": "yellow", "pass": "green"}
VERDICT_ICON = {"block": "\u2717 BLOCK", "warn": "\u26a0 WARN", "pass": "\u2713 PASS"}


@click.group()
def main():
    """Unslop - catch AI-hallucinated (slopsquatted) package names before they get installed."""
    pass


@main.command()
@click.argument("manifest", type=click.Path(exists=True, path_type=Path))
@click.option("--json", "json_out", type=click.Path(path_type=Path), default=None,
              help="Write the full scan report as JSON to this path (for dashboard/CI use).")
@click.option("--only", default=None,
              help="Comma-separated list of package names to check (e.g. only the ones added in a PR diff).")
@click.option("--fail-on-block/--no-fail-on-block", default=True,
              help="Exit with non-zero status if any package is blocked (for CI gating).")
def scan(manifest: Path, json_out: Path, only: str, fail_on_block: bool):
    """Scan a dependency manifest (requirements.txt or package.json) for slopsquatting risk."""
    only_list = [x.strip() for x in only.split(",")] if only else None

    click.echo(f"Scanning {manifest} ...")
    report = scan_manifest(manifest, only_new=only_list)

    click.echo()
    click.echo(f"Ecosystem: {report.ecosystem}  |  Packages checked: {report.total_packages}")
    click.echo("-" * 60)

    for group, assessments in (
        ("block", report.blocked),
        ("warn", report.warned),
        ("pass", report.passed),
    ):
        for a in assessments:
            color = VERDICT_COLOR[group]
            click.secho(f"{VERDICT_ICON[group]}  {a.package}  (risk: {a.risk_score}/100)", fg=color, bold=True)
            for reason in a.reasons:
                click.echo(f"    - {reason}")
            click.echo()

    click.echo("-" * 60)
    click.echo(
        f"Summary: {len(report.blocked)} blocked, {len(report.warned)} warned, "
        f"{len(report.passed)} passed."
    )

    if json_out:
        json_out.write_text(json.dumps(report.to_dict(), indent=2, default=str))
        click.echo(f"Full report written to {json_out}")

    if fail_on_block and report.should_fail_build:
        click.secho("\nBuild gate: FAILED (blocked packages found)", fg="red", bold=True)
        sys.exit(1)
    else:
        click.secho("\nBuild gate: PASSED", fg="green", bold=True)


if __name__ == "__main__":
    main()
