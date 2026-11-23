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
import os
import sys
from pathlib import Path

import click

from . import __version__
from .sarif import to_sarif
from .docscan import is_doc_file, scan_doc
from .deps import manifest_deps
from .gate import render_gate_markdown, run_gate, to_json
from .gitdiff import GitError, added_packages
from .policy import PolicyError, load_policy
from .sbom import build_sbom
from .heuristics import HallucinationEngine
from .report import render_markdown, safe_name, safe_location
from .scanner import ScanReport, scan_manifest, ecosystem_for

VERDICT_COLOR = {"block": "red", "warn": "yellow", "pass": "green"}
VERDICT_ICON = {"block": "\u2717 BLOCK", "warn": "\u26a0 WARN", "pass": "\u2713 PASS"}


def _plain(text: str) -> str:
    """Strip control characters (file names are untrusted; avoids terminal-escape tricks in CI logs)."""
    return "".join("?" if ord(c) < 32 or ord(c) == 127 else c for c in text)


@click.group()
@click.version_option(__version__, prog_name="unslop")
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
@click.option("--sarif", "sarif_out", type=click.Path(path_type=Path), default=None,
              help="Write findings as SARIF 2.1.0 (for GitHub code scanning) to this path.")
@click.option("--no-cache", is_flag=True, default=False, help="Do not read or write the local registry cache.")
@click.option("--strict-docs", is_flag=True, default=False,
              help="In docs/scripts, keep BLOCK for unknown packages (default: downgrade to WARN).")
@click.option("--fail-on-block/--no-fail-on-block", default=True,
              help="Exit with status 1 if any package is blocked (for CI gating).")
def scan(manifests, base_ref, only, json_out, md_out, sarif_out, no_cache, strict_docs, fail_on_block):
    """Scan manifests (requirements.txt, package.json) and install commands in docs/scripts (.md, .sh, Dockerfile, CI YAML)."""
    if no_cache:
        os.environ["UNSLOP_NO_CACHE"] = "1"
    only_list = [x.strip() for x in only.split(",")] if only else None
    engine = HallucinationEngine()
    reports: list[ScanReport] = []
    errors: list[tuple[str, str]] = []   # files that could not be scanned; the rest are still scanned

    for manifest in manifests:
        try:
            if is_doc_file(manifest):
                click.echo(f"Scanning install commands in {manifest}" + (f" (new since {base_ref})" if base_ref else "") + " ...")
                found = scan_doc(manifest, engine, base_ref, only_list, strict_docs)
                if not found:
                    click.echo("  no new install commands found" if base_ref else "  no install commands found")
                reports.extend(found)
                continue
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
        except (ValueError, OSError) as e:
            errors.append((str(manifest), str(e)))
            click.secho(f"Error: {_plain(str(manifest))}: {_plain(str(e))}", fg="red", err=True)

    click.echo()
    for report in reports:
        click.echo(f"{_plain(report.manifest)}  |  ecosystem: {report.ecosystem}  |  packages checked: {report.total_packages}")
        click.echo("-" * 60)
        if report.total_packages == 0:
            click.echo("No packages to scan.\n")
        for group, assessments in (("block", report.blocked), ("warn", report.warned), ("pass", report.passed)):
            for a in assessments:
                click.secho(f"{VERDICT_ICON[group]}  {safe_name(a.package)}  (risk: {a.risk_score}/100)",
                            fg=VERDICT_COLOR[group], bold=True)
                if a.location:
                    click.echo(f"    at {safe_location(a.location)}")
                for reason in a.reasons:
                    click.echo(f"    - {reason}")
                click.echo()

    blocked = sum(len(r.blocked) for r in reports)
    warned = sum(len(r.warned) for r in reports)
    passed = sum(len(r.passed) for r in reports)
    click.echo("-" * 60)
    click.echo(f"Summary: {blocked} blocked, {warned} warned, {passed} passed."
               + (f" {len(errors)} file(s) could not be scanned." if errors else ""))

    if json_out:
        payload = {
            "summary": {"blocked": blocked, "warned": warned, "passed": passed},
            "reports": [r.to_dict() for r in reports],
            "errors": [{"file": f, "error": m} for f, m in errors],
        }
        json_out.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")
        click.echo(f"JSON report written to {json_out}")
    if sarif_out:
        sarif_out.write_text(json.dumps(to_sarif(reports), indent=2), encoding="utf-8")
        click.echo(f"SARIF report written to {sarif_out}")
    if md_out:
        md_out.write_text(render_markdown(reports, errors), encoding="utf-8")
        click.echo(f"Markdown report written to {md_out}")

    if fail_on_block and blocked:
        click.secho("\nBuild gate: FAILED (blocked packages found)", fg="red", bold=True)
        sys.exit(1)
    if errors:
        click.secho(f"\nBuild gate: FAILED ({len(errors)} file(s) could not be scanned)", fg="red", bold=True)
        sys.exit(2)
    click.secho("\nBuild gate: PASSED", fg="green", bold=True)


@main.command()
@click.argument("files", nargs=-1, type=click.Path(exists=True, path_type=Path))
@click.option("--base", "base_ref", default=None, help="Git ref to compare against (only what changed is checked; needed for the secret scan).")
@click.option("--policy", "policy_path", type=click.Path(path_type=Path), default=None, help="Policy file (default: unslop.toml if it exists).")
@click.option("--markdown", "md_out", type=click.Path(path_type=Path), default=None, help="Write the pull request comment here.")
@click.option("--json", "json_out", type=click.Path(path_type=Path), default=None, help="Write the full result as JSON here.")
@click.option("--sarif", "sarif_out", type=click.Path(path_type=Path), default=None, help="Write SARIF 2.1.0 here.")
@click.option("--sbom", "sbom_out", type=click.Path(path_type=Path), default=None, help="Write a CycloneDX SBOM of the scanned manifests here.")
@click.option("--github-output", "gh_out", type=click.Path(path_type=Path), default=None, help="Append findings=, scanned= and blocked= for GitHub Actions.")
@click.option("--strict-docs", is_flag=True, default=False, help="Keep BLOCK for unknown packages found in docs and scripts.")
@click.option("--no-vulns", is_flag=True, default=False, help="Skip the OSV vulnerability lookup.")
@click.option("--no-cache", is_flag=True, default=False, help="Do not read or write the local registry cache.")
def gate(files, base_ref, policy_path, md_out, json_out, sarif_out, sbom_out, gh_out, strict_docs, no_vulns, no_cache):
    """CI/CD security gate: new dependencies (slopsquatting), known vulnerabilities, secrets in added lines, SBOM, policy.

    Exit codes: 0 passed, 1 blocked by policy, 2 could not run (or lookups failed and the policy says fail_on_error)."""
    if no_cache:
        os.environ["UNSLOP_NO_CACHE"] = "1"
    try:
        policy = load_policy(policy_path or (Path("unslop.toml") if Path("unslop.toml").exists() else None))
        res = run_gate(list(files), base_ref, policy, strict_docs=strict_docs, skip_vulns=no_vulns)
    except (PolicyError, GitError) as e:
        _fail(str(e))
        return
    click.echo("Unslop CI/CD security gate")
    click.echo("-" * 60)
    for rep in res.reports:
        for group, items in (("block", rep.blocked), ("warn", rep.warned)):
            for a in items:
                click.secho(f"{VERDICT_ICON[group]}  {safe_name(a.package)} ({a.ecosystem}, risk {a.risk_score}/100)"
                            + (f"  at {safe_location(a.location)}" if a.location else ""), fg=VERDICT_COLOR[group], bold=True)
    for v in res.vulns:
        click.secho(f"VULN  {safe_name(v.package)} {safe_name(v.version)}  {safe_name(v.id)}  [{v.severity}]"
                    + (f"  fixed in {', '.join(v.fixed_in)}" if v.fixed_in else ""), fg="red" if v.severity in ("critical", "high") else "yellow")
    for sf in res.secrets:
        click.secho(f"SECRET  {sf.name} at {safe_location(f'{sf.file}:{sf.line}')}  {sf.preview}  [waiver id: secret:{sf.fingerprint}]",
                    fg="red" if sf.severity == "block" else "yellow")
    for note in res.notes:
        click.echo(f"note: {note}")
    for err in res.errors:
        click.secho(f"error: {_plain(err)}", fg="yellow", err=True)
    click.echo("-" * 60)
    click.echo(f"dependencies checked: {res.scanned} | pinned dependencies checked for vulnerabilities: {res.deps_checked} | "
               f"vulnerabilities: {len(res.vulns)} | secrets: {len(res.secrets)} | SBOM components: {len(res.sbom.get('components', []))}")
    for w in res.waived:
        click.echo(f"waived: {w}")
    outputs = [(md_out, render_gate_markdown(res)), (json_out, json.dumps(to_json(res), indent=2)),
               (sarif_out, json.dumps(to_sarif(res.reports, res.vulns, res.secrets), indent=2)), (sbom_out, json.dumps(res.sbom, indent=2))]
    for target, text in outputs:
        if target:
            target.write_text(text, encoding="utf-8")
    if gh_out:
        with gh_out.open("a", encoding="utf-8") as fh:
            fh.write(f"findings={res.findings}\nscanned={res.scanned}\nblocked={'true' if res.blockers else 'false'}\n")
    if res.blockers:
        click.secho("Decision: BLOCKED", fg="red", bold=True)
        for b in res.blockers:
            click.echo(f"  - {_plain(b)}")
        sys.exit(1)
    if res.errors and policy.fail_on_error:
        click.secho("Decision: FAILED (lookups did not complete and fail_on_error is set)", fg="red", bold=True)
        sys.exit(2)
    click.secho("Decision: PASSED", fg="green", bold=True)


@main.command()
@click.argument("manifests", nargs=-1, required=True, type=click.Path(exists=True, path_type=Path))
@click.option("--output", "-o", type=click.Path(path_type=Path), default=Path("sbom.cdx.json"), show_default=True)
def sbom(manifests, output):
    """Write a CycloneDX 1.5 SBOM for dependency files (requirements.txt, package.json, package-lock.json, pyproject.toml)."""
    by_file, bad = {}, 0
    for m in manifests:
        try:
            by_file[str(m)] = manifest_deps(m)
        except (ValueError, OSError) as e:
            bad += 1
            click.secho(f"Error: {_plain(str(m))}: {_plain(str(e))}", fg="red", err=True)
    doc = build_sbom(by_file)
    output.write_text(json.dumps(doc, indent=2), encoding="utf-8")
    click.echo(f"{len(doc['components'])} components written to {output}")
    if bad:
        sys.exit(2)

if __name__ == "__main__":
    main()
