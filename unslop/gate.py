"""gate.py - the CI/CD security gate: slopsquatting, known vulnerabilities, secrets, SBOM and policy in one run."""
from __future__ import annotations

import datetime as dt
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Optional

from . import secretscan, vulns
from .deps import Dep, added_deps, manifest_deps
from .docscan import is_doc_file, scan_doc
from .gitdiff import added_packages
from .heuristics import HallucinationEngine
from .policy import Policy
from .report import _cell, render_markdown, safe_location, safe_name
from .sbom import build_sbom
from .scanner import ScanReport, ecosystem_for, scan_manifest

MARKER = "<!-- unslop-comment -->"


@dataclass
class GateResult:
    reports: list[ScanReport] = field(default_factory=list)
    vulns: list[vulns.Vuln] = field(default_factory=list)
    secrets: list[secretscan.SecretFinding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    blockers: list[str] = field(default_factory=list)
    waived: list[str] = field(default_factory=list)
    sbom: dict = field(default_factory=dict)
    deps_checked: int = 0

    @property
    def scanned(self) -> int:
        return sum(r.total_packages for r in self.reports)

    @property
    def findings(self) -> int:
        return (sum(len(r.blocked) + len(r.warned) for r in self.reports) + len(self.vulns) + len(self.secrets))


def run_gate(files: list[Path], base_ref: Optional[str], policy: Policy, strict_docs: bool = False,
             skip_vulns: bool = False, today: Optional[dt.date] = None) -> GateResult:
    today = today or dt.date.today()
    engine = HallucinationEngine()
    res = GateResult()
    full: dict[str, list[Dep]] = {}
    to_check: list[tuple[str, Dep]] = []

    for path in files:
        try:
            if is_doc_file(path):
                res.reports.extend(scan_doc(path, engine, base_ref, None, strict_docs))
                continue
            ecosystem_for(path)
            names = added_packages(path, base_ref) if base_ref else None
            res.reports.append(scan_manifest(path, engine=engine, only_new=names))
            full[str(path)] = manifest_deps(path)
            deps = added_deps(path, base_ref) if base_ref else full[str(path)]
            to_check += [(str(path), d) for d in deps if d.version]
        except (ValueError, OSError) as e:
            res.errors.append(f"{path}: {e}")

    if skip_vulns or vulns.skipped():
        res.notes.append("vulnerability check skipped")
    else:
        res.vulns, errs = vulns.check(to_check)
        res.errors += errs
        res.deps_checked = len({(f, d) for f, d in to_check})

    if base_ref:
        try:
            res.secrets = secretscan.scan_diff(secretscan.added_lines_diff(base_ref))
        except ValueError as e:
            res.errors.append(str(e))
    else:
        res.notes.append("secret scan skipped (it needs --base to know which lines are new)")

    res.sbom = build_sbom(full)
    _decide(res, policy, today)
    return res


def _decide(res: GateResult, policy: Policy, today: dt.date) -> None:
    def judge(label: str, keys: list[str], blocking: bool) -> None:
        waiver, expired = policy.waiver_for(keys, today)
        if waiver:
            res.waived.append(f"{label}: waived ({waiver.reason})" + (f", until {waiver.expires}" if waiver.expires else ""))
        else:
            if expired:
                res.waived.append(f"{label}: the waiver has expired")
            if blocking:
                res.blockers.append(label)

    for rep in res.reports:
        for a in rep.blocked:
            judge(f"suspicious dependency `{safe_name(a.package)}` ({a.ecosystem})", [f"pkg:{a.ecosystem}:{a.package}"],
                  policy.block_on_slopsquat)
    for v in res.vulns:
        judge(f"`{safe_name(v.package)}` {safe_name(v.version)} has {v.severity} vulnerability {safe_name(v.id)}",
              [v.id, *v.aliases], policy.vuln_blocks(v.severity))
    for s in res.secrets:
        judge(f"{s.name} at `{safe_location(f'{s.file}:{s.line}')}`", [f"secret:{s.fingerprint}"],
              s.severity == "block" and policy.block_on_secret)


def render_gate_markdown(res: GateResult) -> str:
    out = [MARKER, "## Unslop CI/CD security gate", ""]
    out.append(f"**BLOCKED** by {len(res.blockers)} policy violation(s)." if res.blockers else "**Passed.** No policy violations.")
    out.append("")
    sev = {}
    for v in res.vulns:
        sev[v.severity] = sev.get(v.severity, 0) + 1
    out += ["| Check | Result |", "|---|---|",
            f"| Slopsquatting (new dependencies) | {sum(len(r.blocked) for r in res.reports)} blocked, "
            f"{sum(len(r.warned) for r in res.reports)} warned, {res.scanned} checked |",
            f"| Known vulnerabilities | {len(res.vulns)} found in {res.deps_checked} pinned dependencies"
            + (" (" + ", ".join(f"{n} {k}" for k, n in sev.items()) + ")" if sev else "") + " |",
            f"| Secrets in added lines | {len(res.secrets)} |",
            f"| SBOM | {len(res.sbom.get('components', []))} components (CycloneDX, attached to the run) |", ""]
    if res.blockers:
        out += ["### Why it is blocked", ""] + [f"- {b}" for b in res.blockers] + [""]
    if res.vulns:
        out += ["### Vulnerabilities", "", "| Package | Version | Advisory | Severity | Fixed in |", "|---|---|---|---|---|"]
        for v in res.vulns:
            out.append(f"| `{safe_name(v.package)}` | {_cell(safe_name(v.version))} | {_cell(safe_name(v.id))} | {v.severity}"
                       f"{'' if v.score is None else f' ({v.score})'} | {_cell(', '.join(safe_name(f) for f in v.fixed_in) or 'n/a')} |")
        out.append("")
    if res.secrets:
        out += ["### Secrets (values are never shown)", "", "| Type | Location | Preview | Waiver id |", "|---|---|---|---|"]
        for s in res.secrets:
            out.append(f"| {_cell(s.name)} | `{safe_location(f'{s.file}:{s.line}')}` | {_cell(s.preview)} | `secret:{s.fingerprint}` |")
        out.append("")
    if res.waived:
        out += ["### Waived", ""] + [f"- {w}" for w in res.waived] + [""]
    if res.errors or res.notes:
        out += ["### Notes", ""] + [f"- Could not complete: {_cell(e)}" for e in res.errors] + [f"- {n}" for n in res.notes] + [""]
    if res.reports:
        out.append(render_markdown(res.reports).replace(MARKER + "\n", "", 1))
    else:
        out.append("_Unslop checks new dependencies, known vulnerabilities and secrets. A warning is a signal to verify, not proof of malice._")
    return "\n".join(out)


def to_json(res: GateResult) -> dict:
    return {"blocked": bool(res.blockers), "blockers": res.blockers, "waived": res.waived, "errors": res.errors, "notes": res.notes,
            "reports": [r.to_dict() for r in res.reports], "vulnerabilities": [asdict(v) for v in res.vulns],
            "secrets": [asdict(s) for s in res.secrets], "sbom_components": len(res.sbom.get("components", []))}
