"""sarif.py - SARIF 2.1.0 output so findings appear in GitHub's code-scanning tab and other SARIF viewers."""
from __future__ import annotations

from pathlib import Path

from . import __version__
from .report import safe_location, safe_name
from .scanner import ScanReport

INFO_URI = "https://github.com/gaurav-11-cyber/Unslop"
RULE_ID = "UNSLOP001"
RULES = [
    {"id": "UNSLOP001", "name": "SuspiciousDependency", "shortDescription": {"text": "Dependency may be AI-hallucinated or slopsquatted"},
     "fullDescription": {"text": "The package name is a documented incident, does not exist in the registry, resembles a popular package, "
                                 "or has weak trust signals."}},
    {"id": "UNSLOP002", "name": "VulnerableDependency", "shortDescription": {"text": "Dependency has a known vulnerability"},
     "fullDescription": {"text": "The pinned version matches an advisory in the OSV database."}},
    {"id": "UNSLOP003", "name": "HardCodedSecret", "shortDescription": {"text": "A secret was added to the repository"},
     "fullDescription": {"text": "A line added by this change matches a known secret format. The value is never reported."}},
]


def _uri(path_text: str) -> str:
    p = Path(path_text)
    try:
        if p.is_absolute():
            p = p.resolve().relative_to(Path.cwd().resolve())
    except ValueError:
        pass
    return p.as_posix()


def _split(location: str) -> tuple[str, int]:
    path, _, line = location.rpartition(":")
    return (path, int(line)) if path and line.isdigit() else (location, 1)


def _result(rule: str, level: str, text: str, location: str, fingerprint: str) -> dict:
    file_, line = _split(location)
    file_ = _uri(file_)
    return {"ruleId": rule, "level": level, "message": {"text": text[:1000]},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": safe_location(file_)}, "region": {"startLine": max(1, line)}}}],
            "partialFingerprints": {"unslopFinding/v1": fingerprint}}


def to_sarif(reports: list[ScanReport], vulns=(), secrets=()) -> dict:
    results = []
    for rep in reports:
        fallback = rep.manifest.removesuffix(" (install commands)")
        for a in rep.blocked + rep.warned:
            text = f"{safe_name(a.package)} ({a.ecosystem}): {a.verdict.upper()}, risk {a.risk_score}/100. " + " ".join(a.reasons)
            results.append(_result("UNSLOP001", "error" if a.verdict == "block" else "warning", text,
                                   a.location or fallback, f"{a.ecosystem}:{a.package.lower()}:{safe_location(_uri(_split(a.location or fallback)[0]))}"))
    for v in vulns:
        level = "error" if v.severity in ("critical", "high") else "warning" if v.severity in ("medium", "unknown") else "note"
        text = (f"{safe_name(v.package)} {safe_name(v.version)} ({v.ecosystem}): {v.severity} vulnerability {safe_name(v.id)}. {v.summary} "
                + (f"Fixed in {', '.join(v.fixed_in)}." if v.fixed_in else ""))
        results.append(_result("UNSLOP002", level, text, v.location or "", f"{v.ecosystem}:{v.package.lower()}:{v.version}:{v.id}"))
    for s in secrets:
        results.append(_result("UNSLOP003", "error" if s.severity == "block" else "warning",
                               f"{s.name} added (value hidden, fingerprint {s.fingerprint}).", f"{s.file}:{s.line}", f"secret:{s.fingerprint}"))
    rules = [{**r, "helpUri": INFO_URI, "defaultConfiguration": {"level": "warning"}} for r in RULES]
    return {"$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0",
            "runs": [{"tool": {"driver": {"name": "Unslop", "version": __version__, "informationUri": INFO_URI, "rules": rules}},
                      "results": results}]}
