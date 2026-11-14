"""sarif.py - SARIF 2.1.0 output so findings appear in GitHub's code-scanning tab and other SARIF viewers."""
from __future__ import annotations

from pathlib import Path

from . import __version__
from .report import safe_location, safe_name
from .scanner import ScanReport

INFO_URI = "https://github.com/gaurav-11-cyber/Unslop"
RULE_ID = "UNSLOP001"


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


def to_sarif(reports: list[ScanReport]) -> dict:
    results = []
    for rep in reports:
        fallback = rep.manifest.removesuffix(" (install commands)")
        for a in rep.blocked + rep.warned:
            file_, line = _split(a.location) if a.location else (fallback, 1)
            file_ = _uri(file_)
            text = f"{safe_name(a.package)} ({a.ecosystem}): {a.verdict.upper()}, risk {a.risk_score}/100. " + " ".join(a.reasons)
            results.append({
                "ruleId": RULE_ID,
                "level": "error" if a.verdict == "block" else "warning",
                "message": {"text": text[:1000]},
                "locations": [{"physicalLocation": {"artifactLocation": {"uri": safe_location(file_)},
                                                    "region": {"startLine": max(1, line)}}}],
                "partialFingerprints": {"unslopPackage/v1": f"{a.ecosystem}:{a.package.lower()}:{safe_location(file_)}"},
            })
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "Unslop", "version": __version__, "informationUri": INFO_URI,
                "rules": [{
                    "id": RULE_ID, "name": "SuspiciousDependency",
                    "shortDescription": {"text": "Dependency may be AI-hallucinated or slopsquatted"},
                    "fullDescription": {"text": "The package name is a documented incident, does not exist in the registry, "
                                                "resembles a popular package, or has weak trust signals."},
                    "helpUri": INFO_URI, "defaultConfiguration": {"level": "warning"}}]}},
            "results": results,
        }],
    }
