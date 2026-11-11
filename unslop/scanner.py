"""
scanner.py

Ties registry_client + heuristics together into one scan pipeline:
  1. Parse a manifest (requirements.txt or package.json) into package names
  2. Pull registry metadata for each
  3. Run the risk engine
  4. Return a structured report (used by the CLI, the PR comment and JSON export)

Parsing works on text (not only files) so the same code can read a manifest
from disk and from an older git revision (see gitdiff.py).
"""

from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Optional

from .heuristics import HallucinationEngine, RiskAssessment
from .registry_client import fetch_metadata

# Names that PyPI/npm actually allow. Anything else is never sent to a registry
# (it could be a path trick like "../x") and is flagged instead.
VALID_NAME = re.compile(r"^(@[A-Za-z0-9][A-Za-z0-9._~+-]*/)?[A-Za-z0-9][A-Za-z0-9._~+-]*$")


def parse_requirements_text(text: str) -> list[str]:
    names = []
    for raw_line in text.splitlines():
        line = raw_line.split(" #", 1)[0].strip()
        if not line or line.startswith(("#", "-")) or "://" in line:
            continue
        # "requests==2.31.0" -> "requests", "pkg[extra]>=1; python_version<'3.9'" -> "pkg"
        name = re.split(r"[<>=!~\[; ]", line, maxsplit=1)[0].strip()
        if name:
            names.append(name)
    return names


def parse_package_json_text(text: str) -> list[str]:
    try:
        data = json.loads(text)
    except json.JSONDecodeError as e:
        raise ValueError(f"invalid JSON: {e}") from e
    if not isinstance(data, dict):
        raise ValueError("package.json must contain a JSON object")
    names = []
    for field_name in ("dependencies", "devDependencies"):
        section = data.get(field_name) or {}
        if isinstance(section, dict):
            names.extend(section.keys())
    return names


def ecosystem_for(path: Path) -> str:
    """'pypi' or 'npm', decided from the file name."""
    if path.suffix == ".json":
        return "npm"
    if path.suffix == ".txt" or "requirements" in path.name:
        return "pypi"
    raise ValueError(f"Unsupported manifest file: {path.name}")


def parse_names(ecosystem: str, text: str) -> list[str]:
    if ecosystem == "npm":
        return parse_package_json_text(text)
    return parse_requirements_text(text)


def detect_manifest(path: Path) -> tuple[str, list[str]]:
    """Returns (ecosystem, package_names) for a manifest file on disk."""
    ecosystem = ecosystem_for(path)
    return ecosystem, parse_names(ecosystem, path.read_text(encoding="utf-8"))


@dataclass
class ScanReport:
    manifest: str
    ecosystem: str
    total_packages: int
    blocked: list[RiskAssessment] = field(default_factory=list)
    warned: list[RiskAssessment] = field(default_factory=list)
    passed: list[RiskAssessment] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "manifest": self.manifest,
            "ecosystem": self.ecosystem,
            "total_packages": self.total_packages,
            "blocked": [asdict(a) for a in self.blocked],
            "warned": [asdict(a) for a in self.warned],
            "passed": [asdict(a) for a in self.passed],
        }

    @property
    def should_fail_build(self) -> bool:
        return len(self.blocked) > 0


def _invalid_name_assessment(name: str, ecosystem: str) -> RiskAssessment:
    return RiskAssessment(
        package=name,
        ecosystem=ecosystem,
        risk_score=50,
        verdict="warn",
        reasons=["Not a valid package name; registry lookup skipped."],
    )


def scan_manifest(
    path: Path,
    engine: Optional[HallucinationEngine] = None,
    only_new: Optional[list[str]] = None,
) -> ScanReport:
    """
    Scan a manifest file. If `only_new` is given (e.g. the packages added in a
    PR diff), only those are checked.
    """
    engine = engine or HallucinationEngine()
    ecosystem, names = detect_manifest(path)

    if only_new is not None:
        wanted = {n.lower() for n in only_new}
        names = [n for n in names if n.lower() in wanted]

    report = ScanReport(manifest=str(path), ecosystem=ecosystem, total_packages=len(names))

    for name in names:
        if not VALID_NAME.match(name):
            assessment = _invalid_name_assessment(name, ecosystem)
        else:
            assessment = engine.assess(name, fetch_metadata(name, ecosystem))
        if assessment.verdict == "block":
            report.blocked.append(assessment)
        elif assessment.verdict == "warn":
            report.warned.append(assessment)
        else:
            report.passed.append(assessment)

    return report
