"""
scanner.py

Ties registry_client + heuristics together into one scan pipeline:
  1. Parse a manifest file (requirements.txt or package.json) for package names
  2. Pull registry metadata for each
  3. Run the risk engine
  4. Return a structured report (used by both the CLI and the future
     GitHub Action / dashboard JSON export)
"""

from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Optional

from .heuristics import HallucinationEngine, RiskAssessment
from .registry_client import fetch_metadata


def parse_requirements_txt(path: Path) -> list[str]:
    names = []
    for raw_line in path.read_text().splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        # strip version specifiers / extras: "requests==2.31.0" -> "requests"
        name = re.split(r"[<>=!~\[; ]", line, maxsplit=1)[0].strip()
        if name:
            names.append(name)
    return names


def parse_package_json(path: Path) -> list[str]:
    data = json.loads(path.read_text())
    names = []
    for field_name in ("dependencies", "devDependencies"):
        names.extend((data.get(field_name) or {}).keys())
    return names


def detect_manifest(path: Path) -> tuple[str, list[str]]:
    """Returns (ecosystem, package_names) for a given manifest file path.

    Matches by suffix/content rather than an exact filename, so demo/test
    fixtures (e.g. demo_package.json) work the same as real project files.
    """
    if path.suffix == ".json":
        return "npm", parse_package_json(path)
    if path.suffix == ".txt" or "requirements" in path.name:
        return "pypi", parse_requirements_txt(path)
    raise ValueError(f"Unsupported manifest file: {path.name}")


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


def scan_manifest(
    path: Path,
    engine: Optional[HallucinationEngine] = None,
    only_new: Optional[list[str]] = None,
) -> ScanReport:
    """
    Scan a manifest file. If `only_new` is given (a list of package names,
    e.g. the ones added in a PR diff), only those are checked - this is
    what the GitHub Action uses to keep scans fast and comments relevant.
    """
    engine = engine or HallucinationEngine()
    ecosystem, names = detect_manifest(path)

    if only_new is not None:
        wanted = {n.lower() for n in only_new}
        names = [n for n in names if n.lower() in wanted]

    report = ScanReport(manifest=str(path), ecosystem=ecosystem, total_packages=len(names))

    for name in names:
        meta = fetch_metadata(name, ecosystem)
        assessment = engine.assess(name, meta)
        if assessment.verdict == "block":
            report.blocked.append(assessment)
        elif assessment.verdict == "warn":
            report.warned.append(assessment)
        else:
            report.passed.append(assessment)

    return report
