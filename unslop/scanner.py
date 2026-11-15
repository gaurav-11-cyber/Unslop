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
from concurrent.futures import ThreadPoolExecutor
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
        if not line or line.startswith(("#", "-", ".", "/", "~", "file:")) or "://" in line:
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
    for field_name in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
        section = data.get(field_name) or {}
        if isinstance(section, dict):
            names.extend(section.keys())
    return names


def parse_package_lock_text(text: str) -> list[str]:
    """Package names from package-lock.json (lockfile v2/v3 `packages`, or v1 nested `dependencies`)."""
    try:
        data = json.loads(text)
    except json.JSONDecodeError as e:
        raise ValueError(f"invalid JSON: {e}") from e
    if not isinstance(data, dict):
        raise ValueError("package-lock.json must contain a JSON object")
    names: list[str] = []
    packages = data.get("packages")
    if isinstance(packages, dict):
        for key, info in packages.items():
            if key and "node_modules/" in key and not (isinstance(info, dict) and info.get("link")):
                names.append(key.rsplit("node_modules/", 1)[1])
    else:
        def walk(deps):
            for name, info in (deps or {}).items():
                names.append(name)
                if isinstance(info, dict):
                    walk(info.get("dependencies"))
        walk(data.get("dependencies"))
    return list(dict.fromkeys(names))


def parse_pyproject_text(text: str) -> list[str]:
    """Dependency names from pyproject.toml: PEP 621, PEP 735 dependency-groups and Poetry."""
    try:
        import tomllib
    except ImportError as e:  # Python < 3.11
        raise ValueError("pyproject.toml scanning needs Python 3.11+ (tomllib)") from e
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError as e:
        raise ValueError(f"invalid TOML: {e}") from e
    specs: list[str] = []
    project = data.get("project") or {}
    specs += [x for x in project.get("dependencies") or [] if isinstance(x, str)]
    for group in (project.get("optional-dependencies") or {}).values():
        specs += [x for x in group if isinstance(x, str)]
    for group in (data.get("dependency-groups") or {}).values():
        specs += [x for x in group if isinstance(x, str)]
    names = [re.split(r"[<>=!~\[;\s(@]", s.strip(), maxsplit=1)[0] for s in specs]
    poetry = (data.get("tool") or {}).get("poetry") or {}
    tables = [poetry.get("dependencies"), poetry.get("dev-dependencies")]
    tables += [g.get("dependencies") for g in (poetry.get("group") or {}).values() if isinstance(g, dict)]
    for table in tables:
        if isinstance(table, dict):
            names += [k for k in table if k.lower() != "python"]
    return [n for n in dict.fromkeys(names) if n]


def locate(text: str, name: str) -> int:
    """1-based line of the first whole-token occurrence of `name` (1 if not found)."""
    pat = re.compile(r"(?<![\w.-])" + re.escape(name) + r"(?![\w.-])", re.I)
    for i, line in enumerate(text.splitlines(), 1):
        if pat.search(line):
            return i
    return 1


def ecosystem_for(path: Path) -> str:
    """'pypi' or 'npm', decided from the file name."""
    if path.name == "pyproject.toml":
        return "pypi"
    if path.suffix == ".json":
        return "npm"
    if path.suffix == ".txt" or "requirements" in path.name:
        return "pypi"
    raise ValueError(f"Unsupported manifest file: {path.name}")


def parse_names(ecosystem: str, text: str, filename: str = "") -> list[str]:
    text = text.removeprefix("\ufeff")          # UTF-8 byte-order mark written by some Windows editors
    if ecosystem == "npm":
        return parse_package_lock_text(text) if filename == "package-lock.json" else parse_package_json_text(text)
    return parse_pyproject_text(text) if filename == "pyproject.toml" else parse_requirements_text(text)


def detect_manifest(path: Path) -> tuple[str, list[str]]:
    """Returns (ecosystem, package_names) for a manifest file on disk."""
    ecosystem = ecosystem_for(path)
    return ecosystem, parse_names(ecosystem, path.read_text(encoding="utf-8"), path.name)


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
    report = scan_items(str(path), ecosystem, [(n, None) for n in names], engine)
    flagged = report.blocked + report.warned
    if flagged:                                    # point findings at a line in the file
        text = path.read_text(encoding="utf-8", errors="replace")
        for a in flagged:
            a.location = a.location or f"{path}:{locate(text, a.package)}"
    return report


def scan_items(
    label: str,
    ecosystem: str,
    items: list[tuple[str, Optional[str]]],
    engine: Optional[HallucinationEngine] = None,
    docs: bool = False,
    strict_docs: bool = False,
) -> ScanReport:
    """
    Score (name, location) pairs. In docs mode (names pulled from READMEs, scripts, CI
    files) a BLOCK that is not a documented incident is downgraded to WARN, because docs
    often mention unreleased, example or in-house package names. --strict-docs keeps BLOCK.
    """
    engine = engine or HallucinationEngine()
    report = ScanReport(manifest=label, ecosystem=ecosystem, total_packages=len(items))
    names = [n for n, _ in items]

    def established(n: str) -> bool:   # top-5,000 package and not a documented incident: no lookup needed
        return engine.is_popular(n, ecosystem) and engine._known_incident(n, ecosystem) is None

    valid = list(dict.fromkeys(n for n in names if VALID_NAME.match(n) and not established(n)))
    with ThreadPoolExecutor(max_workers=8) as pool:  # registry calls are I/O bound
        metas = dict(zip(valid, pool.map(lambda n: fetch_metadata(n, ecosystem), valid)))

    for name, location in items:
        if name in metas:
            assessment = engine.assess(name, metas[name])
        elif VALID_NAME.match(name):
            assessment = RiskAssessment(package=name, ecosystem=ecosystem, risk_score=0, verdict="pass",
                                        reasons=["Top-5,000 package by downloads; registry lookup skipped."])
        else:
            assessment = _invalid_name_assessment(name, ecosystem)
        assessment.location = location
        if docs and not strict_docs and assessment.verdict == "block" and assessment.known_incident is None:
            assessment.verdict = "warn"
            assessment.reasons.append(
                "Found in docs/scripts, where example or unreleased package names are common, "
                "so BLOCK was downgraded to WARN (--strict-docs keeps BLOCK).")
        if assessment.verdict == "block":
            report.blocked.append(assessment)
        elif assessment.verdict == "warn":
            report.warned.append(assessment)
        else:
            report.passed.append(assessment)
    return report
