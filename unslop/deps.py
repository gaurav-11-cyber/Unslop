"""deps.py - dependency names WITH versions, needed for the SBOM and for vulnerability lookups.

A version is only reported when the file pins ONE exact version (requirements `==`, a lockfile entry, an exact
package.json version). Ranges such as ^1.2.0 or >=2 are reported as unpinned (version None): we never guess.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from .gitdiff import _normalize, read_at_ref
from .scanner import ecosystem_for

NPM_EXACT = re.compile(r"^=?v?(\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?)$")
PY_EXACT = re.compile(r"^===?\s*([A-Za-z0-9][A-Za-z0-9._+!-]*)$")
PY_PLAIN = re.compile(r"^\d+(?:\.\d+)*$")


@dataclass(frozen=True)
class Dep:
    ecosystem: str
    name: str
    version: Optional[str] = None


def _pep508(spec: str) -> Optional[Dep]:
    spec = spec.split("#", 1)[0].split(";", 1)[0].strip()
    m = re.match(r"([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*(.*)$", spec)
    if not m:
        return None
    pin = PY_EXACT.match(m.group(2).strip().strip("()"))
    return Dep("pypi", m.group(1), pin.group(1) if pin else None)


def _requirements(text: str) -> list[Dep]:
    out = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith(("#", "-", ".", "/", "~", "file:")) or "://" in line:
            continue
        d = _pep508(line)
        if d:
            out.append(d)
    return out


def _pyproject(text: str) -> list[Dep]:
    try:
        import tomllib
    except ImportError as e:
        raise ValueError("pyproject.toml scanning needs Python 3.11+ (tomllib)") from e
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError as e:
        raise ValueError(f"invalid TOML: {e}") from e
    specs: list[str] = []
    project = data.get("project") or {}
    specs += [x for x in project.get("dependencies") or [] if isinstance(x, str)]
    for group in list((project.get("optional-dependencies") or {}).values()) + list((data.get("dependency-groups") or {}).values()):
        specs += [x for x in group if isinstance(x, str)]
    deps = [d for d in map(_pep508, specs) if d]
    poetry = (data.get("tool") or {}).get("poetry") or {}
    tables = [poetry.get("dependencies"), poetry.get("dev-dependencies")]
    tables += [g.get("dependencies") for g in (poetry.get("group") or {}).values() if isinstance(g, dict)]
    for table in tables:
        for name, val in (table or {}).items():
            if name.lower() == "python":
                continue
            v = val.get("version") if isinstance(val, dict) else val
            deps.append(Dep("pypi", name, v if isinstance(v, str) and PY_PLAIN.match(v) else None))
    return deps


def _package_json(text: str) -> list[Dep]:
    try:
        data = json.loads(text)
    except json.JSONDecodeError as e:
        raise ValueError(f"invalid JSON: {e}") from e
    if not isinstance(data, dict):
        raise ValueError("package.json must contain a JSON object")
    out = []
    for field in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
        section = data.get(field)
        if isinstance(section, dict):
            for name, rng in section.items():
                m = NPM_EXACT.match(rng) if isinstance(rng, str) else None
                out.append(Dep("npm", name, m.group(1) if m else None))
    return out


def _package_lock(text: str) -> list[Dep]:
    try:
        data = json.loads(text)
    except json.JSONDecodeError as e:
        raise ValueError(f"invalid JSON: {e}") from e
    if not isinstance(data, dict):
        raise ValueError("package-lock.json must contain a JSON object")
    out: list[Dep] = []
    packages = data.get("packages")
    if isinstance(packages, dict):
        for key, info in packages.items():
            if key and "node_modules/" in key and isinstance(info, dict) and not info.get("link"):
                out.append(Dep("npm", key.rsplit("node_modules/", 1)[1], info.get("version")))
    else:
        def walk(deps):
            for name, info in (deps or {}).items():
                if isinstance(info, dict):
                    out.append(Dep("npm", name, info.get("version")))
                    walk(info.get("dependencies"))
        walk(data.get("dependencies"))
    return out


def parse_deps(ecosystem: str, text: str, filename: str = "") -> list[Dep]:
    text = text.removeprefix("\ufeff")
    if ecosystem == "npm":
        found = _package_lock(text) if filename == "package-lock.json" else _package_json(text)
    else:
        found = _pyproject(text) if filename == "pyproject.toml" else _requirements(text)
    return list(dict.fromkeys(found))


def manifest_deps(path: Path) -> list[Dep]:
    return parse_deps(ecosystem_for(path), path.read_text(encoding="utf-8"), path.name)


def added_deps(path: Path, base_ref: str) -> list[Dep]:
    """Dependencies whose (name, version) pair is new or changed compared with the base ref."""
    eco = ecosystem_for(path)
    head = manifest_deps(path)
    base_text = read_at_ref(path, base_ref)
    if base_text is None:
        return head
    try:
        base = parse_deps(eco, base_text, path.name)
    except ValueError:
        base = []
    seen = {(_normalize(d.name, eco), d.version) for d in base}
    return [d for d in head if (_normalize(d.name, eco), d.version) not in seen]
