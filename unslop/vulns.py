"""vulns.py - known-vulnerability lookup for exactly pinned dependencies, using the free OSV.dev API.

Only packages pinned to one exact version are checked. Severity comes from the advisory's own rating, or is computed
from its CVSS v3 vector. Network problems are returned as errors; they never invent or hide findings.
"""
from __future__ import annotations

import math
import os
import re
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Optional

import requests

from .deps import Dep

OSV = "https://api.osv.dev/v1"
RANK = {"unknown": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
OSV_ECOSYSTEM = {"pypi": "PyPI", "npm": "npm"}


@dataclass
class Vuln:
    id: str
    ecosystem: str
    package: str
    version: str
    severity: str = "unknown"
    score: Optional[float] = None
    summary: str = ""
    aliases: list[str] = field(default_factory=list)
    fixed_in: list[str] = field(default_factory=list)
    location: Optional[str] = None


def _roundup(x: float) -> float:
    i = round(x * 100000)
    return i / 100000.0 if i % 10000 == 0 else (math.floor(i / 10000) + 1) / 10.0


def cvss3_score(vector: str) -> Optional[float]:
    """CVSS v3.x base score from a vector string, or None if it is not a valid v3 vector."""
    try:
        parts = dict(p.split(":") for p in vector.split("/")[1:])
        if not vector.startswith("CVSS:3"):
            return None
        av = {"N": .85, "A": .62, "L": .55, "P": .2}[parts["AV"]]
        ac = {"L": .77, "H": .44}[parts["AC"]]
        ui = {"N": .85, "R": .62}[parts["UI"]]
        changed = parts["S"] == "C"
        pr = ({"N": .85, "L": .68, "H": .5} if changed else {"N": .85, "L": .62, "H": .27})[parts["PR"]]
        cia = {"H": .56, "L": .22, "N": 0.0}
        iss = 1 - (1 - cia[parts["C"]]) * (1 - cia[parts["I"]]) * (1 - cia[parts["A"]])
    except (KeyError, ValueError):
        return None
    impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 if changed else 6.42 * iss
    if impact <= 0:
        return 0.0
    exploit = 8.22 * av * ac * pr * ui
    return _roundup(min((impact + exploit) * (1.08 if changed else 1), 10))


def _label(score: float) -> str:
    return "critical" if score >= 9 else "high" if score >= 7 else "medium" if score >= 4 else "low" if score > 0 else "unknown"


def severity_of(record: dict) -> tuple[str, Optional[float]]:
    label = str((record.get("database_specific") or {}).get("severity", "")).lower()
    label = {"moderate": "medium"}.get(label, label)
    best = None
    for s in record.get("severity") or []:
        if str(s.get("type", "")).startswith("CVSS_V3"):
            sc = cvss3_score(str(s.get("score", "")))
            best = max(best, sc) if best is not None and sc is not None else (sc if sc is not None else best)
    if label in RANK and label != "unknown":
        return label, best
    return (_label(best), best) if best is not None else ("unknown", None)


def _fixed(record: dict, package: str) -> list[str]:
    out: list[str] = []
    for aff in record.get("affected") or []:
        if str((aff.get("package") or {}).get("name", "")).lower() != package.lower():
            continue
        for rng in aff.get("ranges") or []:
            out += [e["fixed"] for e in rng.get("events") or [] if "fixed" in e]
    return list(dict.fromkeys(out))[:3]


def check(deps: list[tuple[str, Dep]], session: Optional[requests.Session] = None, timeout: float = 15) -> tuple[list[Vuln], list[str]]:
    """deps: (manifest path, pinned Dep) pairs. Returns (vulnerabilities, error messages)."""
    session = session or requests.Session()
    pinned = [(f, d) for f, d in dict.fromkeys(deps) if d.version and d.ecosystem in OSV_ECOSYSTEM]
    if not pinned:
        return [], []
    errors: list[str] = []
    hits: dict[int, list[str]] = {}
    for start in range(0, len(pinned), 500):
        chunk = pinned[start:start + 500]
        body = {"queries": [{"package": {"name": d.name, "ecosystem": OSV_ECOSYSTEM[d.ecosystem]}, "version": d.version} for _, d in chunk]}
        try:
            r = session.post(f"{OSV}/querybatch", json=body, timeout=timeout)
            r.raise_for_status()
            for i, res in enumerate(r.json().get("results") or []):
                if res and res.get("vulns"):
                    hits[start + i] = [v["id"] for v in res["vulns"] if "id" in v]
        except (requests.RequestException, ValueError, KeyError) as e:
            errors.append(f"vulnerability lookup failed: {type(e).__name__}")

    cache: dict[str, Optional[dict]] = {}

    def fetch(vid: str) -> Optional[dict]:
        if vid not in cache:
            try:
                r = session.get(f"{OSV}/vulns/{vid}", timeout=timeout)
                r.raise_for_status()
                cache[vid] = r.json()
            except (requests.RequestException, ValueError):
                cache[vid] = None
        return cache[vid]

    ids = sorted({v for vs in hits.values() for v in vs})
    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(fetch, ids))
    if any(cache[i] is None for i in ids):
        errors.append("some advisory details could not be fetched")

    out: list[Vuln] = []
    for idx, vids in hits.items():
        file, dep = pinned[idx]
        for vid in vids:
            rec = cache.get(vid)
            if not rec or rec.get("withdrawn"):
                continue
            sev, score = severity_of(rec)
            if sev == "unknown":                       # OSV records from PyPI often lack a rating: try the GHSA alias
                for alias in rec.get("aliases") or []:
                    if alias.startswith("GHSA-"):
                        other = fetch(alias)
                        if other:
                            sev, score = severity_of(other)
                            break
            out.append(Vuln(id=vid, ecosystem=dep.ecosystem, package=dep.name, version=dep.version or "", severity=sev,
                            score=score, summary=(rec.get("summary") or "")[:200], aliases=rec.get("aliases") or [],
                            fixed_in=_fixed(rec, dep.name), location=file))
    out.sort(key=lambda v: (-RANK[v.severity], v.package, v.id))
    return out, list(dict.fromkeys(errors))


def skipped() -> bool:
    return bool(os.environ.get("UNSLOP_SKIP_VULNS"))
