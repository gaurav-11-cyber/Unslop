"""
heuristics.py

The actual "is this package suspicious" brain. Combines three signals:
  1. Known-hallucination corpus lookup (exact match against documented incidents)
  2. Typosquat / conflation similarity against a popular-package list
  3. Registry metadata red flags (new, low downloads, no repo, few maintainers)

Produces a 0-100 risk score + human-readable reasons, so the CI comment
and dashboard can both explain *why* something got flagged, not just that
it did.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from .registry_client import PackageMetadata

DATA_DIR = Path(__file__).resolve().parent / "data"


def _levenshtein(a: str, b: str) -> int:
    """Classic edit-distance DP. No external dependency needed for this."""
    if a == b:
        return 0
    if len(a) < len(b):
        a, b = b, a
    if len(b) == 0:
        return len(a)

    previous_row = list(range(len(b) + 1))
    for i, ca in enumerate(a):
        current_row = [i + 1]
        for j, cb in enumerate(b):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (ca != cb)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    return previous_row[-1]


def similarity_ratio(a: str, b: str) -> float:
    """0.0 (nothing alike) to 1.0 (identical), Levenshtein-based."""
    max_len = max(len(a), len(b))
    if max_len == 0:
        return 1.0
    return 1.0 - (_levenshtein(a.lower(), b.lower()) / max_len)


def edit_distance(a: str, b: str) -> int:
    """Optimal-string-alignment distance: insert / delete / substitute / swap adjacent = 1 edit."""
    a, b = a.lower(), b.lower()
    prev2, prev = None, list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            v = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb))
            if prev2 is not None and i > 1 and j > 1 and ca == b[j - 2] and a[i - 2] == cb:
                v = min(v, prev2[j - 2] + 1)
            cur.append(v)
        prev2, prev = prev, cur
    return prev[-1]


def _squash(name: str) -> str:
    return re.sub(r"[-_.]+", "", name.lower())


def _norm(ecosystem: str, name: str) -> str:
    """Registry-accurate name: PyPI ignores case and treats - _ . alike; npm is exact (lowercase)."""
    if ecosystem == "pypi":
        return re.sub(r"[-_.]+", "-", name).lower()
    return name.lower()


def _is_conflation(candidate: str, popular_list: list[str]) -> Optional[tuple[str, str]]:
    """
    Names that glue a whole popular package name to the tail of another one,
    e.g. react-codeshift = react + (js)codeshift. Needs a full popular name of
    >= 4 chars at one end and a >= 5 char remainder that ends/starts another popular name.
    """
    c = _squash(candidate)
    squashed = [(p, _squash(p)) for p in popular_list]
    for x, a in squashed:
        if len(a) < 4 or len(c) - len(a) < 5:
            continue
        if c.startswith(a):                      # X + tail-of-Y
            rest = c[len(a):]
            for y, b in squashed:
                if y != x and b != a and b.endswith(rest) and len(b) > len(rest):
                    return (x, y)
        if c.endswith(a):                        # head-of-Y + X
            rest = c[: len(c) - len(a)]
            for y, b in squashed:
                if y != x and b != a and b.startswith(rest) and len(b) > len(rest):
                    return (y, x)
    return None


@dataclass
class RiskAssessment:
    package: str
    ecosystem: str
    risk_score: int  # 0-100, higher = more suspicious
    verdict: str  # "block", "warn", "pass"
    reasons: list[str] = field(default_factory=list)
    known_incident: Optional[dict] = None
    location: Optional[str] = None   # e.g. README.md:42 when found in docs/scripts


class HallucinationEngine:
    def __init__(self, data_dir: Path = DATA_DIR):
        with open(data_dir / "known_hallucinations.json") as f:
            self.known = json.load(f)
        with open(data_dir / "popular_packages.json") as f:
            self.popular = json.load(f)
        self._popular_sets = {
            eco: {_norm(eco, n) for n in names}
            for eco, names in self.popular.items() if isinstance(names, list)
        }

    def _known_incident(self, package_name: str, ecosystem: str) -> Optional[dict]:
        for entry in self.known.get(ecosystem, []):
            if entry["name"].lower() == package_name.lower():
                return entry
        return None

    def assess(self, package_name: str, meta: PackageMetadata) -> RiskAssessment:
        reasons: list[str] = []
        score = 0

        # Signal 1: known documented hallucination / slopsquat incident
        incident = self._known_incident(package_name, meta.ecosystem)
        if incident:
            score += 60
            reasons.append(
                f"Matches a documented hallucinated/slopsquatted package "
                f"({incident['type']}): {incident['note']}"
            )

        # Signal 2: registry unreachable vs package genuinely absent
        if meta.raw_error:
            score += 30
            reasons.append(
                f"Could not verify against the registry ({meta.raw_error}). Treated as "
                "unverified, not as hallucinated; re-run to check."
            )
        elif not meta.exists:
            score += 35
            reasons.append(
                "Package does not exist in the registry yet - if an AI assistant "
                "suggested it, this is a hallucinated dependency waiting to be squatted."
            )

        # Signal 3: typosquat / conflation (never applied to well-known packages themselves)
        popular_list = self.popular.get(meta.ecosystem, [])
        if _norm(meta.ecosystem, package_name) not in self._popular_sets.get(meta.ecosystem, set()):
            conflation = _is_conflation(package_name, popular_list)
            if conflation:
                score += 30
                reasons.append(
                    f"Name pattern looks like a conflation of '{conflation[0]}' and "
                    f"'{conflation[1]}' - a common AI hallucination pattern."
                )
            else:
                n = len(package_name)
                allowed = 0 if n < 5 else (1 if n < 10 else 2)   # short names are too noisy to judge
                hit = None
                for pk in popular_list if allowed else ():
                    if abs(len(pk) - n) <= allowed:
                        d = edit_distance(package_name, pk)
                        if 0 < d <= allowed and (hit is None or d < hit[1]):
                            hit = (pk, d)
                if hit:
                    score += 25
                    reasons.append(
                        f"Name is {hit[1]} edit(s) away from popular package "
                        f"'{hit[0]}' - possible typosquat."
                    )

        # Signal 4: registry metadata red flags (only meaningful if it exists)
        if meta.exists:
            if meta.age_days is not None and meta.age_days < 30:
                score += 15
                reasons.append(f"Registered only {meta.age_days} day(s) ago.")
            if meta.weekly_downloads is not None and meta.weekly_downloads < 50:
                score += 10
                reasons.append(f"Very low adoption: {meta.weekly_downloads} downloads last week.")
            if not meta.has_repository:
                score += 10
                reasons.append("No linked source repository (GitHub/GitLab).")
            if meta.maintainer_count <= 1 and meta.version_count <= 1:
                score += 5
                reasons.append("Single maintainer, single version published - low trust signal.")

        score = min(score, 100)

        if score >= 60:
            verdict = "block"
        elif score >= 30:
            verdict = "warn"
        else:
            verdict = "pass"

        if not reasons:
            reasons.append("No suspicious signals found.")

        return RiskAssessment(
            package=package_name,
            ecosystem=meta.ecosystem,
            risk_score=score,
            verdict=verdict,
            reasons=reasons,
            known_incident=incident,
        )
