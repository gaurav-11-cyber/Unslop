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
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from .registry_client import PackageMetadata

DATA_DIR = Path(__file__).resolve().parent.parent / "data"


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


def _is_conflation(candidate: str, popular_list: list[str]) -> Optional[tuple[str, str]]:
    """
    Detect names that look like two real popular packages mashed together,
    e.g. react-codeshift ~ jscodeshift + react-codemod.
    Cheap heuristic: candidate contains a long prefix of one popular name
    and a long suffix of another.
    """
    candidate_l = candidate.lower().replace("-", "").replace("_", "")
    for p1 in popular_list:
        p1_l = p1.lower().replace("-", "").replace("_", "")
        if len(p1_l) < 4:
            continue
        if candidate_l.startswith(p1_l[: max(4, len(p1_l) // 2)]):
            for p2 in popular_list:
                if p2 == p1:
                    continue
                p2_l = p2.lower().replace("-", "").replace("_", "")
                if len(p2_l) < 4:
                    continue
                if candidate_l.endswith(p2_l[-max(4, len(p2_l) // 2):]):
                    return (p1, p2)
    return None


@dataclass
class RiskAssessment:
    package: str
    ecosystem: str
    risk_score: int  # 0-100, higher = more suspicious
    verdict: str  # "block", "warn", "pass"
    reasons: list[str] = field(default_factory=list)
    known_incident: Optional[dict] = None


class HallucinationEngine:
    def __init__(self, data_dir: Path = DATA_DIR):
        with open(data_dir / "known_hallucinations.json") as f:
            self.known = json.load(f)
        with open(data_dir / "popular_packages.json") as f:
            self.popular = json.load(f)

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

        # Signal 2: package doesn't exist in the registry at all
        if not meta.exists:
            score += 35
            reasons.append(
                "Package does not exist in the registry yet - if an AI assistant "
                "suggested it, this is a hallucinated dependency waiting to be squatted."
            )

        # Signal 3: typosquat / conflation similarity against popular packages
        popular_list = self.popular.get(meta.ecosystem, [])
        conflation = _is_conflation(package_name, popular_list)
        if conflation:
            score += 30
            reasons.append(
                f"Name pattern looks like a conflation of '{conflation[0]}' and "
                f"'{conflation[1]}' - a common AI hallucination pattern."
            )
        else:
            best_match, best_ratio = None, 0.0
            for p in popular_list:
                r = similarity_ratio(package_name, p)
                if r > best_ratio:
                    best_match, best_ratio = p, r
            if best_match and 0.75 <= best_ratio < 1.0:
                score += 25
                reasons.append(
                    f"Name is {best_ratio:.0%} similar to popular package '{best_match}' "
                    "- possible typosquat."
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
