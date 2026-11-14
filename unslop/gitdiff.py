"""
gitdiff.py

Answers one question: "which packages in this manifest are new compared to
some git ref (e.g. origin/main)?"

That is what a PR check should scan. Packages that were already in the base
branch are skipped, which keeps CI fast and the PR comment relevant. A version
bump of an existing package is not "new" and is not scanned.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path
from typing import Optional

from .scanner import ecosystem_for, parse_names


class GitError(Exception):
    """Raised when git cannot answer (not a repo, bad ref, git missing)."""


def _git(args: list[str], cwd: Path) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(["git", *args], capture_output=True, text=True, cwd=cwd)
    except FileNotFoundError as e:
        raise GitError("git is not installed or not on PATH") from e


def _normalize(name: str, ecosystem: str) -> str:
    """PyPI treats '-', '_' and '.' as the same character and ignores case."""
    if ecosystem == "pypi":
        return re.sub(r"[-_.]+", "-", name).lower()
    return name.lower()


def read_at_ref(path: Path, ref: str) -> Optional[str]:
    """Text of `path` at git `ref`, or None if the file did not exist there."""
    path = path.resolve()
    check = _git(["rev-parse", "--verify", "--quiet", f"{ref}^{{commit}}"], cwd=path.parent)
    if check.returncode != 0:
        raise GitError(
            f"Cannot resolve git ref '{ref}'. Is this a git repository, and is the "
            f"base branch fetched? (In GitHub Actions use actions/checkout with fetch-depth: 0.)"
        )

    shown = _git(["show", f"{ref}:./{path.name}"], cwd=path.parent)
    if shown.returncode == 0:
        return shown.stdout
    err = shown.stderr
    if "does not exist in" in err or "exists on disk, but not in" in err:
        return None
    raise GitError(f"git show failed for {path.name} at {ref}: {err.strip()}")


def added_packages(manifest: Path, base_ref: str) -> list[str]:
    """Package names in `manifest` that are not in the same file at `base_ref`."""
    ecosystem = ecosystem_for(manifest)
    head_names = parse_names(ecosystem, manifest.read_text(encoding="utf-8"), manifest.name)

    base_text = read_at_ref(manifest, base_ref)
    base_names: list[str] = []
    if base_text is not None:
        try:
            base_names = parse_names(ecosystem, base_text, manifest.name)
        except ValueError:
            # Broken manifest on the base branch: treat everything as new (scan more, not less).
            base_names = []

    already_there = {_normalize(n, ecosystem) for n in base_names}
    return [n for n in head_names if _normalize(n, ecosystem) not in already_there]
