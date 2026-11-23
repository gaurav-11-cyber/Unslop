"""policy.py - what makes the gate fail. Read from unslop.toml (all keys optional), with expiring waivers."""
from __future__ import annotations

import datetime as dt
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from .vulns import RANK

LEVELS = ("none", "low", "medium", "high", "critical")
KNOWN = {"block_on_vulnerability", "block_on_secret", "block_on_slopsquat", "fail_on_error"}


class PolicyError(ValueError):
    pass


@dataclass
class Waiver:
    id: str
    reason: str
    expires: Optional[dt.date] = None

    def expired(self, today: dt.date) -> bool:
        return self.expires is not None and today > self.expires


@dataclass
class Policy:
    block_on_vulnerability: str = "high"
    block_on_secret: bool = True
    block_on_slopsquat: bool = True
    fail_on_error: bool = False
    waivers: list[Waiver] = field(default_factory=list)

    def vuln_blocks(self, severity: str) -> bool:
        return self.block_on_vulnerability != "none" and RANK[severity] >= RANK[self.block_on_vulnerability] and severity != "unknown"

    def waiver_for(self, keys: list[str], today: dt.date) -> tuple[Optional[Waiver], bool]:
        """(matching waiver, is_expired). An expired waiver does not waive anything."""
        for w in self.waivers:
            if w.id in keys:
                return (None, True) if w.expired(today) else (w, False)
        return None, False


def load_policy(path: Optional[Path]) -> Policy:
    if path is None or not path.exists():
        return Policy()
    try:
        import tomllib
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except ImportError as e:
        raise PolicyError("policy files need Python 3.11+ (tomllib)") from e
    except (OSError, ValueError) as e:
        raise PolicyError(f"cannot read {path}: {e}") from e
    section = data.get("policy") or {}
    unknown = set(section) - KNOWN
    if unknown:
        raise PolicyError(f"unknown policy key(s): {sorted(unknown)}; allowed: {sorted(KNOWN)}")
    level = str(section.get("block_on_vulnerability", "high")).lower()
    if level not in LEVELS:
        raise PolicyError(f"block_on_vulnerability must be one of {LEVELS}")
    for key in ("block_on_secret", "block_on_slopsquat", "fail_on_error"):
        if key in section and not isinstance(section[key], bool):
            raise PolicyError(f"{key} must be true or false")
    waivers = []
    for w in data.get("waiver") or []:
        if not isinstance(w, dict) or not str(w.get("id", "")).strip() or not str(w.get("reason", "")).strip():
            raise PolicyError("every [[waiver]] needs a non-empty id and reason")
        exp = w.get("expires")
        if exp is not None and not isinstance(exp, dt.date):
            raise PolicyError(f"waiver {w['id']}: expires must be a date like 2026-12-31")
        waivers.append(Waiver(str(w["id"]).strip(), str(w["reason"]).strip(), exp))
    return Policy(level, section.get("block_on_secret", True), section.get("block_on_slopsquat", True),
                  section.get("fail_on_error", False), waivers)
