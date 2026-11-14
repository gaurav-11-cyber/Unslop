"""
registry_client.py

Talks to the real package registries (PyPI, npm) to pull metadata used
for hallucination / slopsquatting risk scoring:
  - does the package exist at all?
  - how old is it?
  - how many downloads does it have?
  - does it have a linked source repo / real maintainer info?

No API keys needed - these are all public, unauthenticated endpoints.
"""

from __future__ import annotations

import datetime as dt
import time
from dataclasses import dataclass, field
from typing import Optional

import requests

USER_AGENT = "Unslop/0.1 (+https://github.com/gaurav-11-cyber/unslop)"
TIMEOUT = 8  # seconds, keep scans fast enough for a CI gate


@dataclass
class PackageMetadata:
    name: str
    ecosystem: str  # "pypi" or "npm"
    exists: bool
    age_days: Optional[int] = None
    weekly_downloads: Optional[int] = None
    has_repository: bool = False
    repository_url: Optional[str] = None
    maintainer_count: int = 0
    version_count: int = 0
    raw_error: Optional[str] = None
    security_holding: bool = False   # npm replaced a malicious package with a '0.0.1-security' placeholder
    fetched_at: dt.datetime = field(default_factory=lambda: dt.datetime.now(dt.timezone.utc))


def _session() -> requests.Session:
    s = requests.Session()
    s.headers.update({"User-Agent": USER_AGENT})
    return s


def _get(session: requests.Session, url: str, retries: int = 2) -> requests.Response:
    """GET with short backoff on timeouts, 429 and 5xx. Raises requests.RequestException if all tries fail."""
    for attempt in range(retries + 1):
        try:
            resp = session.get(url, timeout=TIMEOUT)
            if resp.status_code not in (429, 500, 502, 503, 504) or attempt == retries:
                return resp
        except requests.RequestException:
            if attempt == retries:
                raise
        time.sleep(0.5 * 2 ** attempt)
    raise AssertionError("unreachable")


# ---------------------------------------------------------------- PyPI ----

def fetch_pypi_metadata(package_name: str, session: Optional[requests.Session] = None) -> PackageMetadata:
    session = session or _session()
    url = f"https://pypi.org/pypi/{package_name}/json"
    try:
        resp = _get(session, url)
    except requests.RequestException as e:
        return PackageMetadata(name=package_name, ecosystem="pypi", exists=False, raw_error=str(e))

    if resp.status_code == 404:
        return PackageMetadata(name=package_name, ecosystem="pypi", exists=False)
    if resp.status_code != 200:
        return PackageMetadata(
            name=package_name, ecosystem="pypi", exists=False,
            raw_error=f"HTTP {resp.status_code}",
        )

    data = resp.json()
    info = data.get("info", {})
    releases = data.get("releases", {})

    # Age = time since the earliest release upload
    age_days = None
    earliest = None
    for version_files in releases.values():
        for f in version_files:
            uploaded = f.get("upload_time_iso_8601")
            if uploaded:
                ts = dt.datetime.fromisoformat(uploaded.replace("Z", "+00:00"))
                if earliest is None or ts < earliest:
                    earliest = ts
    if earliest:
        age_days = (dt.datetime.now(dt.timezone.utc) - earliest).days

    candidates = [u for u in (info.get("project_urls") or {}).values() if isinstance(u, str)]
    if isinstance(info.get("home_page"), str):
        candidates.append(info["home_page"])
    code_hosts = ("github.com", "gitlab.com", "bitbucket.org", "codeberg.org")
    repo_url = next((u for u in candidates if any(h in u for h in code_hosts)), None)
    has_repo = repo_url is not None
    repo_url = repo_url or (candidates[0] if candidates else None)

    weekly_downloads = _fetch_pypi_downloads(package_name, session)

    return PackageMetadata(
        name=package_name,
        ecosystem="pypi",
        exists=True,
        age_days=age_days,
        weekly_downloads=weekly_downloads,
        has_repository=has_repo,
        repository_url=repo_url,
        maintainer_count=1 if info.get("author") or info.get("maintainer") else 0,
        version_count=len(releases),
    )


def _fetch_pypi_downloads(package_name: str, session: requests.Session) -> Optional[int]:
    """pypistats.org gives recent download counts; PyPI's own JSON API doesn't."""
    try:
        resp = session.get(
            f"https://pypistats.org/api/packages/{package_name}/recent",
            timeout=TIMEOUT,
        )
        if resp.status_code == 200:
            return resp.json().get("data", {}).get("last_week")
    except requests.RequestException:
        pass
    return None


# ----------------------------------------------------------------- npm ----

def fetch_npm_metadata(package_name: str, session: Optional[requests.Session] = None) -> PackageMetadata:
    session = session or _session()
    url = f"https://registry.npmjs.org/{package_name}"
    try:
        resp = _get(session, url)
    except requests.RequestException as e:
        return PackageMetadata(name=package_name, ecosystem="npm", exists=False, raw_error=str(e))

    if resp.status_code == 404:
        return PackageMetadata(name=package_name, ecosystem="npm", exists=False)
    if resp.status_code != 200:
        return PackageMetadata(
            name=package_name, ecosystem="npm", exists=False,
            raw_error=f"HTTP {resp.status_code}",
        )

    data = resp.json()
    time_data = data.get("time", {})
    created = time_data.get("created")
    age_days = None
    if created:
        ts = dt.datetime.fromisoformat(created.replace("Z", "+00:00"))
        age_days = (dt.datetime.now(dt.timezone.utc) - ts).days

    repo = data.get("repository", {})
    repo_url = repo.get("url") if isinstance(repo, dict) else repo
    maintainers = data.get("maintainers", [])
    versions = data.get("versions", {})

    weekly_downloads = _fetch_npm_downloads(package_name, session)

    return PackageMetadata(
        name=package_name,
        ecosystem="npm",
        exists=True,
        age_days=age_days,
        weekly_downloads=weekly_downloads,
        has_repository=bool(repo_url and ("github.com" in (repo_url or "") or "gitlab.com" in (repo_url or ""))),
        repository_url=repo_url,
        maintainer_count=len(maintainers),
        version_count=len(versions),
        security_holding=bool(versions) and all(str(v).startswith("0.0.1-security") for v in versions),
    )


def _fetch_npm_downloads(package_name: str, session: requests.Session) -> Optional[int]:
    try:
        resp = session.get(
            f"https://api.npmjs.org/downloads/point/last-week/{package_name}",
            timeout=TIMEOUT,
        )
        if resp.status_code == 200:
            return resp.json().get("downloads")
    except requests.RequestException:
        pass
    return None


def fetch_metadata(package_name: str, ecosystem: str, session: Optional[requests.Session] = None) -> PackageMetadata:
    if ecosystem == "pypi":
        return fetch_pypi_metadata(package_name, session)
    if ecosystem == "npm":
        return fetch_npm_metadata(package_name, session)
    raise ValueError(f"Unsupported ecosystem: {ecosystem}")
