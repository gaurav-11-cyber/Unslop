"""sbom.py - CycloneDX 1.5 software bill of materials built from the scanned manifests."""
from __future__ import annotations

import datetime as dt
import re
import uuid
from urllib.parse import quote

from . import __version__
from .deps import Dep


def purl(dep: Dep) -> str:
    if dep.ecosystem == "pypi":
        name = re.sub(r"[-_.]+", "-", dep.name).lower()
    else:
        name = "/".join(quote(p, safe="") for p in dep.name.split("/")) if dep.name.startswith("@") else quote(dep.name, safe="")
    return f"pkg:{dep.ecosystem}/{name}" + (f"@{quote(dep.version, safe='')}" if dep.version else "")


def build_sbom(by_file: dict[str, list[Dep]]) -> dict:
    components: dict[str, dict] = {}
    for file, deps in by_file.items():
        for d in deps:
            ref = purl(d)
            comp = components.setdefault(ref, {
                "type": "library", "bom-ref": ref, "name": d.name, "purl": ref,
                **({"version": d.version} if d.version else {}), "properties": []})
            comp["properties"].append({"name": "unslop:manifest", "value": file})
            if not d.version:
                comp["properties"].append({"name": "unslop:pinned", "value": "false"})
    return {
        "bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "metadata": {"timestamp": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                     "tools": {"components": [{"type": "application", "name": "unslop", "version": __version__}]}},
        "components": sorted(components.values(), key=lambda c: c["bom-ref"]),
    }
