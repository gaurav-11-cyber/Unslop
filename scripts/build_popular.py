"""Rebuild unslop/data/popular_packages.json from public download rankings.

PyPI: hugovk/top-pypi-packages (monthly downloads, refreshed monthly).
npm:  the `download-counts` package (nice-registry); its data may lag behind today,
      which is fine here: we only need a list of well-known names to compare against.

Usage: python scripts/build_popular.py [N]     (default N = 5000)
"""
import io, json, sys, tarfile, datetime as dt
from pathlib import Path
import requests

N = int(sys.argv[1]) if len(sys.argv) > 1 else 5000
OUT = Path(__file__).resolve().parent.parent / "unslop" / "data" / "popular_packages.json"

def pypi_top(n):
    url = "https://raw.githubusercontent.com/hugovk/top-pypi-packages/main/top-pypi-packages.min.json"
    d = requests.get(url, timeout=60).json()
    return [r["project"] for r in d["rows"][:n]], d.get("last_update")

def npm_top(n):
    meta = requests.get("https://registry.npmjs.org/download-counts/latest", timeout=30).json()
    blob = requests.get(meta["dist"]["tarball"], timeout=300).content
    with tarfile.open(fileobj=io.BytesIO(blob)) as tf:
        member = next(m for m in tf.getmembers() if m.name.endswith("counts.json"))
        counts = json.load(tf.extractfile(member))
    ranked = sorted(counts.items(), key=lambda kv: kv[1], reverse=True)
    return [k for k, _ in ranked[:n]], meta["version"]

if __name__ == "__main__":
    py, py_date = pypi_top(N)
    npm, npm_ver = npm_top(N)
    OUT.write_text(json.dumps({
        "_comment": f"Top {N} packages per registry. PyPI source: hugovk/top-pypi-packages (last_update {py_date}). "
                    f"npm source: download-counts@{npm_ver}. Rebuild with scripts/build_popular.py.",
        "pypi": py, "npm": npm}, indent=0) + "\n")
    print("pypi", len(py), py[:5], "| npm", len(npm), npm[:5], "| written", OUT.stat().st_size, "bytes")
