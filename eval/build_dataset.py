"""Build the labelled evaluation sets (seeded, reproducible).

malicious_{pypi,npm}.txt : packages reported as malicious in the OpenSSF malicious-packages repo
legit_{pypi,npm}.txt     : real packages ranked 5,001-15,000 by downloads (lesser-known but legitimate),
                           minus anything in the malicious set. Top-5,000 packages are excluded because
                           they are the comparison list itself.

NOTE: "malicious" is not the same as "AI-hallucinated". Most reports are typosquats, dependency-confusion
or spam/worm campaigns. The set measures how well Unslop's name and metadata signals separate malware
names from legitimate ones, not how well it predicts what an LLM will hallucinate.

Usage: python eval/build_dataset.py [N=600]
"""
import io, json, random, subprocess, sys, tarfile, tempfile, datetime as dt
from pathlib import Path
import requests

N = int(sys.argv[1]) if len(sys.argv) > 1 else 600
SEED = 42
OUT = Path(__file__).resolve().parent / "data"
popular = json.loads((Path(__file__).resolve().parent.parent / "unslop" / "data" / "popular_packages.json").read_text())


def norm(eco, n):
    import re
    return re.sub(r"[-_.]+", "-", n).lower() if eco == "pypi" else n.lower()


def ossf_names(eco, tmp):
    repo = Path(tmp) / "ossf"
    if not repo.exists():
        subprocess.run(["git", "clone", "-q", "--depth", "1", "--filter=blob:none", "--no-checkout",
                        "https://github.com/ossf/malicious-packages.git", str(repo)], check=True)
    head = subprocess.run(["git", "log", "-1", "--format=%H %cd"], cwd=repo, capture_output=True, text=True).stdout.strip()
    paths = subprocess.run(["git", "ls-tree", "-r", "--name-only", "HEAD", f"osv/malicious/{eco}"],
                           cwd=repo, capture_output=True, text=True, check=True).stdout.splitlines()
    names = set()
    for p in paths:
        parts = p.split("/")
        if eco == "npm" and parts[3].startswith("@") and len(parts) > 5:
            names.add(parts[3] + "/" + parts[4])
        elif len(parts) > 4:
            names.add(parts[3])
    return sorted(names), head


def ranked_pypi():
    rows = requests.get("https://raw.githubusercontent.com/hugovk/top-pypi-packages/main/top-pypi-packages.min.json",
                        timeout=60).json()
    return [r["project"] for r in rows["rows"]], rows.get("last_update")


def ranked_npm():
    meta = requests.get("https://registry.npmjs.org/download-counts/latest", timeout=30).json()
    blob = requests.get(meta["dist"]["tarball"], timeout=300).content
    with tarfile.open(fileobj=io.BytesIO(blob)) as tf:
        m = next(x for x in tf.getmembers() if x.name.endswith("counts.json"))
        counts = json.load(tf.extractfile(m))
    return [k for k, _ in sorted(counts.items(), key=lambda kv: kv[1], reverse=True)], meta["version"]


if __name__ == "__main__":
    OUT.mkdir(parents=True, exist_ok=True)
    notes = [f"Built {dt.date.today()} with seed {SEED}, N={N} per group.\n"]
    with tempfile.TemporaryDirectory() as tmp:
        for eco, ranker in (("pypi", ranked_pypi), ("npm", ranked_npm)):
            mal, head = ossf_names(eco, tmp)
            ranking, rver = ranker()
            pop = {norm(eco, n) for n in popular[eco]}
            mal_set = {norm(eco, n) for n in mal}
            mal_pool = [n for n in mal if norm(eco, n) not in pop]
            legit_pool = [n for n in ranking[5000:15000] if norm(eco, n) not in mal_set and norm(eco, n) not in pop]
            rnd = random.Random(SEED)
            mal_s, legit_s = rnd.sample(mal_pool, N), rnd.sample(legit_pool, N)
            (OUT / f"malicious_{eco}.txt").write_text("\n".join(mal_s) + "\n")
            (OUT / f"legit_{eco}.txt").write_text("\n".join(legit_s) + "\n")
            notes.append(f"- {eco}: malicious pool {len(mal_pool)} unique names from OpenSSF malicious-packages @ {head}; "
                         f"legit pool {len(legit_pool)} (ranks 5001-15000 of {rver}).")
            print(eco, "malicious", len(mal_pool), "legit pool", len(legit_pool))
    (OUT / "PROVENANCE.md").write_text("\n".join(notes) + "\n")
