"""Full-pipeline evaluation on the held-out TEST split using live PyPI/npm metadata.

  python eval/run_live.py pypi     (then: npm)      -> merges into eval/results.json
Uses the engine's current default parameters. Needs network. Download-count lookups
(pypistats.org / api.npmjs.org) may be blocked in some environments; when they are, the
low-downloads signal is simply absent, which is noted in results.md.
"""
import json, sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT.parent))
from unslop.heuristics import HallucinationEngine, _norm  # noqa: E402
from unslop.registry_client import fetch_metadata  # noqa: E402
from run_eval import load, rate  # noqa: E402

eco = sys.argv[1]
eng = HallucinationEngine()
popset = {_norm(eco, n) for n in eng.popular[eco]}
res = json.loads((ROOT / "results.json").read_text())
res.setdefault("live", {})
for label in ("legit", "malicious"):
    names = [n for n in load(label, eco) if _norm(eco, n) not in popset][1::2]      # same TEST split as run_eval
    with ThreadPoolExecutor(max_workers=8) as pool:
        metas = list(pool.map(lambda n: fetch_metadata(n, eco), names))
    verdicts, gone, errors, downloads_known, stubs = {"pass": 0, "warn": 0, "block": 0}, 0, 0, 0, 0
    for n, m in zip(names, metas):
        if m.raw_error:
            errors += 1
        elif not m.exists:
            gone += 1
        elif m.security_holding:
            stubs += 1                      # npm placeholder, not the malware itself: reported separately
        else:
            verdicts[eng.assess(n, m).verdict] += 1
            downloads_known += m.weekly_downloads is not None
    live = sum(verdicts.values())
    res["live"][f"{eco}/{label}"] = {
        "total": len(names), "lookup_errors": errors, "not_on_registry": gone, "npm_security_placeholders": stubs, "live_packages": live,
        "download_counts_available": downloads_known, "verdicts_among_on_registry": verdicts,
        "flagged_among_on_registry": rate(verdicts["warn"] + verdicts["block"], live),
        "blocked_among_on_registry": rate(verdicts["block"], live)}
    print(eco, label, json.dumps(res["live"][f"{eco}/{label}"]), flush=True)
(ROOT / "results.json").write_text(json.dumps(res, indent=2))
