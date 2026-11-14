"""Evaluate Unslop's name-based signals (and optionally the full pipeline) on labelled sets.

Protocol: each group is split 50/50 (dev / test) by position. Rule parameters are tuned on DEV only;
all reported numbers come from the held-out TEST half. The default (pre-tuning) parameters are reported
next to the tuned ones so the effect of tuning is visible.

  python eval/run_eval.py          # offline: name signals only (deterministic)
  python eval/run_eval.py --live   # also query PyPI/npm for the TEST split (needs network)

Writes eval/results.json and eval/results.md.
"""
import argparse, json, math, itertools, sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT.parent))
from unslop.heuristics import HallucinationEngine, _is_conflation, _norm, edit_distance, CONFLATION_PARAMS, TYPOSQUAT_PARAMS  # noqa: E402

FPR_CAP = 0.01          # tuning constraint: at most 1% of legitimate dev names may be flagged by a rule
ECOS = ("pypi", "npm")


def load(label, eco):
    return [x for x in (ROOT / "data" / f"{label}_{eco}.txt").read_text().split("\n") if x]


def wilson(k, n, z=1.96):
    if n == 0:
        return (0.0, 0.0)
    p, d = k / n, 1 + z * z / n
    c, a = p + z * z / (2 * n), z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))
    return (max(0.0, (c - a) / d), min(1.0, (c + a) / d))


def rate(k, n):
    lo, hi = wilson(k, n)
    return {"k": k, "n": n, "rate": k / n if n else 0.0, "ci": [lo, hi]}


def fmt(r):
    return f"{r['rate']:.1%} ({r['k']}/{r['n']}; 95% CI {r['ci'][0]:.1%}-{r['ci'][1]:.1%})"


def ts_features(name, popular):
    """Rank (index in the popular list) of the closest popular names at exactly 1 and 2 edits."""
    r1 = r2 = 10**9
    for i, pk in enumerate(popular):
        d = edit_distance(name, pk, limit=2)
        if d == 1 and i < r1:
            r1 = i
        elif d == 2 and i < r2:
            r2 = i
        if r1 < 10**9 and r2 < 10**9:
            break
    return r1, r2


CONF_GRID = [dict(min_head=h, min_rest=r, top_k=k) for h, r, k in itertools.product((4, 6), (5, 7), (None, 1000))]
TS_GRID = [dict(min_len=m, two_edit_len=t, top_k=k) for m, t, k in itertools.product((5, 6, 7), (10, 13, None), (5000, 2000, 500))]


def ts_flag(feat, n, p):
    r1, r2 = feat
    allowed = 0 if n < p["min_len"] else (1 if (p["two_edit_len"] is None or n < p["two_edit_len"]) else 2)
    k = p["top_k"] or 10**9
    return (allowed >= 1 and r1 < k) or (allowed >= 2 and r2 < k)


def key(p):
    return json.dumps(p, sort_keys=True)


def main(live):
    eng = HallucinationEngine()
    data, feats = {}, {}
    for eco in ECOS:
        pop = eng.popular[eco]
        popset = {_norm(eco, n) for n in pop}
        for label in ("malicious", "legit"):
            names = [n for n in load(label, eco) if _norm(eco, n) not in popset]
            half = {"dev": names[0::2], "test": names[1::2]}
            data[(eco, label)] = half
            for split, lst in half.items():
                for n in lst:
                    f = {"ts": ts_features(n, pop), "conf": {key(p): bool(_is_conflation(n, pop, **p)) for p in CONF_GRID}}
                    feats[(eco, label, split, n)] = f
        print(eco, "features done", flush=True)

    def counts(rule_fn, label, split):
        out = {}
        for eco in ECOS:
            lst = data[(eco, label)][split]
            out[eco] = sum(1 for n in lst if rule_fn(eco, n, feats[(eco, label, split, n)]))
        return out

    def stats(rule_fn, split):
        tp, fp = counts(rule_fn, "malicious", split), counts(rule_fn, "legit", split)
        return {eco: {"recall": rate(tp[eco], len(data[(eco, "malicious")][split])),
                      "fpr": rate(fp[eco], len(data[(eco, "legit")][split]))} for eco in ECOS}

    conf_rule = lambda p: (lambda eco, n, f: f["conf"][key(p)])
    ts_rule = lambda p: (lambda eco, n, f: ts_flag(f["ts"], len(n), p))

    def choose(grid, mk, must=None):
        best = None
        for p in grid:
            if must and not must(p):
                continue
            s = stats(mk(p), "dev")
            worst_fpr = max(s[e]["fpr"]["rate"] for e in ECOS)
            mean_rec = sum(s[e]["recall"]["rate"] for e in ECOS) / 2
            ok = worst_fpr <= FPR_CAP
            score = (ok, mean_rec if ok else -worst_fpr, -worst_fpr)
            if best is None or score > best[0]:
                best = (score, p)
        return best[1], best[0][0]

    npm_pop = eng.popular["npm"]
    must_conf = lambda p: bool(_is_conflation("react-codeshift", npm_pop, **p))   # the one documented conflation
    conf_best, conf_ok = choose(CONF_GRID, conf_rule, must_conf)
    ts_best, ts_ok = choose(TS_GRID, ts_rule)

    default_conf = dict(min_head=4, min_rest=5, top_k=None)
    default_ts = dict(min_len=5, two_edit_len=10, top_k=5000)
    combos = {
        "default": (default_conf, default_ts),
        "tuned": (conf_best, ts_best),
    }
    res = {"fpr_cap": FPR_CAP, "tuned_params": {"conflation": conf_best, "typosquat": ts_best},
           "constraint_met": {"conflation": conf_ok, "typosquat": ts_ok},
           "sizes": {f"{e}/{l}/{s}": len(data[(e, l)][s]) for e in ECOS for l in ("malicious", "legit") for s in ("dev", "test")},
           "test": {}}
    for name, (cp, tp) in combos.items():
        res["test"][name] = {
            "conflation": stats(conf_rule(cp), "test"),
            "typosquat": stats(ts_rule(tp), "test"),
            "either": stats(lambda eco, n, f, cp=cp, tp=tp: f["conf"][key(cp)] or ts_flag(f["ts"], len(n), tp), "test"),
        }

    if live:
        from unslop.registry_client import fetch_metadata
        res["live"] = {}
        for eco in ECOS:
            for label in ("legit", "malicious"):
                lst = data[(eco, label)]["test"]
                with ThreadPoolExecutor(max_workers=8) as pool:
                    metas = list(pool.map(lambda n: fetch_metadata(n, eco), lst))
                verdicts = {"pass": 0, "warn": 0, "block": 0}
                gone = errors = live_n = 0
                live_flagged = 0
                for n, m in zip(lst, metas):
                    if m.raw_error:
                        errors += 1
                        continue
                    if not m.exists:
                        gone += 1
                        continue
                    live_n += 1
                    v = eng.assess(n, m).verdict
                    verdicts[v] += 1
                    live_flagged += v != "pass"
                res["live"][f"{eco}/{label}"] = {"total": len(lst), "lookup_errors": errors, "not_on_registry": gone,
                                                 "on_registry": live_n, "verdicts_among_on_registry": verdicts,
                                                 "flagged_among_on_registry": rate(live_flagged, live_n)}
                print(eco, label, res["live"][f"{eco}/{label}"], flush=True)

    (ROOT / "results.json").write_text(json.dumps(res, indent=2))
    print(json.dumps({k: res[k] for k in ("tuned_params", "constraint_met", "sizes")}, indent=1))
    for name in combos:
        for rule in ("conflation", "typosquat", "either"):
            for eco in ECOS:
                s = res["test"][name][rule][eco]
                print(f"[{name:7}] {rule:10} {eco:4} recall {fmt(s['recall'])} | FPR {fmt(s['fpr'])}")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--live", action="store_true")
    main(ap.parse_args().live)
