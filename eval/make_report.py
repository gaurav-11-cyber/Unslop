"""Render eval/results.md from eval/results.json (numbers are copied, never typed by hand)."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent
r = json.loads((ROOT / "results.json").read_text())
T, L = r["test"], r["live"]
f = lambda x: f"{x['rate']:.1%} ({x['k']}/{x['n']}, 95% CI {x['ci'][0]:.1%}-{x['ci'][1]:.1%})"
ECOS = ("pypi", "npm")

out = ["# Unslop evaluation", "",
       "Held-out test split: 300 legitimate + 300 malicious package names per ecosystem, seeded sample (seed 42). "
       "Rule parameters were chosen on a separate dev split. Data provenance: `eval/data/PROVENANCE.md`.", "",
       "## Findings", ""]
leg = {e: L[f"{e}/legit"] for e in ECOS}
mal = {e: L[f"{e}/malicious"] for e in ECOS}
live_n = sum(mal[e]["live_packages"] for e in ECOS)
live_k = sum(mal[e]["verdicts_among_on_registry"]["warn"] + mal[e]["verdicts_among_on_registry"]["block"] for e in ECOS)
out += [
    f"1. **False positives (full pipeline, live registry data):** PyPI {f(leg['pypi']['flagged_among_on_registry'])}; "
    f"npm {f(leg['npm']['flagged_among_on_registry'])} of lesser-known legitimate packages got a WARN or BLOCK.",
    f"2. **Typosquat rule** (held-out): PyPI recall {f(T['tuned']['typosquat']['pypi']['recall'])} at "
    f"FPR {f(T['tuned']['typosquat']['pypi']['fpr'])}; npm recall {f(T['tuned']['typosquat']['npm']['recall'])}. "
    "Tuning cut the false-positive rate (PyPI "
    f"{T['default']['typosquat']['pypi']['fpr']['rate']:.1%} -> {T['tuned']['typosquat']['pypi']['fpr']['rate']:.1%}, npm "
    f"{T['default']['typosquat']['npm']['fpr']['rate']:.1%} -> {T['tuned']['typosquat']['npm']['fpr']['rate']:.1%}) without losing recall.",
    f"3. **Conflation rule is not validated:** recall {f(T['tuned']['conflation']['pypi']['recall'])} (PyPI) and "
    f"{f(T['tuned']['conflation']['npm']['recall'])} (npm); false positives fell from "
    f"{T['default']['conflation']['pypi']['fpr']['rate']:.1%}/{T['default']['conflation']['npm']['fpr']['rate']:.1%} to "
    f"{T['tuned']['conflation']['pypi']['fpr']['rate']:.1%}/{T['tuned']['conflation']['npm']['fpr']['rate']:.1%} after tuning, but the 1% cap was not met. "
    "It is kept as a weak corroborating signal (+15, never a WARN alone) because it matches one documented incident (react-codeshift); n=1 proves nothing.",
    f"4. **Malicious packages that are still live are NOT detected by name/metadata signals:** {live_k}/{live_n} flagged "
    f"(PyPI {mal['pypi']['live_packages']}, npm {mal['npm']['live_packages']}). Unslop's value is the incident corpus, the existence check for "
    "unregistered names, typosquat hints and npm placeholder recognition, not a general malware classifier.",
    f"5. **Removed packages:** {mal['pypi']['not_on_registry']}/{mal['pypi']['total']} sampled PyPI malicious names no longer exist (reported as "
    f"'does not exist'). {mal['npm']['npm_security_placeholders']}/{mal['npm']['total']} npm names are `0.0.1-security` placeholders; Unslop now blocks "
    "these. That check follows from how the labels were produced, so it is not independent evidence of accuracy.", "",
    "## Name-only rules, held-out test split", "",
    "| Params | Rule | Ecosystem | Recall on malicious | False-positive rate on legitimate |", "|---|---|---|---|---|"]
for name in ("default", "tuned"):
    for rule in ("conflation", "typosquat", "either"):
        for e in ECOS:
            s = T[name][rule][e]
            out.append(f"| {name} | {rule} | {e} | {f(s['recall'])} | {f(s['fpr'])} |")
out += ["", f"Tuned parameters: `{json.dumps(r['tuned_params'])}`. Constraint (dev FPR <= {r['fpr_cap']:.0%}) met: `{json.dumps(r['constraint_met'])}`.",
        "", "## Full pipeline (live PyPI/npm metadata), held-out test split", "",
        "| Group | Looked up | Not on registry | npm placeholders | Live packages | Flagged (WARN/BLOCK) among live |", "|---|---|---|---|---|---|"]
for e in ECOS:
    for lab in ("legit", "malicious"):
        x = L[f"{e}/{lab}"]
        out.append(f"| {e} {lab} | {x['total']} | {x['not_on_registry']} | {x['npm_security_placeholders']} | {x['live_packages']} | {f(x['flagged_among_on_registry'])} |")
out += ["", "## Limits of this evaluation", "",
        "- **Malicious is not the same as hallucinated.** Labels come from the OpenSSF malicious-packages repository: typosquats, dependency confusion, spam and worm campaigns. No labelled set of AI-hallucinated names was available here, so Unslop's core claim (flagging a hallucinated, not-yet-registered name) rests on the existence check and the incident corpus, and is not measured.",
        "- The npm malicious sample is mostly campaign-generated random names, which explains 0% typosquat recall there.",
        "- Legitimate negatives are packages ranked 5,001-15,000 by downloads. Packages in the top 5,000 skip the name rules entirely, so FPR on typical manifests is probably lower; that was not measured.",
        "- Weekly download counts were unavailable in the environment that produced these numbers (pypistats.org and api.npmjs.org blocked), so the low-downloads signal was absent. Re-run `eval/run_live.py` locally for the full pipeline.",
        "- Samples are 300 per cell, so intervals are wide (see CIs). Weights (+15, +25, +35, +60, +70) are set by judgment, not fitted.", "",
        "Reproduce: `python eval/build_dataset.py && python eval/run_eval.py && python eval/run_live.py pypi && python eval/run_live.py npm && python eval/make_report.py`", ""]
(ROOT / "results.md").write_text("\n".join(out))
print("\n".join(out[:22]))
