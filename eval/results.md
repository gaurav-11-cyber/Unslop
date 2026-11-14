# Unslop evaluation

Held-out test split: 300 legitimate + 300 malicious package names per ecosystem, seeded sample (seed 42). Rule parameters were chosen on a separate dev split. Data provenance: `eval/data/PROVENANCE.md`.

## Findings

1. **False positives (full pipeline, live registry data):** PyPI 0.0% (0/300, 95% CI 0.0%-1.3%); npm 0.0% (0/300, 95% CI 0.0%-1.3%) of lesser-known legitimate packages got a WARN or BLOCK.
2. **Typosquat rule** (held-out): PyPI recall 8.7% (26/300, 95% CI 6.0%-12.4%) at FPR 2.3% (7/300, 95% CI 1.1%-4.7%); npm recall 0.0% (0/300, 95% CI 0.0%-1.3%). Tuning cut the false-positive rate (PyPI 5.7% -> 2.3%, npm 2.7% -> 0.7%) without losing recall.
3. **Conflation rule is not validated:** recall 0.0% (0/300, 95% CI 0.0%-1.3%) (PyPI) and 0.0% (0/300, 95% CI 0.0%-1.3%) (npm); false positives fell from 6.0%/8.7% to 3.0%/2.0% after tuning, but the 1% cap was not met. It is kept as a weak corroborating signal (+15, never a WARN alone) because it matches one documented incident (react-codeshift); n=1 proves nothing.
4. **Malicious packages that are still live are NOT detected by name/metadata signals:** 0/119 flagged (PyPI 4, npm 115). Unslop's value is the incident corpus, the existence check for unregistered names, typosquat hints and npm placeholder recognition, not a general malware classifier.
5. **Removed packages:** 296/300 sampled PyPI malicious names no longer exist (reported as 'does not exist'). 182/300 npm names are `0.0.1-security` placeholders; Unslop now blocks these. That check follows from how the labels were produced, so it is not independent evidence of accuracy.

## Name-only rules, held-out test split

| Params | Rule | Ecosystem | Recall on malicious | False-positive rate on legitimate |
|---|---|---|---|---|
| default | conflation | pypi | 1.3% (4/300, 95% CI 0.5%-3.4%) | 6.0% (18/300, 95% CI 3.8%-9.3%) |
| default | conflation | npm | 0.3% (1/300, 95% CI 0.1%-1.9%) | 8.7% (26/300, 95% CI 6.0%-12.4%) |
| default | typosquat | pypi | 9.0% (27/300, 95% CI 6.3%-12.8%) | 5.7% (17/300, 95% CI 3.6%-8.9%) |
| default | typosquat | npm | 0.0% (0/300, 95% CI 0.0%-1.3%) | 2.7% (8/300, 95% CI 1.4%-5.2%) |
| default | either | pypi | 10.3% (31/300, 95% CI 7.4%-14.3%) | 11.7% (35/300, 95% CI 8.5%-15.8%) |
| default | either | npm | 0.3% (1/300, 95% CI 0.1%-1.9%) | 11.3% (34/300, 95% CI 8.2%-15.4%) |
| tuned | conflation | pypi | 0.0% (0/300, 95% CI 0.0%-1.3%) | 3.0% (9/300, 95% CI 1.6%-5.6%) |
| tuned | conflation | npm | 0.0% (0/300, 95% CI 0.0%-1.3%) | 2.0% (6/300, 95% CI 0.9%-4.3%) |
| tuned | typosquat | pypi | 8.7% (26/300, 95% CI 6.0%-12.4%) | 2.3% (7/300, 95% CI 1.1%-4.7%) |
| tuned | typosquat | npm | 0.0% (0/300, 95% CI 0.0%-1.3%) | 0.7% (2/300, 95% CI 0.2%-2.4%) |
| tuned | either | pypi | 8.7% (26/300, 95% CI 6.0%-12.4%) | 5.3% (16/300, 95% CI 3.3%-8.5%) |
| tuned | either | npm | 0.0% (0/300, 95% CI 0.0%-1.3%) | 2.7% (8/300, 95% CI 1.4%-5.2%) |

Tuned parameters: `{"conflation": {"min_head": 4, "min_rest": 7, "top_k": 1000}, "typosquat": {"min_len": 6, "two_edit_len": null, "top_k": 5000}}`. Constraint (dev FPR <= 1%) met: `{"conflation": false, "typosquat": true}`.

## Full pipeline (live PyPI/npm metadata), held-out test split

| Group | Looked up | Not on registry | npm placeholders | Live packages | Flagged (WARN/BLOCK) among live |
|---|---|---|---|---|---|
| pypi legit | 300 | 0 | 0 | 300 | 0.0% (0/300, 95% CI 0.0%-1.3%) |
| pypi malicious | 300 | 296 | 0 | 4 | 0.0% (0/4, 95% CI 0.0%-49.0%) |
| npm legit | 300 | 0 | 0 | 300 | 0.0% (0/300, 95% CI 0.0%-1.3%) |
| npm malicious | 300 | 3 | 182 | 115 | 0.0% (0/115, 95% CI -0.0%-3.2%) |

## Limits of this evaluation

- **Malicious is not the same as hallucinated.** Labels come from the OpenSSF malicious-packages repository: typosquats, dependency confusion, spam and worm campaigns. No labelled set of AI-hallucinated names was available here, so Unslop's core claim (flagging a hallucinated, not-yet-registered name) rests on the existence check and the incident corpus, and is not measured.
- The npm malicious sample is mostly campaign-generated random names, which explains 0% typosquat recall there.
- Legitimate negatives are packages ranked 5,001-15,000 by downloads. Packages in the top 5,000 skip the name rules entirely, so FPR on typical manifests is probably lower; that was not measured.
- Weekly download counts were unavailable in the environment that produced these numbers (pypistats.org and api.npmjs.org blocked), so the low-downloads signal was absent. Re-run `eval/run_live.py` locally for the full pipeline.
- Samples are 300 per cell, so intervals are wide (see CIs). Weights (+15, +25, +35, +60, +70) are set by judgment, not fitted.

Reproduce: `python eval/build_dataset.py && python eval/run_eval.py && python eval/run_live.py pypi && python eval/run_live.py npm && python eval/make_report.py`
