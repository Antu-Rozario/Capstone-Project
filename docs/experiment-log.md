# Experiment Log

One entry for every change that affects results, with numbers before and after. Changes informed by test labels are marked **label-informed**. Treat their gains as optimistic, and confirm them on held-out data (fresh synthetic seeds, CERT r6.2) before claiming them.

Reproduce any entry with:

```bash
.venv/bin/python -m ueba.detection data/processed/synthetic
.venv/bin/python -m ueba.detection data/processed/cert_r4.2 --baseline-end 2010-06-01
```

A user counts as flagged at risk level Medium or above.

---

## E1 — First detection run (v1)

**Setup:**

- **Rules:** 8 rules (FR-3).
- **ML detector:** IsolationForest, scoring each user's daily activity against their own baseline.
- **Risk Score:** 75% rule Findings, 25% ML.
- **Baseline Window:** synthetic 2026-08-20 → 2026-09-16; CERT 2010-01-02 → 2010-05-31.

| Dataset | Flagged | TP | FP | FN | Precision | Recall | F1 | Precision@k | Normal-user FP rate | Hard-negative FP rate |
|---|---|---|---|---|---|---|---|---|---|---|
| Synthetic (seed 42, default Intensity) | 15 | 15 | 0 | 0 | 1.00 | 1.00 | 1.00 | 1.00 | 0% | 0% (25 users) |
| CERT r4.2 | 248 | 70 | 178 | 0 | 0.28 | 1.00 | 0.44 | 0.67 | 19.1% | — |

**Reading the synthetic result.** The team designed both the scenarios and the rules, and the default Intensity is meant to be clearly visible. A perfect score here shows the pipeline works end to end. It does not show real-world accuracy. RQ2 (Intensity sweeps) and CERT are the meaningful tests.

**CERT error analysis.** Of the 178 false positives:

- `EXECUTABLE_TO_USB` fired for **141**, and was the only rule for 95 of them. The rule fires on any `.exe` copy by a user who copied none during the 5-month baseline. Over a 12-month Detection Window, ordinary USB users eventually copy one by chance.
- `OTHER_USER_PC` fired for 40, and was alone for 21. CERT's readme says some users routinely log on to other users' machines.

## E2 — Supporting rules (v2), label-informed

**Change.** `EXECUTABLE_TO_USB` and `OTHER_USER_PC` became `low` severity. They still appear as evidence and raise a score when another rule fires, but they can't make a user Medium on their own. The ML component also only counts for users with at least one medium or high Finding.

| Dataset | Flagged | TP | FP | FN | Precision | Recall | F1 | Precision@k | Normal-user FP rate |
|---|---|---|---|---|---|---|---|---|---|
| Synthetic (seed 42) | 15 | 15 | 0 | 0 | 1.00 | 1.00 | 1.00 | 1.00 | 0% |
| CERT r4.2 | 117 | 68 | 49 | 2 | **0.58** | **0.97** | **0.73** | 0.69 | **5.3%** |

**Trade-off.** 2 missed insiders (`U0290`, `U0980`, both scenario 2) for 129 fewer false positives. In v1 both were caught only by `EXECUTABLE_TO_USB`. Scenario-2 users were already USB users, and their increase in USB use stayed below the `NEW_USB_USER` threshold (baseline mean + 4σ).

**Recall by CERT scenario:** 1 → 30/30 · 2 → 28/30 · 3 → 10/10.

**Caveat.** This change was chosen by looking at CERT labels, so CERT r4.2 is no longer a clean test for it. Confirm on r6.2 or another held-out release before reporting the v2 numbers as final.

**Open ideas for next experiments:**

- **A relative-increase rule for existing USB users** (for example, a 14-day rolling count of USB connects above 2× the baseline). It would target the 2 scenario-2 misses.
- **The RQ1 detector comparison** (z-score, IsolationForest, LOF, OC-SVM) on precision@k.
- **RQ2 Intensity sweeps** on fresh synthetic seeds.

---

## E3 — Full evaluation on fresh seeds (FR-8, RQ1–RQ4)

`python -m ueba.evaluate` uses synthetic seeds **101, 102 and 103**, which weren't used while developing or tuning. It also runs on CERT r4.2 (v2 rules), with gemma4 and hybrid RAG. Full output is in [reports/evaluation.md](../reports/evaluation.md). The detection settings are unchanged from E2, and the run took 4.5 minutes.

**Headline results:**

| Measure | Result |
|---|---|
| Synthetic, default Intensity (3 fresh seeds) | precision 0.88–0.94, recall 1.00, mean F1 **0.95** |
| CERT r4.2 | precision 0.58, recall 0.97, F1 0.73 (as in E2) |
| Demo cases | **8 of 8** passed end to end, including the CERT insider and the Privacy Lint trap |
| Human-in-the-loop | **0 violations** in 40 generated cases |
| Explanation rubric | 100% pass for both gemma4 and the template, 20 cases each, with 0 unsupported numbers |

**On fresh seeds the synthetic score drops from 1.00 to 0.95.** All **5 false positives across the 3 seeds are `SUSTAINED_INCREASE` Findings**: 4 are Finance users in the quarter-end rush, and 1 is a normal Legal user. In RQ3, 8.2% of `benign_quarter_end` users are flagged (4 of 49), against 0% of on-call staff and new hires. A department-wide surge looks like a personal sustained increase, because baselines are per user. This is the clearest case for peer-group-relative thresholds as future work.

### RQ1: detectors

- **The combined Risk Score barely changes with the detector** (same F1 everywhere). Rules carry 75% of the score, and the ML part can only raise a score, never create one.
- **Ranking by the ML score alone:**
  - On synthetic data, the simple **baseline z-score is best** (AUC ≈ 0.99, precision@k ≈ 0.84).
  - On CERT, **IsolationForest is best** (AUC 0.968, precision@k 0.59), with OC-SVM close behind (0.964 and 0.56).
  - LOF is the weakest on CERT (precision@k 0.07), and the slowest (28 seconds).
- **Choosing IsolationForest as the default is justified by CERT,** the external benchmark. On our own synthetic data, the simplest statistical baseline is as good or better.

### RQ2: sensitivity to Intensity

| Scenario | Smallest level reliably flagged by the Risk Score |
|---|---|
| `after_hours` | Level 1 (4 events per night) |
| `new_device_transfer` | Level 2 (6 transfers per day) |
| `cross_department_sensitive` | Level 3 (8 accesses per day) |
| `mass_download` | Level 3–4 (10–50× normal; the rule's floor of 25 transfers per day limits it) |
| `slow_drip` | Partial at levels 0–2 (22–56%), fully caught at level 3 (+5 per day) |

The **ML detector alone** seems to catch faint anomalies the rules miss: at level 0, 33–89% of each scenario's users. But the reference rows show it flags **17–20% of normal users and 55–69% of hard negatives at every level**. At faint levels its "recall" is mostly no better than its false-alarm rate. The combined score keeps normal users at about 0% and hard negatives at 3–4.5%. This supports the design rule "ML can raise a score but never create one".

### RQ3: false positives and fairness

- **Hard negatives:** on-call staff 0% (0 of 9), new hires 0% (0 of 9), quarter-end Finance 8.2% (4 of 49).
- **Departments, synthetic + CERT combined:** false-positive rates range from 0% to 11.8%. The highest are small CERT units: Purchasing & Contracts 2 of 17, Administration 8 of 82. With so few users, these rates have wide uncertainty.

### RQ4: explanation quality

Both writers pass every automated criterion. The rubric has hit a **ceiling**: it can't separate gemma4 from the template. A gemma4 summary in an earlier run said "on separate occasions", which wasn't in the facts, and the rubric didn't catch it, because the guard checks numbers, not claims.

**Next steps:**

1. A **human-rated sample**, blind to which writer produced each case.
2. A **claim-level faithfulness check.**
3. A **second local model** for a real model comparison.

### Error analysis (CERT)

- **49 false positives.** The most common pattern is `AFTER_HOURS` + `EXECUTABLE_TO_USB` (20 users). It needs a primary rule (after-hours, medium) plus a supporting one, so these are users with genuinely unusual nights who also happened to copy an `.exe`.
- **2 false negatives,** both scenario-2 users already discussed in E2.

---

## E4 — RQ4 with two local LLMs; blind human-rating set

**Setup:**

- `ollama pull llama3.2` (3B, 2.0 GB) added a second local model alongside gemma4 (8B).
- `python -m ueba.evaluate` now compares the template, gemma4 and llama3.2 on the same 10 flagged users per dataset.
- `python -m ueba.rating build --users-per-dataset 3` created a blind rating set: **18 items** (3 users × 2 datasets × 3 writers), with the writer key kept separately in `data/rating/key.json`.

**Automated rubric:**

| Writer | Rubric pass | Unsupported numbers | Fallbacks | Mean time per case |
|---|---|---|---|---|
| Template | 100% | 0 | — | 0.04–0.08 s |
| gemma4 (8B) | 100% | 0 | 0 | 5.7–6.5 s |
| llama3.2 (3B) | 100% | 0 | 0 | 2.8 s |

**Observation (qualitative, not yet rated):** llama3.2's summaries are noticeably weaker.

- It lists rule names ("MASS_DOWNLOAD, NEW_DEVICE_TRANSFER…") instead of the evidence.
- It repeats an awkward phrase ("High risk level (96.3) and score").
- It produces near-identical text for different users.

gemma4 cites the actual evidence ("31 file transfers on 2026-09-23 … 30 transfers from a new device").

**Conclusion so far.** The automated rubric can't separate a clearly weaker model from a stronger one. It measures safety and grounding, which all three writers meet, not quality. The blind human rating is therefore the deciding measure for RQ4's "how do models compare".

**Next.** Each team member runs `streamlit run src/ueba/rating_app.py` (18 items, about 20–30 minutes). Then `python -m ueba.rating analyse` writes `reports/human_rating.md`, including Krippendorff's alpha. If alpha is below 0.67, report the comparison as inconclusive.
