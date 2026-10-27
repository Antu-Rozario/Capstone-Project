"""Full evaluation: detection metrics, RQ1-RQ4, explanation rubric, demo cases, HITL check (FR-8).

Writes reports/evaluation.md, reports/evaluation.json and plots.

Run: .venv/bin/python -m ueba.evaluate            # full (about 10 minutes with gemma4)
     .venv/bin/python -m ueba.evaluate --quick    # smoke run
"""

from __future__ import annotations

import argparse
import json
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Any

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import pandas as pd  # noqa: E402

from ueba.agent import NarrativeLLM, OllamaLLM  # noqa: E402
from ueba.dashboard import Dataset, load_dataset  # noqa: E402
from ueba.demo import run_demo_cases  # noqa: E402
from ueba.detection import run_detection  # noqa: E402
from ueba.detectors import DETECTORS  # noqa: E402
from ueba.evaluation import detection_metrics  # noqa: E402
from ueba.generator import GeneratorConfig  # noqa: E402
from ueba.rag import build_index  # noqa: E402
from ueba.review import authorised_actions  # noqa: E402
from ueba.studies import SWEEP_LEVELS, rq1_detectors, rq2_sensitivity, rq3_fairness, rq4_narratives_with_cases, synthetic_dataset  # noqa: E402

# Fresh seeds: never used while developing or tuning (development used 7, 11 and 42).
FRESH_SEEDS = [101, 102, 103]
DEFAULT_DETECTOR = "isolation_forest"


def _md(df: pd.DataFrame, floatfmt: str = ".3f") -> str:
    def fmt(v: Any) -> str:
        return format(v, floatfmt) if isinstance(v, float) else str(v)

    header = "| " + " | ".join(map(str, df.columns)) + " |"
    sep = "|" + "---|" * len(df.columns)
    rows = ["| " + " | ".join(fmt(v) for v in row) + " |" for row in df.itertuples(index=False)]
    return "\n".join([header, sep, *rows])


def _plot_rq1(df: pd.DataFrame, path: Path) -> None:
    pivot = df.groupby("detector")[["f1", "precision_at_k", "ml_auc", "ml_precision_at_k"]].mean()
    ax = pivot.plot.bar(figsize=(8, 4.5), rot=0)
    ax.set_ylim(0, 1.05)
    ax.set_title("RQ1 — detectors (mean over datasets)")
    ax.legend(loc="upper center", bbox_to_anchor=(0.5, -0.15), ncol=4, fontsize=8)
    plt.tight_layout()
    plt.savefig(path, dpi=120)
    plt.close()


def _plot_rq2(df: pd.DataFrame, path: Path) -> None:
    g = df.groupby(["scenario", "level"])[["recall", "ml_recall"]].mean().reset_index()
    fig, axes = plt.subplots(1, 2, figsize=(10, 4), sharey=True)
    for scenario, sub in g.groupby("scenario"):
        style = {"linestyle": "--", "color": "gray" if "normal" in str(scenario) else "black"} if str(scenario).startswith("(reference)") else {}
        axes[0].plot(sub["level"], sub["recall"], marker="o", label=scenario, **style)
        axes[1].plot(sub["level"], sub["ml_recall"], marker="o", label=scenario, **style)
    axes[0].set_title("Rules + ML (flagged Medium+)")
    axes[1].set_title("ML only (day above 99th percentile)")
    for ax in axes:
        ax.set_xlabel("Intensity level (0 = faint, 4 = strong)")
        ax.set_xticks(sorted(g["level"].unique()))
        ax.set_ylim(-0.05, 1.05)
    axes[0].set_ylabel("Recall")
    axes[1].legend(fontsize=7, loc="lower right")
    fig.suptitle("RQ2 — recall vs Intensity")
    plt.tight_layout()
    plt.savefig(path, dpi=120)
    plt.close()


def _plot_rq3(df: pd.DataFrame, path: Path) -> None:
    sub = df.sort_values("fp_rate")
    labels = [f"{t[:4]}: {g}" for t, g in zip(sub["group_type"], sub["group"])]
    plt.figure(figsize=(8, 0.35 * len(sub) + 1))
    plt.barh(labels, sub["fp_rate"])
    plt.xlabel("False-positive rate (non-anomalous users flagged)")
    plt.title("RQ3 — false positives by department and hard negative")
    plt.tight_layout()
    plt.savefig(path, dpi=120)
    plt.close()


def _error_analysis(ds: Dataset) -> dict[str, Any]:
    assert ds.labels is not None
    result = run_detection(ds.events, ds.users, ds.baseline_end, DEFAULT_DETECTOR)
    df = result.ranking.merge(ds.labels, on="user_id")
    flagged = df["risk_level"].isin(["High", "Medium"])
    fp = df[flagged & ~df["is_anomalous"]]
    fn = df[~flagged & df["is_anomalous"]]
    rule_counts = Counter(r for rules in fp["rules"] for r in str(rules).split(", ") if r)
    return {
        "dataset": ds.name,
        "false_positives": int(len(fp)),
        "false_negatives": int(len(fn)),
        "fp_rule_counts": dict(rule_counts.most_common()),
        "fp_top_rule_combinations": fp["rules"].value_counts().head(5).to_dict(),
        "false_negative_users": fn[["user_id", "scenario", "risk_score", "rules"]].to_dict(orient="records"),
    }


def run(args: argparse.Namespace) -> dict[str, Any]:
    out: Path = args.out
    out.mkdir(parents=True, exist_ok=True)
    seeds = FRESH_SEEDS[:1] if args.quick else FRESH_SEEDS
    synth = [synthetic_dataset(GeneratorConfig(n_users=args.users, seed=s)) for s in seeds]
    cert: Dataset | None = None
    if not args.no_cert and (args.cert_dir / "events.parquet").exists():
        cert = load_dataset(args.cert_dir)
    datasets = synth + ([cert] if cert is not None else [])

    retriever = build_index(backend=args.rag)
    llm: NarrativeLLM | None = None
    if args.llm != "none":
        candidate = OllamaLLM("gemma4" if args.llm == "auto" else args.llm)
        llm = candidate if candidate.available() else None

    print("detection + RQ1 …")
    detectors = ["baseline_zscore", DEFAULT_DETECTOR] if args.quick else list(DETECTORS)
    rq1 = rq1_detectors(datasets, detectors)
    detection = rq1[rq1["detector"] == DEFAULT_DETECTOR].drop(columns=["detector"])

    print("RQ2 …")
    n_levels = len(next(iter(SWEEP_LEVELS.values()))[1])
    rq2 = rq2_sensitivity(seeds, levels=[0, n_levels // 2, n_levels - 1] if args.quick else None, n_users=args.users)

    print("RQ3 …")
    rq3 = rq3_fairness(datasets)

    print("RQ4 + explanation rubric …")
    writers: dict[str, NarrativeLLM | None] = {"template": None}
    if args.llm != "none":
        # RQ4 compares every available model; the demo cases use the primary one (--llm).
        for model in [m.strip() for m in args.models.split(",") if m.strip()]:
            candidate = OllamaLLM(model)
            if candidate.available():
                writers[candidate.name] = candidate
    n_cases = 3 if args.quick else 10
    rq4_frames, generated = [], []
    for ds in [synth[0]] + ([cert] if cert is not None else []):
        df, cases = rq4_narratives_with_cases(ds, retriever, writers, n_cases)
        rq4_frames.append(df)
        generated += [c for cs in cases.values() for c in cs]
    rq4 = pd.concat(rq4_frames, ignore_index=True)
    fallback_reasons = Counter(c["generated_by"] for c in generated if "fallback" in c["generated_by"])

    print("demo cases …")
    demo = run_demo_cases(synth[0], retriever, llm, cert)

    hitl_cases = generated
    violations = sum(any(a["requires_approval"] for a in authorised_actions(c, None)) for c in hitl_cases)
    errors = [_error_analysis(ds) for ds in ([synth[0]] + ([cert] if cert is not None else []))]

    rq1.to_csv(out / "rq1_detectors.csv", index=False)
    rq2.to_csv(out / "rq2_sensitivity.csv", index=False)
    rq3.to_csv(out / "rq3_fairness.csv", index=False)
    rq4.to_csv(out / "rq4_narratives.csv", index=False)
    _plot_rq1(rq1, out / "rq1_detectors.png")
    _plot_rq2(rq2, out / "rq2_sensitivity.png")
    _plot_rq3(rq3, out / "rq3_fairness.png")

    demo_counts = Counter(r.status for r in demo)
    data: dict[str, Any] = {
        "settings": {"generated": datetime.now().isoformat(timespec="seconds"), "mode": "quick" if args.quick else "full",
                     "seeds": seeds, "users": args.users, "detector": DEFAULT_DETECTOR, "llm": llm.name if llm else "none",
                     "rag": retriever.backend, "cert": cert is not None},
        "detection": detection.to_dict(orient="records"),
        "rq1": rq1.to_dict(orient="records"),
        "rq2": rq2.to_dict(orient="records"),
        "rq3": rq3.to_dict(orient="records"),
        "rq4": rq4.to_dict(orient="records"),
        "fallback_reasons": dict(fallback_reasons),
        "demo": {"passed": demo_counts["passed"], "failed": demo_counts["failed"], "skipped": demo_counts["skipped"],
                 "cases": [vars(r) for r in demo]},
        "hitl": {"cases_checked": len(hitl_cases), "violations": int(violations)},
        "error_analysis": errors,
    }
    (out / "evaluation.json").write_text(json.dumps(data, indent=2, default=str))
    (out / "evaluation.md").write_text(_report(data, rq1, rq2, rq3, rq4, detection, demo))
    return data


def _report(data: dict[str, Any], rq1: pd.DataFrame, rq2: pd.DataFrame, rq3: pd.DataFrame, rq4: pd.DataFrame,
            detection: pd.DataFrame, demo: list[Any]) -> str:
    s = data["settings"]
    synth = detection[detection["dataset"].str.startswith("synthetic")]
    demo_ran = data["demo"]["passed"] + data["demo"]["failed"]
    rq2_table = rq2.groupby(["scenario", "level"])["recall"].mean().unstack("level")
    rq2_table.columns = [f"level {c}" for c in rq2_table.columns]
    rq2_ml_table = rq2.groupby(["scenario", "level"])["ml_recall"].mean().unstack("level")
    rq2_ml_table.columns = [f"level {c}" for c in rq2_ml_table.columns]
    intensity_rows = pd.DataFrame([{"scenario": sc, "field": f, **{f"level {i}": v for i, v in enumerate(vals)}}
                                   for sc, (f, vals) in SWEEP_LEVELS.items()])
    lines = [
        "# Evaluation Report",
        "",
        f"Generated {s['generated']} · mode **{s['mode']}** · synthetic seeds {s['seeds']} ({s['users']} users each; "
        f"fresh seeds, not used in development) · CERT r4.2: {'yes' if s['cert'] else 'no'} · "
        f"detector {s['detector']} · LLM {s['llm']} · RAG {s['rag']}",
        "",
        "A user counts as **flagged** at risk level Medium or High. All numbers come from `evaluation.json` in this folder.",
        "",
        "## 1. Headline results",
        "",
        "| Measure | Result |",
        "|---|---|",
        f"| Synthetic F1 (mean over seeds) | {synth['f1'].mean():.3f} |" if len(synth) else "| Synthetic F1 | n/a |",
        *([f"| CERT r4.2 precision / recall / F1 | {r['precision']:.3f} / {r['recall']:.3f} / {r['f1']:.3f} |"
           for r in detection[detection['dataset'].str.startswith('cert')].to_dict(orient='records')]),
        f"| Demo cases passed | {data['demo']['passed']} of {demo_ran} run ({data['demo']['skipped']} skipped) |",
        f"| Human-in-the-loop violations | {data['hitl']['violations']} in {data['hitl']['cases_checked']} cases |",
        *[f"| Rubric pass rate: {r['writer']} on {r['dataset']} | {r['rubric_pass_rate']:.0%} |" for r in rq4.to_dict(orient="records")],
        "",
        "## 2. Detection accuracy",
        "",
        _md(detection[["dataset", "precision", "recall", "f1", "precision_at_k", "ml_auc", "seconds"]]),
        "",
        "## 3. RQ1 — How do the detectors compare?",
        "",
        "The Risk Score is 75% rule Findings, so the detector changes the combined metrics only slightly. "
        "`ml_auc` and `ml_precision_at_k` rank users by the ML score alone and isolate the detector itself.",
        "",
        _md(rq1),
        "",
        "![RQ1](rq1_detectors.png)",
        "",
        "## 4. RQ2 — How faint can an anomaly be before it's missed?",
        "",
        "Recall of each scenario's users (flagged Medium+), averaged over seeds. The two **(reference)** rows apply the "
        "same test to users who should *not* be flagged, so they are false-flag rates. Compare `ml_recall` with them "
        "before crediting the ML detector with faint anomalies. Intensity values per level:",
        "",
        _md(intensity_rows),
        "",
        "**Rules + ML (the Risk Score):**",
        "",
        _md(rq2_table.reset_index()),
        "",
        "**ML detector alone** (user has a day above the 99th percentile of normal days):",
        "",
        _md(rq2_ml_table.reset_index()),
        "",
        "![RQ2](rq2_sensitivity.png)",
        "",
        "## 5. RQ3 — Who is flagged wrongly?",
        "",
        "False-positive rate among non-anomalous users, by department and by hard-negative group (summed over datasets).",
        "",
        _md(rq3),
        "",
        "![RQ3](rq3_fairness.png)",
        "",
        "## 6. RQ4 — Explanation quality and hallucination",
        "",
        "Rubric criteria are binary per case: **clear**, **evidence_based**, **actionable**, **safe** (see `src/ueba/rubric.py`). "
        "`unsupported_rate` is the share of numbers in summaries that don't appear in the case's facts. "
        "`benign_grounded_rate` is the share of innocent explanations that match a playbook explanation.",
        "",
        _md(rq4),
        "",
        "Fallback reasons: " + (", ".join(f"{k} ×{v}" for k, v in data["fallback_reasons"].items()) or "none"),
        "",
        "## 7. Demo cases",
        "",
        _md(pd.DataFrame([{"case": r.name, "user": r.user_id, "status": r.status, "risk": r.risk_level,
                           "generated_by": r.generated_by, "details": "; ".join(r.details)} for r in demo])),
        "",
        "## 8. Human-in-the-loop check",
        "",
        f"Checked {data['hitl']['cases_checked']} generated cases: with no Review Decision, "
        f"{data['hitl']['violations']} authorised a Sensitive Recommendation.",
        "",
        "## 9. Error analysis",
        "",
    ]
    for e in data["error_analysis"]:
        lines += [f"**{e['dataset']}**: {e['false_positives']} false positives, {e['false_negatives']} false negatives.", "",
                  f"- Rules behind false positives: {e['fp_rule_counts'] or 'none'}",
                  f"- Most common rule combinations: {e['fp_top_rule_combinations'] or 'none'}",
                  f"- Missed users: {e['false_negative_users'] or 'none'}", ""]
    lines += [
        "## 10. Limitations",
        "",
        "- **Synthetic results reflect the generator's assumptions.** The team wrote both the scenarios and the rules. RQ2 shows "
        "where detection breaks down; perfect scores at default Intensity show only that the pipeline works.",
        "- **CERT r4.2 is \"dense\"** (70 of 1,000 users), so real-world precision would be lower. The CERT rule change in "
        "experiment E2 was label-informed (docs/experiment-log.md).",
        "- **Rubric checks are automated proxies.** The hallucination guard checks numbers, not claims. A human-rated sample "
        "is still required (REQUIREMENTS §11 Q3).",
        "- **RQ4's automated rubric is at a ceiling.** Model differences need the blind human rating (`python -m ueba.rating`, see reports/human_rating.md).",
        "- **Control Mapping IDs are an unverified draft (FR-11).**",
        "",
        "## Reproduce",
        "",
        "```bash",
        ".venv/bin/python -m ueba.evaluate            # full",
        ".venv/bin/python -m ueba.evaluate --quick    # smoke run",
        "```",
        "",
    ]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="Run the full evaluation and write reports/evaluation.md.")
    parser.add_argument("--quick", action="store_true", help="1 seed, 3 Intensity levels, 2 detectors, 3 cases per writer")
    parser.add_argument("--llm", default="auto", help="primary LLM for demo cases: auto | none | an Ollama model name")
    parser.add_argument("--models", default="gemma4,llama3.2", help="models compared in RQ4 (unavailable ones are skipped)")
    parser.add_argument("--rag", default="auto", choices=["auto", "hybrid", "ollama", "tfidf"])
    parser.add_argument("--cert-dir", type=Path, default=Path("data/processed/cert_r4.2"))
    parser.add_argument("--no-cert", action="store_true")
    parser.add_argument("--users", type=int, default=120)
    parser.add_argument("--out", type=Path, default=Path("reports"))
    data = run(parser.parse_args(argv))
    print(f"demo: {data['demo']['passed']} passed, {data['demo']['failed']} failed, {data['demo']['skipped']} skipped · "
          f"HITL violations: {data['hitl']['violations']}")


if __name__ == "__main__":
    main()
