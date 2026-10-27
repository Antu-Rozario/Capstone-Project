"""Research-question studies (REQUIREMENTS §7), built on the FR-8 metrics.

RQ1 detectors · RQ2 sensitivity to Intensity · RQ3 false positives and fairness · RQ4 narrative quality.
Synthetic studies use fresh seeds that weren't used during development (see evaluate.py).
"""

from __future__ import annotations

import time
from dataclasses import asdict
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd
from sklearn.metrics import roc_auc_score

from ueba.agent import CaseAgent, NarrativeLLM, Toolbox
from ueba.controls import load_control_mapping
from ueba.dashboard import Dataset
from ueba.detection import SCENARIO_RULE, DetectionResult, run_detection
from ueba.evaluation import detection_metrics
from ueba.generator import GeneratorConfig, Intensity, generate
from ueba.rag import Retriever
from ueba.rubric import RUBRIC_CRITERIA, hallucination_stats, score_case

FLAGGED = ("High", "Medium")
ML_FLAG = 0.99  # ML-only "flag": a day more unusual than 99% of normal days

# Per scenario: the Intensity field swept and its values. Level i applies value i to every scenario at once.
SWEEP_LEVELS: dict[str, tuple[str, list[float]]] = {
    "mass_download": ("mass_download_multiplier", [2, 3, 5, 10, 50]),
    "after_hours": ("after_hours_events_per_night", [2, 4, 8, 15, 25]),
    "cross_department_sensitive": ("cross_department_accesses_per_day", [1, 2, 4, 8, 12]),
    "new_device_transfer": ("new_device_transfers_per_day", [2, 4, 6, 10, 30]),
    "slow_drip": ("slow_drip_extra_per_day", [1, 2, 3, 5, 8]),
}


def synthetic_dataset(cfg: GeneratorConfig) -> Dataset:
    s = generate(cfg)
    return Dataset(f"synthetic-seed{cfg.seed}", Path("."), s.events, s.users, s.labels, s.baseline_end)


def _ml_user_scores(result: DetectionResult) -> pd.Series:
    per_user = result.ml_scores.groupby(result.features.loc[result.ml_scores.index, "user_id"]).max()
    return per_user.reindex(result.ranking["user_id"]).fillna(0.0)


# --- RQ1 -------------------------------------------------------------------------------


def rq1_detectors(datasets: list[Dataset], detectors: list[str]) -> pd.DataFrame:
    rows = []
    for ds in datasets:
        assert ds.labels is not None
        truth = ds.labels.set_index("user_id")["is_anomalous"].astype(bool)
        for det in detectors:
            t = time.perf_counter()
            result = run_detection(ds.events, ds.users, ds.baseline_end, det)
            seconds = time.perf_counter() - t
            m = detection_metrics(result.ranking, ds.labels)
            ml = _ml_user_scores(result)
            y = truth.reindex(ml.index).fillna(False).to_numpy()
            k = int(y.sum())
            top = ml.sort_values(ascending=False).head(k).index
            rows.append({
                "dataset": ds.name, "detector": det,
                "precision": m["precision"], "recall": m["recall"], "f1": m["f1"], "precision_at_k": m["precision_at_k"],
                "ml_auc": float(roc_auc_score(y, ml.to_numpy())) if 0 < k < len(y) else float("nan"),
                "ml_precision_at_k": float(truth.reindex(top).fillna(False).mean()) if k else float("nan"),
                "seconds": seconds,
            })
    return pd.DataFrame(rows)


# --- RQ2 -------------------------------------------------------------------------------


def _intensity_at(level: int) -> Intensity:
    overrides: dict[str, Any] = {field: values[level] for field, values in SWEEP_LEVELS.values()}
    return Intensity(**{**asdict(Intensity()), **overrides})


def rq2_sensitivity(seeds: list[int], levels: list[int] | None = None, n_users: int = 120,
                    detector: str = "isolation_forest") -> pd.DataFrame:
    n_levels = len(next(iter(SWEEP_LEVELS.values()))[1])
    rows = []
    for level in levels if levels is not None else list(range(n_levels)):
        for seed in seeds:
            cfg = GeneratorConfig(n_users=n_users, seed=seed, intensity=_intensity_at(level))
            s = generate(cfg)
            result = run_detection(s.events, s.users, s.baseline_end, detector)
            rank = result.ranking.set_index("user_id")
            ml = _ml_user_scores(result)
            for scenario, (field, values) in SWEEP_LEVELS.items():
                users = s.labels.loc[s.labels["scenario"] == scenario, "user_id"].tolist()
                rules = {u: {f.rule for f in result.findings_for(u)} for u in users}
                rows.append({
                    "scenario": scenario, "level": level, "intensity_field": field, "intensity": values[level],
                    "seed": seed, "users": len(users),
                    "recall": float(np.mean([rank.loc[u, "risk_level"] in FLAGGED for u in users])),
                    "rule_recall": float(np.mean([SCENARIO_RULE[scenario] in rules[u] for u in users])),
                    "ml_recall": float(np.mean([ml.get(u, 0.0) >= ML_FLAG for u in users])),
                })
            # Reference rows: the same thresholds applied to users who should NOT be flagged.
            # Without these, ML-only "recall" at faint intensities would look better than it is.
            groups = {
                "(reference) normal users": s.labels["scenario"] == "normal",
                "(reference) hard negatives": s.labels["scenario"].astype(str).str.startswith("benign_"),
            }
            for name, mask in groups.items():
                users = s.labels.loc[mask, "user_id"].tolist()
                rows.append({
                    "scenario": name, "level": level, "intensity_field": "", "intensity": float("nan"),
                    "seed": seed, "users": len(users),
                    "recall": float(np.mean([rank.loc[u, "risk_level"] in FLAGGED for u in users])),
                    "rule_recall": float("nan"),
                    "ml_recall": float(np.mean([ml.get(u, 0.0) >= ML_FLAG for u in users])),
                })
    return pd.DataFrame(rows)


# --- RQ3 -------------------------------------------------------------------------------


def rq3_fairness(datasets: list[Dataset], detector: str = "isolation_forest") -> pd.DataFrame:
    """False-positive counts by department and by Hard Negative group, summed over datasets."""
    frames = []
    for ds in datasets:
        assert ds.labels is not None
        result = run_detection(ds.events, ds.users, ds.baseline_end, detector)
        df = result.ranking.merge(ds.labels, on="user_id")
        df = df[~df["is_anomalous"].astype(bool)]
        df["flagged"] = df["risk_level"].isin(FLAGGED)
        frames.append(df.assign(dataset=ds.name))
    df = pd.concat(frames)
    dept = df.groupby("department").agg(users=("user_id", "size"), flagged=("flagged", "sum")).reset_index()
    dept = dept.rename(columns={"department": "group"}).assign(group_type="department")
    hn = df[df["scenario"].astype(str).str.startswith("benign_")]
    hn = hn.groupby("scenario").agg(users=("user_id", "size"), flagged=("flagged", "sum")).reset_index()
    hn = hn.rename(columns={"scenario": "group"}).assign(group_type="hard_negative")
    out = pd.concat([dept, hn], ignore_index=True)
    out["flagged"] = out["flagged"].astype(int)
    out["fp_rate"] = out["flagged"] / out["users"]
    return out[["group_type", "group", "users", "flagged", "fp_rate"]]


# --- RQ4 -------------------------------------------------------------------------------


def rq4_narratives(ds: Dataset, retriever: Retriever, writers: dict[str, NarrativeLLM | None], n_cases: int = 10,
                   detector: str = "isolation_forest") -> pd.DataFrame:
    """Rubric and hallucination metrics per narrative writer, on the top-n flagged users."""
    df, _ = rq4_narratives_with_cases(ds, retriever, writers, n_cases, detector)
    return df


def rq4_narratives_with_cases(ds: Dataset, retriever: Retriever, writers: dict[str, NarrativeLLM | None],
                              n_cases: int = 10, detector: str = "isolation_forest"
                              ) -> tuple[pd.DataFrame, dict[str, list[dict[str, Any]]]]:
    result = run_detection(ds.events, ds.users, ds.baseline_end, detector)
    users = result.ranking.loc[result.ranking["risk_level"].isin(FLAGGED), "user_id"].head(n_cases).tolist()
    toolbox = Toolbox(result, ds.events, ds.users, retriever, load_control_mapping())
    rows, all_cases = [], {}
    for name, llm in writers.items():
        agent = CaseAgent(toolbox, llm)
        cases, seconds = [], []
        for u in users:
            t = time.perf_counter()
            cases.append(agent.build_case(u).to_dict())
            seconds.append(time.perf_counter() - t)
        scores = [score_case(c, retriever) for c in cases]
        hall = hallucination_stats(cases, retriever)
        row: dict[str, Any] = {"dataset": ds.name, "writer": name, "cases": len(cases),
                               "rubric_pass_rate": float(np.mean([s["passed"] for s in scores])) if scores else 0.0}
        for crit in RUBRIC_CRITERIA:
            row[crit] = float(np.mean([s["criteria"][crit] for s in scores])) if scores else 0.0
        row["unsupported_rate"] = hall["unsupported_rate"]
        row["benign_grounded_rate"] = hall["benign_grounded_rate"]
        row["fallback_rate"] = float(np.mean(["fallback" in c["generated_by"] for c in cases])) if cases else 0.0
        row["mean_seconds"] = float(np.mean(seconds)) if seconds else 0.0
        rows.append(row)
        all_cases[name] = cases
    return pd.DataFrame(rows), all_cases
