"""Blind human rating of Case Summary narratives (RQ4).

1. `build`: the same flagged users are summarised by every narrative writer (the template and each LLM).
   Items are shuffled and saved without the writer; the key goes in a separate file.
2. Raters score each item 1-5 for every criterion in the rating app (`rating_app.py`), and flag
   unsupported claims.
3. `analyse`: un-blinds the results and reports per-writer means, the unsupported-claim rate and
   inter-rater agreement (Krippendorff's alpha, interval scale).

Run: .venv/bin/python -m ueba.rating build
     .venv/bin/python -m streamlit run src/ueba/rating_app.py
     .venv/bin/python -m ueba.rating analyse
"""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd

from ueba.agent import CaseAgent, NarrativeLLM, OllamaLLM, Toolbox
from ueba.controls import load_control_mapping
from ueba.dashboard import Dataset, load_dataset
from ueba.detection import run_detection
from ueba.generator import GeneratorConfig
from ueba.rag import Retriever, build_index
from ueba.studies import synthetic_dataset

CRITERIA: dict[str, str] = {
    "clarity": "Easy to understand; states the risk level and what happened.",
    "faithfulness": "Every statement is supported by the evidence shown; nothing is invented or exaggerated.",
    "usefulness": "Helps an analyst decide what to check next.",
    "neutrality": "Describes activity, not the person; no accusation, speculation or loaded words.",
}
DEFAULT_DIR = Path("data/rating")


# --- build ------------------------------------------------------------------------------


def build_rating_set(
    datasets: list[Dataset],
    retriever: Retriever,
    writers: dict[str, NarrativeLLM | None],
    users_per_dataset: int = 5,
    seed: int = 2026,
) -> tuple[list[dict[str, Any]], dict[str, dict[str, str]]]:
    rng = np.random.default_rng(seed)
    items: list[dict[str, Any]] = []
    key: dict[str, dict[str, str]] = {}
    used_ids: set[str] = set()
    for ds in datasets:
        result = run_detection(ds.events, ds.users, ds.baseline_end)
        flagged = sorted(result.ranking.loc[result.ranking["risk_level"].isin(["High", "Medium"]), "user_id"])
        chosen = list(rng.choice(flagged, size=min(users_per_dataset, len(flagged)), replace=False))
        toolbox = Toolbox(result, ds.events, ds.users, retriever, load_control_mapping())
        for user in chosen:
            for writer, llm in writers.items():
                case = CaseAgent(toolbox, llm).build_case(str(user)).to_dict()
                item_id = ""
                while not item_id or item_id in used_ids:
                    item_id = f"R{int(rng.integers(100000, 999999))}"
                used_ids.add(item_id)
                items.append({
                    "item_id": item_id,
                    "subject": case["subject"],
                    "risk_level": case["risk_level"],
                    "risk_score": case["risk_score"],
                    "evidence": [{"rule": o["rule"], "description": o["description"]} for o in case["observations"]],
                    "summary": case["summary"],
                    "possible_benign_explanations": case["possible_benign_explanations"],
                })
                key[item_id] = {"writer": writer, "case_id": case["case_id"], "generated_by": case["generated_by"],
                                "dataset": ds.name}
    order = rng.permutation(len(items))
    return [items[i] for i in order], key


def save_rating_set(items: list[dict[str, Any]], key: dict[str, dict[str, str]], folder: Path) -> None:
    folder = Path(folder)
    folder.mkdir(parents=True, exist_ok=True)
    (folder / "items.json").write_text(json.dumps(items, indent=2))
    (folder / "key.json").write_text(json.dumps(key, indent=2))


def load_rating_set(folder: Path) -> tuple[list[dict[str, Any]], dict[str, dict[str, str]]]:
    folder = Path(folder)
    return json.loads((folder / "items.json").read_text()), json.loads((folder / "key.json").read_text())


# --- ratings ----------------------------------------------------------------------------


class RatingStore:
    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self._ratings: list[dict[str, Any]] = json.loads(self.path.read_text()) if self.path.exists() else []

    def record(self, rater: str, item_id: str, scores: dict[str, int], unsupported_claim: bool, comment: str = "") -> None:
        if not rater.strip():
            raise ValueError("rater name is required")
        if set(scores) != set(CRITERIA):
            raise ValueError(f"scores must cover exactly {sorted(CRITERIA)}")
        if not all(isinstance(v, int) and 1 <= v <= 5 for v in scores.values()):
            raise ValueError("scores must be integers from 1 to 5")
        entry = {"rater": rater.strip(), "item_id": item_id, "scores": scores, "unsupported_claim": bool(unsupported_claim),
                 "comment": comment.strip(), "timestamp": datetime.now(timezone.utc).isoformat()}
        self._ratings = [r for r in self._ratings if not (r["rater"] == entry["rater"] and r["item_id"] == item_id)]
        self._ratings.append(entry)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(self._ratings, indent=2))

    def ratings(self) -> list[dict[str, Any]]:
        return list(self._ratings)

    def done_by(self, rater: str) -> set[str]:
        return {r["item_id"] for r in self._ratings if r["rater"] == rater.strip()}


# --- analysis ---------------------------------------------------------------------------


def krippendorff_alpha_interval(data: np.ndarray) -> float:
    """Krippendorff's alpha for interval data. `data` is raters x units; NaN marks a missing rating."""
    units = [col[~np.isnan(col)] for col in np.asarray(data, dtype=float).T]
    units = [u for u in units if len(u) >= 2]
    if not units:
        return float("nan")

    def pair_sq_sum(v: np.ndarray) -> float:  # sum over ordered pairs i != j of (vi - vj)^2
        return float(2 * (len(v) * np.sum(v**2) - np.sum(v) ** 2))

    values = np.concatenate(units)
    n = len(values)
    observed = sum(pair_sq_sum(u) / (len(u) - 1) for u in units) / n
    expected = pair_sq_sum(values) / (n * (n - 1))
    return 1.0 if expected == 0 else 1.0 - observed / expected


def analyse(items: list[dict[str, Any]], key: dict[str, dict[str, str]], ratings: list[dict[str, Any]]) -> dict[str, Any]:
    rows = [{"rater": r["rater"], "item_id": r["item_id"], "writer": key[r["item_id"]]["writer"],
             "fallback": "fallback" in key[r["item_id"]]["generated_by"], "unsupported_claim": r["unsupported_claim"],
             **r["scores"]} for r in ratings if r["item_id"] in key]
    df = pd.DataFrame(rows)
    if df.empty:
        return {"per_writer": pd.DataFrame(), "alpha": {}, "raters": 0, "items_rated": 0, "comments": []}
    per_writer = df.groupby("writer").agg(
        ratings=("item_id", "size"), items=("item_id", "nunique"),
        **{c: (c, "mean") for c in CRITERIA},
        unsupported_claim_rate=("unsupported_claim", "mean"), fallback_items=("fallback", "sum"),
    ).reset_index()
    alpha = {}
    for c in CRITERIA:
        matrix = df.pivot_table(index="rater", columns="item_id", values=c, aggfunc="mean")
        alpha[c] = krippendorff_alpha_interval(matrix.to_numpy())
    comments = [{"writer": key[r["item_id"]]["writer"], "comment": r["comment"]} for r in ratings if r.get("comment")]
    return {"per_writer": per_writer, "alpha": alpha, "raters": int(df["rater"].nunique()),
            "items_rated": int(df["item_id"].nunique()), "items_total": len(items), "comments": comments}


def write_report(result: dict[str, Any], path: Path) -> None:
    lines = ["# Human Rating of Case Summary Narratives (RQ4)", "",
             f"{result['raters']} raters · {result['items_rated']} of {result.get('items_total', '?')} items rated · "
             "scores 1 (poor) to 5 (excellent) · raters were blind to the writer.", "",
             "## Mean score per writer", ""]
    per = result["per_writer"]
    if per.empty:
        lines.append("No ratings yet.")
    else:
        cols = list(per.columns)
        lines += ["| " + " | ".join(cols) + " |", "|" + "---|" * len(cols)]
        for row in per.itertuples(index=False):
            lines.append("| " + " | ".join(f"{v:.2f}" if isinstance(v, float) else str(v) for v in row) + " |")
        lines += ["", "## Inter-rater agreement (Krippendorff's alpha, interval)", "",
                  "| criterion | alpha |", "|---|---|"]
        lines += [f"| {c} | {a:.2f} |" for c, a in result["alpha"].items()]
        lines += ["", "Alpha ≥ 0.80 is reliable; 0.67-0.80 allows tentative conclusions; below 0.67 means the raters disagree "
                  "too much to compare writers confidently.", ""]
        if result["comments"]:
            lines += ["## Rater comments", ""] + [f"- *{c['writer']}*: {c['comment']}" for c in result["comments"]]
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text("\n".join(lines) + "\n")


# --- CLI ----------------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="Blind human rating of Case Summary narratives (RQ4).")
    sub = parser.add_subparsers(dest="command", required=True)
    b = sub.add_parser("build", help="generate the blind rating set")
    b.add_argument("--models", default="gemma4,llama3.2", help="comma-separated Ollama models (unavailable ones are skipped)")
    b.add_argument("--users-per-dataset", type=int, default=5)
    b.add_argument("--cert-dir", type=Path, default=Path("data/processed/cert_r4.2"))
    b.add_argument("--no-cert", action="store_true")
    b.add_argument("--rag", default="auto")
    b.add_argument("--out", type=Path, default=DEFAULT_DIR)
    a = sub.add_parser("analyse", help="un-blind and summarise the ratings")
    a.add_argument("--dir", type=Path, default=DEFAULT_DIR)
    a.add_argument("--report", type=Path, default=Path("reports/human_rating.md"))
    args = parser.parse_args(argv)

    if args.command == "build":
        writers: dict[str, NarrativeLLM | None] = {"template": None}
        for model in [m.strip() for m in args.models.split(",") if m.strip()]:
            llm = OllamaLLM(model)
            if llm.available():
                writers[llm.name] = llm
            else:
                print(f"skipping {model}: not available in Ollama")
        datasets = [synthetic_dataset(GeneratorConfig(seed=101))]
        if not args.no_cert and (args.cert_dir / "events.parquet").exists():
            datasets.append(load_dataset(args.cert_dir))
        items, key = build_rating_set(datasets, build_index(backend=args.rag), writers, args.users_per_dataset)
        save_rating_set(items, key, args.out)
        print(f"{len(items)} blind items from {len(datasets)} datasets × writers {list(writers)} → {args.out}")
    else:
        items, key = load_rating_set(args.dir)
        result = analyse(items, key, RatingStore(args.dir / "ratings.json").ratings())
        write_report(result, args.report)
        print(result["per_writer"].to_string(index=False) if not result["per_writer"].empty else "no ratings yet")
        print(f"report → {args.report}")


if __name__ == "__main__":
    main()
