"""Eight prepared end-to-end demo cases (FR-8 "demo success rate on 5-10 prepared test cases").

Each case runs the full pipeline: detection → agent → validation → rubric → human-in-the-loop
check. Users are picked deterministically (first matching user ID), never the best-ranked one,
so the cases aren't cherry-picked.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import pandas as pd

from ueba.agent import CaseAgent, NarrativeLLM, Toolbox, validate_case
from ueba.controls import load_control_mapping
from ueba.dashboard import Dataset
from ueba.detection import DetectionResult, run_detection
from ueba.rag import Retriever
from ueba.review import authorised_actions
from ueba.rubric import score_case


@dataclass(frozen=True)
class DemoCase:
    name: str
    source: str  # "synthetic" | "cert"
    scenario: str  # label used to pick the user
    expect: str  # "flagged" | "low"
    rule: str | None = None
    trap: bool = False


DEMO_CASES: list[DemoCase] = [
    DemoCase("Mass download", "synthetic", "mass_download", "flagged", "MASS_DOWNLOAD"),
    DemoCase("After-hours activity", "synthetic", "after_hours", "flagged", "AFTER_HOURS"),
    DemoCase("Cross-department sensitive access", "synthetic", "cross_department_sensitive", "flagged", "CROSS_DEPT_SENSITIVE"),
    DemoCase("Transfers from a new device", "synthetic", "new_device_transfer", "flagged", "NEW_DEVICE_TRANSFER"),
    DemoCase("Hard negative: on-call night work", "synthetic", "benign_on_call", "low"),
    DemoCase("Clean control: normal user", "synthetic", "normal", "low"),
    DemoCase("CERT insider", "cert", "cert_scenario_", "flagged"),
    DemoCase("Privacy Lint trap", "synthetic", "mass_download", "flagged", "MASS_DOWNLOAD", trap=True),
]


class TrapLLM:
    """Deliberately writes accusatory narrative, to prove the Privacy Lint catches it."""

    name = "trap-llm"

    def write(self, system: str, facts: dict[str, Any]) -> dict[str, Any]:
        return {
            "summary": "This malicious employee is stealing company data and should be treated as a suspect.",
            "possible_benign_explanations": ["None; this is clearly theft."],
        }


@dataclass
class DemoResult:
    name: str
    user_id: str
    status: str  # passed | failed | skipped
    details: list[str] = field(default_factory=list)
    risk_level: str = ""
    case_id: str = ""
    generated_by: str = ""
    rubric: dict[str, bool] = field(default_factory=dict)


def _pick_user(labels: pd.DataFrame, scenario: str) -> str | None:
    match = labels[labels["scenario"].astype(str).str.startswith(scenario)] if scenario.endswith("_") \
        else labels[labels["scenario"] == scenario]
    return str(match["user_id"].sort_values().iloc[0]) if len(match) else None


def _run_one(
    demo: DemoCase, ds: Dataset, result: DetectionResult, retriever: Retriever, llm: NarrativeLLM | None
) -> DemoResult:
    assert ds.labels is not None
    user = _pick_user(ds.labels, demo.scenario)
    if user is None:
        return DemoResult(demo.name, "", "skipped", [f"no user with scenario {demo.scenario}"])
    row = result.ranking.set_index("user_id").loc[user]
    out = DemoResult(demo.name, user, "passed", risk_level=str(row["risk_level"]))
    flagged = row["risk_level"] in ("High", "Medium")
    rules = {f.rule for f in result.findings_for(user)}

    if demo.expect == "low":
        if flagged:
            out.status, out.details = "failed", [f"expected Low, got {row['risk_level']} ({', '.join(sorted(rules))})"]
        return out

    if not flagged:
        out.status = "failed"
        out.details.append(f"expected flagged, got {row['risk_level']}")
        return out
    if demo.rule and demo.rule not in rules:
        out.status = "failed"
        out.details.append(f"expected rule {demo.rule}, got {sorted(rules)}")

    toolbox = Toolbox(result, ds.events, ds.users, retriever, load_control_mapping())
    case = CaseAgent(toolbox, TrapLLM() if demo.trap else llm).build_case(user).to_dict()
    out.case_id, out.generated_by = case["case_id"], case["generated_by"]
    errors = validate_case(case)
    score = score_case(case, retriever)
    out.rubric = score["criteria"]
    if errors:
        out.details += [f"schema: {e}" for e in errors]
    if not score["passed"]:
        out.details += score["reasons"]
    if any(a["requires_approval"] for a in authorised_actions(case, None)):
        out.details.append("HITL: a sensitive action was authorised without approval")
    if demo.trap and not (case["generated_by"].startswith("template (fallback") and case["privacy_lint"]["passed"]):
        out.details.append("trap: accusatory narrative was not replaced")
    if out.details:
        out.status = "failed"
    return out


def run_demo_cases(
    synthetic: Dataset,
    retriever: Retriever,
    llm: NarrativeLLM | None,
    cert: Dataset | None = None,
    detector: str = "isolation_forest",
) -> list[DemoResult]:
    results_by_source: dict[str, tuple[Dataset, DetectionResult]] = {
        "synthetic": (synthetic, run_detection(synthetic.events, synthetic.users, synthetic.baseline_end, detector))
    }
    if cert is not None:
        results_by_source["cert"] = (cert, run_detection(cert.events, cert.users, cert.baseline_end, detector))
    out: list[DemoResult] = []
    for demo in DEMO_CASES:
        if demo.source not in results_by_source:
            out.append(DemoResult(demo.name, "", "skipped", [f"{demo.source} dataset not available"]))
            continue
        ds, result = results_by_source[demo.source]
        out.append(_run_one(demo, ds, result, retriever, llm))
    return out
