import copy
from pathlib import Path
from typing import Any

import pytest

from ueba.agent import CaseAgent, Toolbox
from ueba.controls import load_control_mapping
from ueba.detection import run_detection
from ueba.generator import GeneratorConfig, generate
from ueba.rag import Retriever, build_index
from ueba.rubric import RUBRIC_CRITERIA, hallucination_stats, score_case

POLICIES = Path(__file__).resolve().parents[1] / "policies"


@pytest.fixture(scope="module")
def retriever() -> Retriever:
    return build_index(POLICIES, backend="tfidf")


@pytest.fixture(scope="module")
def case(retriever: Retriever) -> dict[str, Any]:
    s = generate(GeneratorConfig(n_users=60, seed=11))
    r = run_detection(s.events, s.users, s.baseline_end)
    user = str(s.labels.loc[s.labels["scenario"] == "mass_download", "user_id"].iloc[0])
    return CaseAgent(Toolbox(r, s.events, s.users, retriever, load_control_mapping())).build_case(user).to_dict()


def test_a_well_formed_case_passes_every_criterion(case: dict[str, Any], retriever: Retriever) -> None:
    score = score_case(case, retriever)
    assert set(score["criteria"]) == set(RUBRIC_CRITERIA)
    assert all(score["criteria"].values()), score["reasons"]
    assert score["passed"] is True and score["reasons"] == []


def test_overlong_summary_without_risk_level_is_not_clear(case: dict[str, Any], retriever: Retriever) -> None:
    bad = copy.deepcopy(case)
    bad["summary"] = "words " * 150
    score = score_case(bad, retriever)
    assert score["criteria"]["clear"] is False and score["passed"] is False


def test_unresolvable_citation_or_invented_number_breaks_evidence(case: dict[str, Any], retriever: Retriever) -> None:
    bad = copy.deepcopy(case)
    bad["policy_citations"].append({"citation": "made-up#nowhere", "title": "", "section": "", "excerpt": ""})
    assert score_case(bad, retriever)["criteria"]["evidence_based"] is False
    bad = copy.deepcopy(case)
    bad["summary"] += " The user moved 424242 files."
    assert score_case(bad, retriever)["criteria"]["evidence_based"] is False


def test_no_actions_is_not_actionable(case: dict[str, Any], retriever: Retriever) -> None:
    bad = copy.deepcopy(case)
    bad["recommended_actions"] = [a for a in bad["recommended_actions"] if a["requires_approval"]]
    assert score_case(bad, retriever)["criteria"]["actionable"] is False  # nothing the analyst can do now


def test_ungated_sensitive_action_or_accusation_is_unsafe(case: dict[str, Any], retriever: Retriever) -> None:
    bad = copy.deepcopy(case)
    for a in bad["recommended_actions"]:
        if "restrict" in a["action"].lower():
            a["requires_approval"] = False
    assert score_case(bad, retriever)["criteria"]["safe"] is False
    bad = copy.deepcopy(case)
    bad["summary"] = "This malicious user is High risk and needs review."
    assert score_case(bad, retriever)["criteria"]["safe"] is False


def test_hallucination_stats_count_numeric_claims(case: dict[str, Any], retriever: Retriever) -> None:
    clean = hallucination_stats([case], retriever)
    assert clean["numeric_claims"] >= 1 and clean["unsupported_numeric_claims"] == 0
    bad = copy.deepcopy(case)
    bad["summary"] += " Also 777 and 888 files."
    stats = hallucination_stats([case, bad], retriever)
    assert stats["unsupported_numeric_claims"] == 2
    assert 0 < stats["unsupported_rate"] < 1


def test_benign_explanations_are_checked_against_the_playbooks_not_themselves(
    case: dict[str, Any], retriever: Retriever
) -> None:
    assert hallucination_stats([case], retriever)["benign_grounded_rate"] == 1.0  # template copies playbook items
    invented = copy.deepcopy(case)
    invented["possible_benign_explanations"] = ["Their cat walked across the keyboard."]
    assert hallucination_stats([invented], retriever)["benign_grounded_rate"] == 0.0
