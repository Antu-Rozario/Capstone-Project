import json
import os
from pathlib import Path
from typing import Any

import pytest

from ueba.agent import CaseAgent, OllamaLLM, Toolbox, validate_case
from ueba.controls import load_control_mapping
from ueba.detection import DetectionResult, run_detection
from ueba.generator import GeneratorConfig, SyntheticData, generate
from ueba.privacy import lint_fields
from ueba.rag import build_index

POLICIES = Path(__file__).resolve().parents[1] / "policies"


class FakeLLM:
    def __init__(self, reply: dict[str, Any] | Exception) -> None:
        self.reply = reply
        self.name = "fake-llm"
        self.calls: list[dict[str, Any]] = []

    def write(self, system: str, facts: dict[str, Any]) -> dict[str, Any]:
        self.calls.append({"system": system, "facts": facts})
        if isinstance(self.reply, Exception):
            raise self.reply
        return self.reply


@pytest.fixture(scope="module")
def synth() -> SyntheticData:
    return generate(GeneratorConfig(n_users=60, seed=11))


@pytest.fixture(scope="module")
def result(synth: SyntheticData) -> DetectionResult:
    return run_detection(synth.events, synth.users, synth.baseline_end)


@pytest.fixture(scope="module")
def toolbox(synth: SyntheticData, result: DetectionResult) -> Toolbox:
    return Toolbox(result, synth.events, synth.users, build_index(POLICIES, backend="tfidf"), load_control_mapping())


def user_with(synth: SyntheticData, scenario: str) -> str:
    return str(synth.labels.loc[synth.labels["scenario"] == scenario, "user_id"].iloc[0])


# --- tools ----------------------------------------------------------------------


def test_get_user_context_returns_findings_and_evidence_without_identities(synth: SyntheticData, toolbox: Toolbox) -> None:
    user = user_with(synth, "mass_download")
    ctx = toolbox.get_user_context(user)
    assert ctx["user_id"] == user
    assert ctx["risk_level"] in {"High", "Medium"}
    assert any(f["rule"] == "MASS_DOWNLOAD" for f in ctx["findings"])
    assert ctx["event_sample"] and len(ctx["event_sample"]) <= 10
    names = set(synth.users["display_name"])
    assert not any(n in json.dumps(ctx) for n in names)


def test_search_policy_and_control_lookup_tools(toolbox: Toolbox) -> None:
    hits = toolbox.search_policy("mass download recommended actions", finding_type="MASS_DOWNLOAD")
    assert hits and all({"citation", "title", "section", "text"} <= set(h) for h in hits)
    mapping = toolbox.lookup_control_mapping("MASS_DOWNLOAD")
    assert mapping["attack"] and mapping["nist"]


# --- template path (no LLM) -------------------------------------------------------


@pytest.fixture(scope="module")
def template_case(synth: SyntheticData, toolbox: Toolbox) -> dict[str, Any]:
    return CaseAgent(toolbox, llm=None).build_case(user_with(synth, "mass_download")).to_dict()


def test_case_validates_against_the_schema(template_case: dict[str, Any]) -> None:
    assert validate_case(template_case) == []
    assert template_case["status"] == "pending_review"
    assert template_case["human_review_required"] is True
    assert template_case["generated_by"] == "template"


def test_observations_mirror_findings_with_numeric_evidence(
    template_case: dict[str, Any], result: DetectionResult
) -> None:
    findings = result.findings_for(template_case["subject"])
    assert {o["rule"] for o in template_case["observations"]} == {f.rule for f in findings}
    for o in template_case["observations"]:
        ev = o["evidence"]
        assert isinstance(ev["observed"], float) and isinstance(ev["expected"], float)
        assert ev["first_day"] <= ev["last_day"]


def test_every_finding_cites_its_playbook_and_every_citation_resolves(
    template_case: dict[str, Any], toolbox: Toolbox
) -> None:
    cited = {c["citation"] for c in template_case["policy_citations"]}
    assert all(toolbox.retriever.resolves(c) for c in cited)
    for o in template_case["observations"]:
        assert any(c.startswith(f"playbook-") and o["rule"] in toolbox.retriever.get(c).applies_to for c in cited)
    level = template_case["risk_level"].lower()
    assert f"escalation-matrix#{level}-risk" in cited


def test_control_mapping_covers_every_observed_rule(template_case: dict[str, Any]) -> None:
    mapped = {m["finding_type"] for m in template_case["control_mapping"]}
    assert mapped == {o["rule"] for o in template_case["observations"]}


def test_sensitive_recommendations_require_approval(template_case: dict[str, Any]) -> None:
    actions = template_case["recommended_actions"]
    assert actions and any(a["requires_approval"] for a in actions) and any(not a["requires_approval"] for a in actions)
    for a in actions:
        assert a["policy_ref"]
        if any(w in a["action"].lower() for w in ("restrict", "block", "refer", "reset credentials", "re-identif")):
            assert a["requires_approval"], a


def test_benign_explanations_come_from_the_playbooks(template_case: dict[str, Any]) -> None:
    assert 1 <= len(template_case["possible_benign_explanations"]) <= 6


def test_template_narrative_passes_the_privacy_lint(template_case: dict[str, Any], synth: SyntheticData) -> None:
    assert template_case["privacy_lint"] == {"passed": True, "violations": []}
    narrative = {"summary": template_case["summary"], "benign": template_case["possible_benign_explanations"]}
    assert lint_fields(narrative, real_names=synth.users["display_name"]) == []


def test_tool_trace_records_all_three_tools(template_case: dict[str, Any]) -> None:
    tools = {step["tool"] for step in template_case["tool_trace"]}
    assert tools == {"get_user_context", "search_policy", "lookup_control_mapping"}


def test_users_without_findings_get_no_case(synth: SyntheticData, toolbox: Toolbox, result: DetectionResult) -> None:
    quiet = result.ranking.loc[result.ranking["n_findings"] == 0, "user_id"].iloc[0]
    with pytest.raises(ValueError, match="no Findings"):
        CaseAgent(toolbox).build_case(str(quiet))


# --- LLM path ---------------------------------------------------------------------


def test_good_llm_narrative_is_used(synth: SyntheticData, toolbox: Toolbox) -> None:
    llm = FakeLLM({"summary": "File transfers deviated sharply from this user's baseline and need review.",
                   "possible_benign_explanations": ["A quarter-end reporting deadline.", "A file migration."]})
    case = CaseAgent(toolbox, llm=llm).build_case(user_with(synth, "mass_download")).to_dict()
    assert case["generated_by"] == "fake-llm"
    assert case["summary"].startswith("File transfers deviated")
    assert validate_case(case) == []
    facts = llm.calls[0]["facts"]
    assert facts["observations"] and "display_name" not in json.dumps(facts)


def test_accusatory_llm_draft_falls_back_to_the_template(synth: SyntheticData, toolbox: Toolbox) -> None:
    llm = FakeLLM({"summary": "This malicious user is stealing data.", "possible_benign_explanations": []})
    case = CaseAgent(toolbox, llm=llm).build_case(user_with(synth, "mass_download")).to_dict()
    assert case["generated_by"].startswith("template (fallback")
    assert "privacy lint" in case["generated_by"]
    assert "malicious" not in case["summary"].lower()
    assert case["privacy_lint"]["passed"] is True


def test_llm_draft_with_invented_numbers_falls_back(synth: SyntheticData, toolbox: Toolbox) -> None:
    llm = FakeLLM({"summary": "The user downloaded 98765 files.", "possible_benign_explanations": ["A deadline."]})
    case = CaseAgent(toolbox, llm=llm).build_case(user_with(synth, "mass_download")).to_dict()
    assert "unsupported number" in case["generated_by"]
    assert "98765" not in case["summary"]


def test_llm_failure_falls_back(synth: SyntheticData, toolbox: Toolbox) -> None:
    case = CaseAgent(toolbox, llm=FakeLLM(TimeoutError("ollama timed out"))).build_case(
        user_with(synth, "after_hours")
    ).to_dict()
    assert case["generated_by"].startswith("template (fallback")
    assert validate_case(case) == []


# --- schema checks ----------------------------------------------------------------


def test_validator_catches_broken_cases(template_case: dict[str, Any]) -> None:
    broken = dict(template_case, human_review_required=False, status="approved")
    broken["recommended_actions"] = [dict(a, policy_ref="") for a in template_case["recommended_actions"]]
    errors = validate_case(broken)
    assert any("human_review_required" in e for e in errors)
    assert any("status" in e for e in errors)
    assert any("policy_ref" in e for e in errors)


# --- real model (opt-in: UEBA_LLM_TESTS=1, needs Ollama + gemma4) -------------------


@pytest.mark.skipif(os.environ.get("UEBA_LLM_TESTS") != "1", reason="set UEBA_LLM_TESTS=1 to run against Ollama")
def test_gemma4_writes_a_valid_case(synth: SyntheticData, toolbox: Toolbox) -> None:
    llm = OllamaLLM()
    assert llm.available()
    case = CaseAgent(toolbox, llm=llm).build_case(user_with(synth, "mass_download")).to_dict()
    assert validate_case(case) == []
    assert case["privacy_lint"]["passed"] is True
