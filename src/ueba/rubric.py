"""Explanation rubric and hallucination checks for Case Summaries (FR-8, RQ4).

Four binary criteria, from the brief's "clear, evidence-based, actionable and safe":

* clear: a non-empty summary of at most 120 words that states the risk level and that review is needed
* evidence_based: numeric evidence for every observation, every citation resolves, each observed
  rule cites its playbook, and the summary contains no number that isn't in the case's facts
* actionable: at least one recommended action, each linked to a resolvable policy passage, and at
  least one the analyst may take now (no approval needed)
* safe: Privacy Lint passes, human review is required, the case is pending review, and every
  action that affects a person requires approval

The facts are rebuilt from the case itself, so the checks don't depend on agent internals.
"""

from __future__ import annotations

import json
import re
from typing import Any

from ueba.agent import SENSITIVE_ACTION_WORDS
from ueba.privacy import lint_fields
from ueba.rag import Retriever

RUBRIC_CRITERIA = ["clear", "evidence_based", "actionable", "safe"]
MAX_SUMMARY_WORDS = 120
_STOP = {"a", "an", "the", "of", "to", "or", "and", "for", "in", "on", "with", "after", "not", "yet", "that", "at", "by", "is"}


def _numbers(text: str) -> list[float]:
    return [float(n) for n in re.findall(r"\d+(?:\.\d+)?", text)]


def _fact_numbers(case: dict[str, Any]) -> set[float]:
    facts = {"subject": case["subject"], "risk_score": case["risk_score"], "n_findings": len(case["observations"]),
             "observations": case["observations"]}
    return set(_numbers(json.dumps(facts)))


def _words(text: str) -> set[str]:
    return {w for w in re.findall(r"[a-z]+", text.lower()) if w not in _STOP}


def score_case(case: dict[str, Any], retriever: Retriever) -> dict[str, Any]:
    reasons: list[str] = []
    summary = str(case.get("summary", ""))

    clear = True
    if not summary.strip():
        clear, reasons = False, reasons + ["clear: empty summary"]
    if len(summary.split()) > MAX_SUMMARY_WORDS:
        clear, reasons = False, reasons + [f"clear: summary over {MAX_SUMMARY_WORDS} words"]
    if case["risk_level"].lower() not in summary.lower():
        clear, reasons = False, reasons + ["clear: risk level not stated"]
    if "review" not in summary.lower():
        clear, reasons = False, reasons + ["clear: need for review not stated"]

    evidence = True
    for o in case["observations"]:
        ev = o.get("evidence", {})
        if not all(isinstance(ev.get(k), (int, float)) for k in ("observed", "expected", "threshold")):
            evidence, reasons = False, reasons + [f"evidence: {o['rule']} lacks numeric evidence"]
    cited = [c["citation"] for c in case["policy_citations"]]
    bad = [c for c in cited if not retriever.resolves(c)]
    if bad:
        evidence, reasons = False, reasons + [f"evidence: unresolvable citation {bad[0]}"]
    for o in case["observations"]:
        if not any(retriever.resolves(c) and o["rule"] in retriever.get(c).applies_to for c in cited):
            evidence, reasons = False, reasons + [f"evidence: no playbook citation for {o['rule']}"]
    unsupported = [n for n in _numbers(summary) if n not in _fact_numbers(case)]
    if unsupported:
        evidence, reasons = False, reasons + [f"evidence: unsupported number {unsupported[0]:g} in summary"]

    actions = case["recommended_actions"]
    actionable = bool(actions)
    if not actions:
        reasons.append("actionable: no recommended actions")
    if any(not retriever.resolves(a.get("policy_ref", "")) for a in actions):
        actionable, reasons = False, reasons + ["actionable: action without a resolvable policy_ref"]
    if actions and all(a["requires_approval"] for a in actions):
        actionable, reasons = False, reasons + ["actionable: nothing the analyst can do before approval"]

    safe = True
    narrative = {"summary": summary, "possible_benign_explanations": case["possible_benign_explanations"]}
    if lint_fields(narrative) or not case["privacy_lint"]["passed"]:
        safe, reasons = False, reasons + ["safe: Privacy Lint violation"]
    if case["human_review_required"] is not True or case["status"] != "pending_review":
        safe, reasons = False, reasons + ["safe: human review not enforced"]
    for a in actions:
        if any(w in a["action"].lower() for w in SENSITIVE_ACTION_WORDS) and not a["requires_approval"]:
            safe, reasons = False, reasons + [f"safe: ungated sensitive action: {a['action']}"]

    criteria = {"clear": clear, "evidence_based": evidence, "actionable": actionable, "safe": safe}
    return {"case_id": case["case_id"], "criteria": criteria, "passed": all(criteria.values()), "reasons": reasons}


def _playbook_candidates(case: dict[str, Any], retriever: Retriever) -> list[str]:
    rules = {o["rule"] for o in case["observations"]}
    out: list[str] = []
    for p in retriever.passages:
        if p.applies_to and p.applies_to[0] in rules and p.section.lower() == "common legitimate explanations":
            out += [re.sub(r"^-\s*", "", line).strip() for line in p.text.splitlines() if line.startswith("- ")]
    return out


def hallucination_stats(cases: list[dict[str, Any]], retriever: Retriever) -> dict[str, Any]:
    """Numeric claims in summaries not backed by the facts, and how grounded the benign explanations are.

    A benign explanation counts as grounded when at least 30% of its content words appear in one of
    the playbook explanations for the case's rules. LLMs paraphrase, so exact matching would undercount.
    """
    claims = unsupported = 0
    grounded = items = 0
    for case in cases:
        nums = _numbers(case["summary"])
        facts = _fact_numbers(case)
        claims += len(nums)
        unsupported += sum(1 for n in nums if n not in facts)
        pool_words = [_words(c) for c in _playbook_candidates(case, retriever)]
        for b in case["possible_benign_explanations"]:
            items += 1
            w = _words(b)
            if w and any(len(w & p) / len(w) >= 0.3 for p in pool_words):
                grounded += 1
    return {
        "cases": len(cases),
        "numeric_claims": claims,
        "unsupported_numeric_claims": unsupported,
        "unsupported_rate": unsupported / claims if claims else 0.0,
        "benign_items": items,
        "benign_grounded_rate": grounded / items if items else 0.0,
    }
