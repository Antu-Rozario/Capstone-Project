"""Explanation agent: turns a flagged user's Findings into a structured Case Summary (FR-5).

Workflow (planner-executor):
1. Tools gather the facts: `get_user_context`, then for every Finding `search_policy`
   and `lookup_control_mapping`. Each call is recorded in `tool_trace`.
2. Code assembles everything that must be exact: risk score, observations with evidence,
   policy citations, control mapping and recommended actions (with approval flags taken
   from the playbooks, plus a keyword safety net).
3. A local LLM (Ollama, gemma4 by default) writes only the narrative: `summary` and
   `possible_benign_explanations`, using the versioned prompt in `prompts/`.
4. The narrative must pass the Privacy Lint and a hallucination guard (every number in it
   must appear in the facts). Otherwise, or if no LLM is available, a grounded template
   writes it and `generated_by` records why.

Every Case Summary starts as `pending_review` with `human_review_required: true`.

Run: .venv/bin/python -m ueba.agent data/processed/synthetic --top 3
"""

from __future__ import annotations

import argparse
import json
import re
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Protocol

import pandas as pd

from ueba.controls import ControlMapping, load_control_mapping
from ueba.detection import RULES, DetectionResult, Finding, run_detection
from ueba.privacy import lint_fields
from ueba.rag import Retriever, build_index

PROMPT_VERSION = "case_summary_v1"
PROMPT_PATH = Path(__file__).parent / "prompts" / f"{PROMPT_VERSION}.md"

NARRATIVE_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "summary": {"type": "string"},
        "possible_benign_explanations": {"type": "array", "items": {"type": "string"}},
    },
    "required": ["summary", "possible_benign_explanations"],
}

PRIVACY_NOTE = (
    "This summary describes file-access activity that deviates from the user's own baseline. "
    "It is not a conclusion about intent. The subject is identified by pseudonym only; "
    "re-identification and every action marked as requiring approval need a Reviewer's decision "
    "(Privacy and Fairness Standard; Escalation Matrix)."
)

# Safety net: actions that affect a person always need approval, even if a playbook forgot the marker.
SENSITIVE_ACTION_WORDS = ("restrict", "revoke", "suspend", "block", "refer", "reset credentials", "re-identif",
                          "reduce the person's access", "contact the person", "line manager", "remind the person")
APPROVAL_MARKER = "**[approval required]**"


# --- tools ------------------------------------------------------------------------


@dataclass
class Toolbox:
    """The agent's three tools, over one detection run."""

    result: DetectionResult
    events: pd.DataFrame
    users: pd.DataFrame
    retriever: Retriever
    mapping: ControlMapping

    def get_user_context(self, user_id: str) -> dict[str, Any]:
        rank = self.result.ranking.set_index("user_id")
        if user_id not in rank.index:
            raise KeyError(f"unknown user {user_id}")
        row = {str(k): v for k, v in rank.loc[user_id].to_dict().items()}
        findings = self.result.findings_for(user_id)
        sample = pd.DataFrame()
        if findings:
            worst = max(findings, key=lambda f: f.observed / max(f.threshold, 1.0)).worst_day
            ev = self.events[(self.events["user_id"] == user_id) & (self.events["timestamp"].dt.normalize() == worst)]
            cols = ["timestamp", "event_type", "action", "file_category", "file_department", "sensitivity", "device_id"]
            sample = ev[cols].head(10).astype(str)
        return {
            "user_id": user_id,
            "department": str(row["department"]),
            "role": str(row["role"]),
            "risk_score": float(row["risk_score"]),
            "risk_level": str(row["risk_level"]),
            "ml_score": float(row["ml_score"]),
            "baseline_source": str(self.result.baselines["baseline_source"].get(user_id, "user")),
            "findings": [f.to_dict() for f in findings],
            "event_sample": sample.to_dict(orient="records"),
        }

    def search_policy(self, query: str, finding_type: str | None = None, k: int = 3) -> list[dict[str, str]]:
        return [
            {"citation": h.passage.citation, "title": h.passage.title, "section": h.passage.section, "text": h.passage.text}
            for h in self.retriever.search(query, k=k, finding_type=finding_type)
        ]

    def lookup_control_mapping(self, finding_type: str) -> dict[str, Any]:
        return self.mapping.lookup(finding_type)


# --- LLM ----------------------------------------------------------------------------


class NarrativeLLM(Protocol):
    name: str

    def write(self, system: str, facts: dict[str, Any]) -> dict[str, Any]: ...


class OllamaLLM:
    """Local chat model via Ollama /api/chat with JSON-schema structured output."""

    def __init__(self, model: str = "gemma4", url: str = "http://localhost:11434", timeout: float = 180) -> None:
        self.model, self.url, self.timeout = model, url.rstrip("/"), timeout
        self.name = f"ollama:{model}"

    def available(self) -> bool:
        try:
            with urllib.request.urlopen(f"{self.url}/api/tags", timeout=2) as resp:
                names = [m["name"].split(":")[0] for m in json.load(resp)["models"]]
            return self.model.split(":")[0] in names
        except (urllib.error.URLError, OSError, ValueError, KeyError):
            return False

    def write(self, system: str, facts: dict[str, Any]) -> dict[str, Any]:
        body = {
            "model": self.model,
            "messages": [{"role": "system", "content": system}, {"role": "user", "content": json.dumps(facts)}],
            "format": NARRATIVE_SCHEMA,
            "stream": False,
            "think": False,
            "options": {"temperature": 0.2, "seed": 7},
        }
        req = urllib.request.Request(f"{self.url}/api/chat", data=json.dumps(body).encode(),
                                     headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:
            content = json.load(resp)["message"]["content"]
        reply: dict[str, Any] = json.loads(content)
        return reply


# --- case summary -------------------------------------------------------------------


@dataclass(frozen=True)
class CaseSummary:
    case_id: str
    subject: str
    department: str
    role: str
    risk_score: float
    risk_level: str
    summary: str
    observations: list[dict[str, Any]]
    possible_benign_explanations: list[str]
    policy_citations: list[dict[str, str]]
    control_mapping: list[dict[str, Any]]
    recommended_actions: list[dict[str, Any]]
    privacy_note: str
    privacy_lint: dict[str, Any]
    generated_by: str
    prompt_version: str
    tool_trace: list[dict[str, Any]]
    human_review_required: bool = True
    status: str = "pending_review"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _numbers(text: str) -> set[float]:
    return {float(n) for n in re.findall(r"\d+(?:\.\d+)?", text)}


def _bullets(text: str) -> list[str]:
    return [re.sub(r"^(\d+\.|-)\s*", "", line).strip() for line in text.splitlines() if re.match(r"^(\d+\.|-)\s", line)]


def _playbook_section(retriever: Retriever, rule: str, section: str) -> tuple[str, str] | None:
    for p in retriever.passages:
        if p.applies_to == (rule,) and p.section.lower() == section.lower():
            return p.citation, p.text
    return None


@dataclass
class CaseAgent:
    toolbox: Toolbox
    llm: NarrativeLLM | None = None
    trace: list[dict[str, Any]] = field(default_factory=list)

    def _call(self, tool: str, args: dict[str, Any], result: Any, summary: str) -> Any:
        self.trace.append({"tool": tool, "args": args, "result": summary})
        return result

    def build_case(self, user_id: str) -> CaseSummary:
        self.trace = []
        tb = self.toolbox
        ctx = self._call("get_user_context", {"user_id": user_id}, tb.get_user_context(user_id), "")
        self.trace[-1]["result"] = f"{len(ctx['findings'])} findings, risk {ctx['risk_level']} {ctx['risk_score']}"
        if not ctx["findings"]:
            raise ValueError(f"{user_id} has no Findings in the Detection Window: nothing to summarise")

        findings = [f for f in tb.result.findings_for(user_id)]
        observations = [self._observation(f) for f in findings]
        citations: dict[str, dict[str, str]] = {}
        mapping: list[dict[str, Any]] = []
        actions: dict[str, dict[str, Any]] = {}
        benign: list[str] = []

        for f in findings:
            query = f"{f.rule} {RULES[f.rule].unit}"
            hits = tb.search_policy(query, finding_type=f.rule, k=2)
            self._call("search_policy", {"query": query, "finding_type": f.rule}, hits, ", ".join(h["citation"] for h in hits))
            for h in hits:
                citations.setdefault(h["citation"], self._citation(h))
            m = tb.lookup_control_mapping(f.rule)
            self._call("lookup_control_mapping", {"finding_type": f.rule}, m, ", ".join(t["id"] for t in m["attack"]))
            mapping.append(m)

            acts = _playbook_section(tb.retriever, f.rule, "Recommended actions")
            if acts:
                citations.setdefault(acts[0], self._citation_of(acts[0]))
                for line in _bullets(acts[1]):
                    text = line.replace(APPROVAL_MARKER, "").strip()
                    needs = APPROVAL_MARKER in line or any(w in text.lower() for w in SENSITIVE_ACTION_WORDS)
                    actions.setdefault(text, {"action": text, "requires_approval": needs, "policy_ref": acts[0],
                                              "finding_type": f.rule})
            ben = _playbook_section(tb.retriever, f.rule, "Common legitimate explanations")
            if ben:
                citations.setdefault(ben[0], self._citation_of(ben[0]))
                benign += [b for b in _bullets(ben[1]) if b not in benign]

        level = ctx["risk_level"].lower()
        escalation = f"escalation-matrix#{level}-risk"
        if tb.retriever.resolves(escalation):
            citations.setdefault(escalation, self._citation_of(escalation))
        if ctx["risk_level"] == "High" and tb.retriever.resolves("evidence-handling-standard#preserving-logs"):
            ref = "evidence-handling-standard#preserving-logs"
            citations.setdefault(ref, self._citation_of(ref))
            actions.setdefault("preserve", {"action": "Preserve the relevant metadata logs for the affected days.",
                                            "requires_approval": False, "policy_ref": ref, "finding_type": "ALL"})

        facts = {
            "subject": user_id,
            "department": ctx["department"],
            "role": ctx["role"],
            "risk_score": ctx["risk_score"],
            "risk_level": ctx["risk_level"],
            "n_findings": len(observations),
            "observations": [{"rule": o["rule"], "severity": o["severity"], "description": o["description"]} for o in observations],
            "candidate_benign_explanations": benign[:8],
        }
        summary, benign_out, generated_by = self._narrative(facts, benign)
        real_names: list[str] = (
            self.toolbox.users["display_name"].astype(str).tolist() if "display_name" in self.toolbox.users else []
        )
        violations = lint_fields(
            {"summary": summary, "possible_benign_explanations": benign_out, "privacy_note": PRIVACY_NOTE,
             "observations": [o["description"] for o in observations]},
            real_names=real_names,
        )
        worst_day = min(f.first_day for f in findings).date().isoformat()
        return CaseSummary(
            case_id=f"CASE-{user_id}-{worst_day}",
            subject=user_id,
            department=ctx["department"],
            role=ctx["role"],
            risk_score=ctx["risk_score"],
            risk_level=ctx["risk_level"],
            summary=summary,
            observations=observations,
            possible_benign_explanations=benign_out,
            policy_citations=list(citations.values()),
            control_mapping=mapping,
            recommended_actions=list(actions.values()),
            privacy_note=PRIVACY_NOTE,
            privacy_lint={"passed": not violations, "violations": [asdict(v) for v in violations]},
            generated_by=generated_by,
            prompt_version=PROMPT_VERSION,
            tool_trace=self.trace,
        )

    # --- helpers --------------------------------------------------------------------

    @staticmethod
    def _observation(f: Finding) -> dict[str, Any]:
        d = f.to_dict()
        return {
            "rule": f.rule,
            "severity": f.severity,
            "description": f.description,
            "evidence": {k: d[k] for k in ("observed", "expected", "threshold", "first_day", "last_day", "worst_day",
                                           "n_days", "baseline_source")},
        }

    @staticmethod
    def _citation(hit: dict[str, str]) -> dict[str, str]:
        return {"citation": hit["citation"], "title": hit["title"], "section": hit["section"], "excerpt": hit["text"][:240]}

    def _citation_of(self, citation: str) -> dict[str, str]:
        p = self.toolbox.retriever.get(citation)
        return {"citation": p.citation, "title": p.title, "section": p.section, "excerpt": p.text[:240]}

    def _template(self, facts: dict[str, Any], benign: list[str]) -> tuple[str, list[str]]:
        rules = ", ".join(o["rule"] for o in facts["observations"])
        first = facts["observations"][0]
        summary = (
            f"{facts['subject']} ({facts['role']}, {facts['department']}) has a {facts['risk_level']} Risk Score of "
            f"{facts['risk_score']:g} based on {len(facts['observations'])} Finding(s): {rules}. "
            f"Most notable: {first['description']} "
            "This activity deviates from the user's baseline and requires human review before any action."
        )
        return summary, benign[:4]

    def _narrative(self, facts: dict[str, Any], benign: list[str]) -> tuple[str, list[str], str]:
        if self.llm is None:
            s, b = self._template(facts, benign)
            return s, b, "template"
        reason = ""
        try:
            reply = self.llm.write(PROMPT_PATH.read_text(), facts)
            summary = str(reply.get("summary", "")).strip()
            items = [str(x).strip() for x in reply.get("possible_benign_explanations", []) if str(x).strip()][:4]
            unsupported = _numbers(summary) - _numbers(json.dumps(facts))
            violations = lint_fields({"summary": summary, "possible_benign_explanations": items})
            # Most serious reason first: a privacy violation outranks an incomplete draft.
            if violations:
                reason = f"privacy lint: {violations[0].term}"
            elif unsupported:
                reason = f"unsupported number {sorted(unsupported)[0]:g}"
            elif not summary or not items:
                reason = "empty narrative"
            else:
                return summary, items, self.llm.name
        except (OSError, ValueError, KeyError, TimeoutError, urllib.error.URLError) as exc:
            reason = f"LLM error: {type(exc).__name__}"
        s, b = self._template(facts, benign)
        return s, b, f"template (fallback from {self.llm.name}: {reason})"


# --- validation ---------------------------------------------------------------------


def validate_case(case: dict[str, Any]) -> list[str]:
    """Structural and safety checks for a Case Summary dict. Empty list = valid."""
    errors: list[str] = []
    required = [f.name for f in CaseSummary.__dataclass_fields__.values()]
    errors += [f"missing field: {k}" for k in required if k not in case]
    if errors:
        return errors
    if case["human_review_required"] is not True:
        errors.append("human_review_required must be true")
    if case["status"] != "pending_review":
        errors.append("status must start as pending_review")
    if not 0 <= float(case["risk_score"]) <= 100:
        errors.append("risk_score must be within 0-100")
    if not str(case["summary"]).strip():
        errors.append("summary is empty")
    if not case["observations"]:
        errors.append("observations is empty")
    for i, o in enumerate(case["observations"]):
        ev = o.get("evidence", {})
        if not all(isinstance(ev.get(k), (int, float)) for k in ("observed", "expected", "threshold")):
            errors.append(f"observations[{i}] lacks numeric evidence")
    if not case["policy_citations"]:
        errors.append("policy_citations is empty")
    for i, a in enumerate(case["recommended_actions"]):
        if not isinstance(a.get("requires_approval"), bool):
            errors.append(f"recommended_actions[{i}].requires_approval must be a boolean")
        if not a.get("policy_ref"):
            errors.append(f"recommended_actions[{i}].policy_ref is empty")
    if not case["recommended_actions"]:
        errors.append("recommended_actions is empty")
    return errors


# --- CLI ------------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> None:
    from ueba.detection import _default_baseline_end

    parser = argparse.ArgumentParser(description="Generate Case Summaries for flagged users.")
    parser.add_argument("data_dir", type=Path)
    parser.add_argument("--user", action="append", help="user ID (repeatable); default: --top")
    parser.add_argument("--top", type=int, default=3, help="summarise the N highest-risk users")
    parser.add_argument("--baseline-end")
    parser.add_argument("--llm", default="auto", help="auto | none | an Ollama model name (default gemma4)")
    parser.add_argument("--rag", default="auto", choices=["auto", "hybrid", "ollama", "tfidf"])
    parser.add_argument("--out", type=Path)
    args = parser.parse_args(argv)

    data_dir: Path = args.data_dir
    baseline_end = pd.Timestamp(args.baseline_end) if args.baseline_end else _default_baseline_end(data_dir)
    events = pd.read_parquet(data_dir / "events.parquet")
    users = pd.read_parquet(data_dir / "users.parquet")
    result = run_detection(events, users, baseline_end)
    toolbox = Toolbox(result, events, users, build_index(backend=args.rag), load_control_mapping())

    llm: NarrativeLLM | None = None
    if args.llm != "none":
        candidate = OllamaLLM("gemma4" if args.llm == "auto" else args.llm)
        if candidate.available():
            llm = candidate
        elif args.llm != "auto":
            raise SystemExit(f"Ollama model {args.llm!r} not available")

    agent = CaseAgent(toolbox, llm)
    flagged = result.ranking[result.ranking["n_findings"] > 0]
    targets = args.user or flagged["user_id"].head(args.top).tolist()
    out = args.out or Path("data/cases") / data_dir.name
    out.mkdir(parents=True, exist_ok=True)
    print(f"RAG: {toolbox.retriever.backend} · LLM: {llm.name if llm else 'template only'}\n")
    for uid in targets:
        case = agent.build_case(uid).to_dict()
        errors = validate_case(case)
        (out / f"{case['case_id']}.json").write_text(json.dumps(case, indent=2))
        print(f"{case['case_id']}  {case['risk_level']} {case['risk_score']}  generated_by={case['generated_by']}")
        print(f"  {case['summary']}")
        print(f"  lint={'pass' if case['privacy_lint']['passed'] else 'FAIL'}  schema={'ok' if not errors else errors}\n")
    print(f"written to {out}")


if __name__ == "__main__":
    main()
