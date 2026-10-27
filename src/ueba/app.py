"""Streamlit dashboard: ranking, investigation, Case Summary, human review, evaluation (FR-7).

Run: .venv/bin/python -m streamlit run src/ueba/app.py

Configuration (environment variables, all optional):
  UEBA_DATA_ROOT  processed datasets folder (default data/processed)
  UEBA_LLM        auto | none | <ollama model>   (default auto = gemma4 when available)
  UEBA_RAG        auto | hybrid | ollama | tfidf (default auto)
  UEBA_REVIEWS    review store JSON (default data/reviews.json)
  UEBA_CASES_DIR  where Case Summaries are saved (default data/cases)
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, cast

import altair as alt
import pandas as pd
import streamlit as st

from ueba.agent import CaseAgent, NarrativeLLM, OllamaLLM, Toolbox, validate_case
from ueba.controls import load_control_mapping
from ueba.dashboard import Dataset, action_status, available_datasets, daily_activity, filter_ranking, headline_metrics, load_dataset
from ueba.detection import RISK_LEVELS, DetectionResult, run_detection
from ueba.detectors import DETECTORS
from ueba.evaluation import detection_metrics
from ueba.rag import Retriever, build_index
from ueba.review import DECISIONS, ReviewStore

DATA_ROOT = Path(os.environ.get("UEBA_DATA_ROOT", "data/processed"))
LLM_SETTING = os.environ.get("UEBA_LLM", "auto")
RAG_SETTING = os.environ.get("UEBA_RAG", "auto")
REVIEWS_PATH = Path(os.environ.get("UEBA_REVIEWS", "data/reviews.json"))
CASES_DIR = Path(os.environ.get("UEBA_CASES_DIR", "data/cases"))

LEVEL_ICON = {"High": "🔴", "Medium": "🟠", "Low": "🟢"}
BANNER = (
    "**Decision support only.** Scores describe how file activity deviates from each user's own baseline; "
    "they are not a conclusion about intent. Users are pseudonymous. Any action that affects a person "
    "requires a Reviewer's approval."
)


# --- cached resources ---------------------------------------------------------------


@st.cache_resource(show_spinner="Loading dataset…")
def get_dataset(path: str) -> Dataset:
    return load_dataset(Path(path))


@st.cache_resource(show_spinner="Running baselines, rules and detector…")
def get_detection(path: str, detector: str) -> DetectionResult:
    ds = get_dataset(path)
    return run_detection(ds.events, ds.users, ds.baseline_end, detector)


@st.cache_resource(show_spinner="Indexing policy corpus…")
def get_retriever(backend: str) -> Retriever:
    return build_index(backend=backend)


@st.cache_resource
def get_llm(setting: str) -> NarrativeLLM | None:
    if setting == "none":
        return None
    llm = OllamaLLM("gemma4" if setting == "auto" else setting)
    return llm if llm.available() else None


def review_store() -> ReviewStore:
    return ReviewStore(REVIEWS_PATH)  # re-read every run so decisions from other sessions show up


# --- page -----------------------------------------------------------------------------


st.set_page_config(page_title="Insider Threat UEBA", page_icon="🛡️", layout="wide")
st.title("🛡️ Insider Threat File Access UEBA")
st.warning(BANNER)

datasets = available_datasets(DATA_ROOT)
if not datasets:
    st.error(
        f"No processed datasets in `{DATA_ROOT}`. Generate one with "
        "`.venv/bin/python -m ueba.generator --out data/processed/synthetic`."
    )
    st.stop()

with st.sidebar:
    st.header("Settings")
    names = list(datasets)
    # The synthetic testbed is the demo dataset (FR-2 Must); open on it when present.
    ds_name = st.selectbox("Dataset", names, index=names.index("synthetic") if "synthetic" in names else 0, key="dataset")
    detector = st.selectbox("ML detector", list(DETECTORS), index=list(DETECTORS).index("isolation_forest"), key="detector")
    ds_path = str(datasets[ds_name])
    dataset = get_dataset(ds_path)
    result = get_detection(ds_path, detector)
    llm = get_llm(LLM_SETTING)
    retriever = get_retriever(RAG_SETTING)

    flagged = result.ranking[result.ranking["n_findings"] > 0]
    options = flagged["user_id"].tolist() or result.ranking["user_id"].tolist()
    user_id = st.selectbox(
        "User to investigate",
        options,
        key="user",
        format_func=lambda u: f"{u} · {LEVEL_ICON[str(result.ranking.set_index('user_id').at[u, 'risk_level'])]} "
        f"{float(cast(float, result.ranking.set_index('user_id').at[u, 'risk_score'])):.0f}",
    )
    if user_id is None:
        st.info("No users in this dataset.")
        st.stop()
    st.divider()
    reviewer = st.text_input("Reviewer name", key="reviewer", help="Recorded with every Review Decision")
    st.caption(f"Baseline Window ends {dataset.baseline_end.date()} · {len(dataset.events):,} events")
    st.caption(f"RAG: {retriever.backend}")
    st.caption(f"LLM: {llm.name if llm else 'template only (no LLM)'}")

tabs = st.tabs(["📊 Risk ranking", "🔎 Investigation", "📝 Case & review", "📈 Evaluation", "📚 Policy search"])


# --- tab 1: ranking ---------------------------------------------------------------------

with tabs[0]:
    m = headline_metrics(result)
    cols = st.columns(5)
    cols[0].metric("Users", m["users"])
    cols[1].metric("🔴 High", m["High"])
    cols[2].metric("🟠 Medium", m["Medium"])
    cols[3].metric("🟢 Low", m["Low"])
    cols[4].metric("Findings", m["findings"])

    f1, f2 = st.columns(2)
    levels = f1.multiselect("Risk level", RISK_LEVELS, default=["High", "Medium"], key="filter_levels")
    depts = f2.multiselect("Department", sorted(result.ranking["department"].astype(str).unique()), key="filter_depts")
    view = filter_ranking(result.ranking, levels, depts).copy()
    view.insert(0, "level", view["risk_level"].map(lambda lv: f"{LEVEL_ICON[lv]} {lv}"))
    st.dataframe(
        view[["level", "user_id", "department", "role", "risk_score", "rules", "top_finding"]],
        hide_index=True,
        column_config={
            "risk_score": st.column_config.ProgressColumn("Risk Score", min_value=0, max_value=100, format="%.1f"),
            "top_finding": st.column_config.TextColumn("Top Finding", width="large"),
        },
    )
    na = [r for r, ok in result.applicable_rules.items() if not ok]
    if na:
        st.caption(f"Rules not applicable to this dataset (missing fields): {', '.join(na)}")


# --- tab 2: investigation ----------------------------------------------------------------

with tabs[1]:
    row = result.ranking.set_index("user_id").loc[user_id]
    st.subheader(f"{user_id} · {LEVEL_ICON[row['risk_level']]} {row['risk_level']} ({row['risk_score']:.1f})")
    st.caption(f"{row['department']} · {row['role']} · ML score {row['ml_score']:.3f} · "
               f"baseline from {result.baselines.loc[user_id, 'baseline_source']}")

    daily = daily_activity(result, user_id)
    window = alt.Chart(pd.DataFrame({"start": [dataset.baseline_end], "end": [daily["day"].max()]})).mark_rect(
        opacity=0.08, color="orange"
    ).encode(x="start:T", x2="end:T")
    for col, base_col, label in [("transfers", "transfers_baseline", "File transfers per day"),
                                 ("after_hours_events", "after_hours_baseline", "After-hours activity per day")]:
        line = alt.Chart(daily).mark_line(point=True).encode(x=alt.X("day:T", title=None), y=alt.Y(f"{col}:Q", title=label))
        rule = alt.Chart(daily).mark_rule(strokeDash=[4, 4], color="gray").encode(y=f"mean({base_col}):Q")
        st.altair_chart((window + line + rule).properties(height=200))
    st.caption("Shaded: Detection Window. Dashed: the user's baseline mean.")

    findings = result.findings_for(user_id)
    st.markdown(f"#### Findings ({len(findings)})")
    if not findings:
        st.info("No Findings for this user in the Detection Window.")
    mapping = load_control_mapping()
    for f in findings:
        with st.expander(f"{f.rule} · {f.severity}", expanded=f.severity == "high"):
            st.markdown(f.description)
            st.dataframe(pd.DataFrame([{k: v for k, v in f.to_dict().items() if k not in ("user_id", "description", "rule")}]),
                         hide_index=True)
            entry = mapping.lookup(f.rule)
            st.markdown("**ATT&CK (activity consistent with):** " + "; ".join(f"`{t['id']}` {t['name']}" for t in entry["attack"]))
            st.markdown("**NIST SP 800-53:** " + "; ".join(f"`{c['id']}` {c['name']}" for c in entry["nist"]))
    if findings and not mapping.verified:
        st.caption("⚠️ Control Mapping is a draft awaiting verification (FR-11).")


# --- tab 3: case & review --------------------------------------------------------------

def show_case(case: dict[str, Any]) -> None:
    store = review_store()
    status = store.status(case["case_id"])
    st.subheader(case["case_id"])
    c1, c2, c3 = st.columns(3)
    c1.markdown(f"**Review status:** `{status}`")
    c2.markdown(f"**Generated by:** `{case['generated_by']}`")
    c3.markdown(f"**Privacy Lint:** {'✅ pass' if case['privacy_lint']['passed'] else '❌ fail'}")
    st.info(case["summary"])

    st.markdown("#### Observations")
    st.dataframe(pd.DataFrame([{"rule": o["rule"], "severity": o["severity"], "evidence": o["description"]}
                               for o in case["observations"]]), hide_index=True)
    st.markdown("#### Possible legitimate explanations")
    st.markdown("\n".join(f"- {b}" for b in case["possible_benign_explanations"]))

    st.markdown("#### Recommended actions")
    actions = pd.DataFrame(action_status(case, store.latest(case["case_id"])))
    actions["status"] = actions["status"].map(lambda s: ("✅ " if s == "authorised" else "🔒 ") + s)
    st.dataframe(actions[["status", "action", "requires_approval", "policy_ref"]], hide_index=True)

    with st.expander(f"Policy citations ({len(case['policy_citations'])})"):
        for c in case["policy_citations"]:
            st.markdown(f"**`{c['citation']}`** · {c['title']} · {c['section']}\n\n> {c['excerpt']}")
    with st.expander("Control mapping"):
        st.dataframe(pd.DataFrame([{"finding": m["finding_type"],
                                    "ATT&CK": ", ".join(t["id"] for t in m["attack"]),
                                    "NIST": ", ".join(n["id"] for n in m["nist"]),
                                    "verified": m["verified"]} for m in case["control_mapping"]]),
                     hide_index=True)
    with st.expander("Agent tool trace"):
        st.dataframe(pd.DataFrame(case["tool_trace"]).astype(str), hide_index=True)
    with st.expander("Raw JSON"):
        st.json(case, expanded=False)
    st.caption(case["privacy_note"])

    st.markdown("#### Review decision")
    decision = st.radio("Decision", DECISIONS, horizontal=True, key="decision", index=None)
    notes = st.text_area("Notes", key="review_notes")
    if st.button("Submit review", key="submit_review", type="primary"):
        if not (reviewer or "").strip():
            st.error("Enter your name as Reviewer in the sidebar before submitting.")
        elif decision is None:
            st.error("Choose a decision.")
        else:
            store.record(case["case_id"], decision, reviewer, notes)
            st.success(f"Recorded: {decision} by {reviewer}.")
            st.rerun()
    history = store.history(case["case_id"])
    if history:
        st.dataframe(pd.DataFrame([vars(h) for h in history]), hide_index=True)


with tabs[2]:
    cases: dict[str, dict[str, Any]] = st.session_state.setdefault("cases", {})
    key = f"{ds_name}:{detector}:{user_id}"
    if st.button(f"Generate case summary for {user_id}", key="generate_case", disabled=not result.findings_for(user_id)):
        with st.spinner("Agent: gathering context, searching policy, drafting narrative…"):
            toolbox = Toolbox(result, dataset.events, dataset.users, retriever, load_control_mapping())
            case = CaseAgent(toolbox, llm).build_case(user_id).to_dict()
        errors = validate_case(case)
        if errors:
            st.error("Case failed validation: " + "; ".join(errors))
        out = CASES_DIR / ds_name
        out.mkdir(parents=True, exist_ok=True)
        (out / f"{case['case_id']}.json").write_text(json.dumps(case, indent=2))
        cases[key] = case
    if key in cases:
        show_case(cases[key])
    else:
        st.caption("Generate a Case Summary to review it here. Users without Findings get no case.")


# --- tab 4: evaluation ----------------------------------------------------------------

with tabs[3]:
    if dataset.labels is None:
        st.info("This dataset has no Ground-truth Labels.")
    else:
        st.caption("Evaluation mode: compares the ranking with Ground-truth Labels, which analysts never see in the workflow.")
        met = detection_metrics(result.ranking, dataset.labels)
        cols = st.columns(5)
        cols[0].metric("Precision", f"{met['precision']:.2f}")
        cols[1].metric("Recall", f"{met['recall']:.2f}")
        cols[2].metric("F1", f"{met['f1']:.2f}")
        cols[3].metric(f"Precision@{met['k']}", f"{met['precision_at_k']:.2f}")
        cols[4].metric("Normal-user FP rate", f"{met['normal_fp_rate']:.1%}")
        st.markdown("#### By scenario")
        st.dataframe(pd.DataFrame(met["per_scenario"]).T.rename_axis("scenario").reset_index(),
                     hide_index=True)
        if met["fp_rate_by_department"]:
            st.markdown("#### False-positive rate by department (fairness check)")
            fp = pd.DataFrame({"department": list(met["fp_rate_by_department"]),
                               "fp_rate": list(met["fp_rate_by_department"].values())})
            if fp["fp_rate"].max() == 0:
                st.success("No non-anomalous user was flagged in any department.")
            else:
                # Fixed 0..max domain (at least 10%) so small rates stay readable and the axis never collapses.
                domain = [0, max(0.1, float(fp["fp_rate"].max()))]
                x = alt.X("fp_rate:Q", title="false-positive rate", scale=alt.Scale(domain=domain),
                          axis=alt.Axis(format=".0%"))
                st.altair_chart(alt.Chart(fp).mark_bar().encode(x=x, y=alt.Y("department:N", sort="-x"))
                                .properties(height=220))
        st.caption("Flagged = Medium or High. See docs/experiment-log.md for caveats about these numbers.")


# --- tab 5: policy search -------------------------------------------------------------

with tabs[4]:
    query = st.text_input("Ask the policy corpus", key="policy_query", placeholder="who approves restricting access?")
    if query:
        for hit in retriever.search(query, k=5):
            p = hit.passage
            with st.expander(f"{p.citation} · {p.title} — {p.section} ({hit.score:.3f})"):
                st.markdown(p.text)
