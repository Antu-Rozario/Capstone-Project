"""Blind rating page for Case Summary narratives (RQ4).

Run: .venv/bin/python -m streamlit run src/ueba/rating_app.py
Env: UEBA_RATING_DIR (default data/rating), created with `python -m ueba.rating build`.
"""

from __future__ import annotations

import os
from pathlib import Path

import streamlit as st

from ueba.rating import CRITERIA, RatingStore, load_rating_set

FOLDER = Path(os.environ.get("UEBA_RATING_DIR", "data/rating"))

st.set_page_config(page_title="Case Summary Rating", page_icon="📝", layout="centered")
st.title("📝 Case Summary Rating")
st.caption(
    "Each item shows the evidence for one flagged user and an automatically written summary. Rate the summary only. "
    "You aren't told how it was written. Scores: 1 = poor, 5 = excellent."
)

if not (FOLDER / "items.json").exists():
    st.error(f"No rating set in `{FOLDER}`. Create it with `.venv/bin/python -m ueba.rating build`.")
    st.stop()

items, _key = load_rating_set(FOLDER)
store = RatingStore(FOLDER / "ratings.json")

rater = st.text_input("Your name", key="rater")
if not rater.strip():
    st.info("Enter your name to start. Your progress is saved, so you can stop and continue later.")
    st.stop()

done = store.done_by(rater)
remaining = [i for i in items if i["item_id"] not in done]
st.progress(len(done) / len(items), text=f"{len(done)} of {len(items)} rated")
if not remaining:
    st.success("All items rated. Thank you!")
    st.stop()

item = remaining[0]
st.subheader(f"Item {item['item_id']}")
st.markdown(f"**User:** {item['subject']} · **Risk:** {item['risk_level']} ({item['risk_score']:.1f})")
st.markdown("**Evidence (from the detection system):**")
st.markdown("\n".join(f"- `{e['rule']}`: {e['description']}" for e in item["evidence"]))
st.markdown("**Summary to rate:**")
st.info(item["summary"])
st.markdown("**Possible legitimate explanations offered:**")
st.markdown("\n".join(f"- {b}" for b in item["possible_benign_explanations"]) or "_none_")

st.divider()
scores = {}
for criterion, help_text in CRITERIA.items():
    scores[criterion] = st.slider(criterion.capitalize(), 1, 5, 3, key=f"score_{criterion}", help=help_text)
    st.caption(help_text)
unsupported = st.checkbox("The summary contains a claim the evidence does not support", key="unsupported")
comment = st.text_area("Comment (optional)", key="comment")

if st.button("Save and next", key="save_rating", type="primary"):
    store.record(rater, item["item_id"], {k: int(v) for k, v in scores.items()}, unsupported, comment)
    for k in [f"score_{c}" for c in CRITERIA] + ["unsupported", "comment"]:
        st.session_state.pop(k, None)
    st.rerun()
