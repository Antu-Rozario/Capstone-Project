"""Headless smoke tests of the Streamlit dashboard using Streamlit's AppTest."""

import json
from pathlib import Path

import pytest
from streamlit.testing.v1 import AppTest

from ueba.generator import GeneratorConfig, generate, save_processed

APP = str(Path(__file__).resolve().parents[1] / "src" / "ueba" / "app.py")


@pytest.fixture()
def app(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> AppTest:
    save_processed(generate(GeneratorConfig(n_users=60, seed=11)), tmp_path / "processed" / "synthetic")
    monkeypatch.setenv("UEBA_DATA_ROOT", str(tmp_path / "processed"))
    monkeypatch.setenv("UEBA_LLM", "none")
    monkeypatch.setenv("UEBA_RAG", "tfidf")
    monkeypatch.setenv("UEBA_REVIEWS", str(tmp_path / "reviews.json"))
    monkeypatch.setenv("UEBA_CASES_DIR", str(tmp_path / "cases"))
    at = AppTest.from_file(APP, default_timeout=120)
    at.run()
    return at


def all_text(at: AppTest) -> str:
    parts = [m.value for m in at.markdown] + [c.value for c in at.caption] + [i.value for i in at.info]
    parts += [s.value for s in at.success] + [w.value for w in at.warning] + [e.value for e in at.error]
    return "\n".join(str(p) for p in parts)


def test_dashboard_loads_without_errors(app: AppTest) -> None:
    assert not app.exception
    assert "Insider Threat" in app.title[0].value
    assert any("not a conclusion" in w.value for w in app.warning)  # privacy banner
    assert app.dataframe  # ranking table
    assert app.selectbox(key="user").value is not None


def test_generate_case_then_approve_unlocks_sensitive_actions(app: AppTest, tmp_path: Path) -> None:
    app.button(key="generate_case").click().run()
    assert not app.exception
    text = all_text(app)
    assert "pending_review" in text
    assert "locked: needs approval" in json.dumps([d.value.to_dict() for d in app.dataframe], default=str)

    app.text_input(key="reviewer").input("R. Analyst")
    app.radio(key="decision").set_value("approved")
    app.text_area(key="review_notes").input("Manager confirmed no project.")
    app.button(key="submit_review").click().run()
    assert not app.exception
    assert "approved" in all_text(app)
    reviews = json.loads((tmp_path / "reviews.json").read_text())
    assert list(reviews.values())[0][0]["reviewer"] == "R. Analyst"
    assert list((tmp_path / "cases").rglob("*.json"))


def test_review_without_a_name_is_refused(app: AppTest, tmp_path: Path) -> None:
    app.button(key="generate_case").click().run()
    app.radio(key="decision").set_value("approved")
    app.button(key="submit_review").click().run()
    assert any("name" in e.value.lower() for e in app.error)
    assert not (tmp_path / "reviews.json").exists()
