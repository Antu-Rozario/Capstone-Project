import json
from pathlib import Path

import pytest
from streamlit.testing.v1 import AppTest

from ueba.rating import CRITERIA, save_rating_set

APP = str(Path(__file__).resolve().parents[1] / "src" / "ueba" / "rating_app.py")

ITEMS = [
    {"item_id": f"R00000{i}", "subject": f"U000{i}", "risk_level": "High", "risk_score": 90.0,
     "evidence": [{"rule": "MASS_DOWNLOAD", "description": "300 file transfers in one day."}],
     "summary": f"Summary number {i}.", "possible_benign_explanations": ["A deadline."]}
    for i in range(1, 4)
]
KEY = {i["item_id"]: {"writer": "w", "case_id": "c", "generated_by": "w", "dataset": "d"} for i in ITEMS}


@pytest.fixture()
def app(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> AppTest:
    save_rating_set(ITEMS, KEY, tmp_path)
    monkeypatch.setenv("UEBA_RATING_DIR", str(tmp_path))
    at = AppTest.from_file(APP, default_timeout=60)
    at.run()
    return at


def test_rating_page_asks_for_a_name_first(app: AppTest) -> None:
    assert not app.exception
    assert any("name" in i.value.lower() for i in app.info)
    assert not app.button  # nothing to submit before a name is given


def test_rating_an_item_saves_it_and_moves_on(app: AppTest, tmp_path: Path) -> None:
    app.text_input(key="rater").input("Rater A").run()
    assert "Summary number" in "\n".join(m.value for m in [*app.markdown, *app.info])
    for c in CRITERIA:
        app.slider(key=f"score_{c}").set_value(4)
    app.checkbox(key="unsupported").check()
    app.text_area(key="comment").input("fine")
    app.button(key="save_rating").click().run()
    assert not app.exception
    saved = json.loads((tmp_path / "ratings.json").read_text())
    assert len(saved) == 1 and saved[0]["rater"] == "Rater A" and saved[0]["unsupported_claim"] is True
    assert app.subheader[0].value == "Item R000002"  # moved on to the next unrated item


def test_writer_identity_is_never_shown(app: AppTest) -> None:
    app.text_input(key="rater").input("Rater B").run()
    page = "\n".join(str(e.value) for e in [*app.markdown, *app.caption, *app.info])
    assert "generated_by" not in page and "writer" not in page.lower()
