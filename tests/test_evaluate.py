import json
from pathlib import Path

from ueba.evaluate import main


def test_quick_evaluation_writes_report_json_and_plots(tmp_path: Path) -> None:
    out = tmp_path / "reports"
    main(["--quick", "--llm", "none", "--rag", "tfidf", "--no-cert", "--users", "60", "--out", str(out)])
    report = (out / "evaluation.md").read_text()
    for heading in ["# Evaluation Report", "Detection accuracy", "RQ1", "RQ2", "RQ3", "RQ4", "Demo cases",
                    "Human-in-the-loop", "Error analysis", "Limitations", "Reproduce"]:
        assert heading in report, heading
    data = json.loads((out / "evaluation.json").read_text())
    assert {"settings", "detection", "rq1", "rq2", "rq3", "rq4", "demo", "hitl"} <= set(data)
    assert data["hitl"]["violations"] == 0 and data["hitl"]["cases_checked"] > 0
    assert data["demo"]["passed"] + data["demo"]["failed"] + data["demo"]["skipped"] == 8
    for plot in ["rq1_detectors.png", "rq2_sensitivity.png", "rq3_fairness.png"]:
        assert (out / plot).stat().st_size > 1000, plot
