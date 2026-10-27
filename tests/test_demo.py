from pathlib import Path

import pytest

from ueba.dashboard import Dataset
from ueba.demo import DEMO_CASES, TrapLLM, run_demo_cases
from ueba.generator import GeneratorConfig, generate
from ueba.rag import build_index

POLICIES = Path(__file__).resolve().parents[1] / "policies"


@pytest.fixture(scope="module")
def synthetic() -> Dataset:
    s = generate(GeneratorConfig(n_users=60, seed=11))
    return Dataset("synthetic", Path("."), s.events, s.users, s.labels, s.baseline_end)


def test_there_are_eight_prepared_cases() -> None:
    assert len(DEMO_CASES) == 8
    assert len({c.name for c in DEMO_CASES}) == 8


def test_demo_cases_pass_end_to_end_without_cert(synthetic: Dataset) -> None:
    results = run_demo_cases(synthetic, build_index(POLICIES, backend="tfidf"), llm=None, cert=None)
    by_name = {r.name: r for r in results}
    assert set(by_name) == {c.name for c in DEMO_CASES}
    assert by_name["CERT insider"].status == "skipped"
    ran = [r for r in results if r.status != "skipped"]
    assert len(ran) == 7
    failures = [(r.name, r.details) for r in ran if r.status != "passed"]
    assert not failures, failures


def test_privacy_trap_is_caught(synthetic: Dataset) -> None:
    results = run_demo_cases(synthetic, build_index(POLICIES, backend="tfidf"), llm=None, cert=None)
    trap = next(r for r in results if r.name == "Privacy Lint trap")
    assert trap.status == "passed"
    assert trap.generated_by.startswith("template (fallback") and "privacy lint" in trap.generated_by


def test_trap_llm_writes_accusatory_text() -> None:
    reply = TrapLLM().write("", {})
    assert "malicious" in reply["summary"].lower()
