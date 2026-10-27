from pathlib import Path

import pytest

from ueba.detection import RULES
from functools import cache

from ueba.rag import OllamaEmbedder, Passage, PolicyIndex, Retriever, build_index, load_corpus

POLICIES = Path(__file__).resolve().parents[1] / "policies"


@pytest.fixture(scope="module")
def corpus() -> list[Passage]:
    return load_corpus(POLICIES)


@pytest.fixture(scope="module")
def index() -> PolicyIndex:
    return build_index(POLICIES, backend="tfidf")


@cache
def hybrid_index() -> Retriever:
    return build_index(POLICIES, backend="hybrid")


def agent_query(rule: str) -> str:
    """The query the agent's search_policy tool sends for a Finding."""
    return f"{rule} {RULES[rule].unit}"


# --- corpus ---------------------------------------------------------------------


def test_corpus_is_chunked_by_section_with_unique_citations(corpus: list[Passage]) -> None:
    citations = [p.citation for p in corpus]
    assert len(citations) == len(set(citations))
    assert len(corpus) >= 40
    assert "playbook-mass-download#recommended-actions" in citations
    assert "escalation-matrix#high-risk" in citations
    assert all(p.text.strip() for p in corpus)


def test_front_matter_is_parsed_and_not_part_of_the_text(corpus: list[Passage]) -> None:
    playbook = [p for p in corpus if p.doc == "playbook-after-hours"]
    assert playbook and all(p.applies_to == ("AFTER_HOURS",) for p in playbook)
    assert all("applies_to" not in p.text for p in corpus)
    general = [p for p in corpus if p.doc == "escalation-matrix"]
    assert general and all(p.applies_to == () for p in general)


def test_every_rule_has_a_playbook(corpus: list[Passage]) -> None:
    covered = {rule for p in corpus for rule in p.applies_to}
    assert covered == set(RULES)


def test_approval_markers_survive_chunking(corpus: list[Passage]) -> None:
    actions = next(p for p in corpus if p.citation == "playbook-mass-download#recommended-actions")
    assert "[approval required]" in actions.text


# --- retrieval (FR-4 done-when) ---------------------------------------------------


@pytest.mark.parametrize("rule", sorted(RULES))
def test_agent_query_for_each_finding_returns_its_playbook_in_the_top_3(index: PolicyIndex, rule: str) -> None:
    hits = index.search(agent_query(rule), k=3)
    assert any(rule in h.passage.applies_to for h in hits), [h.passage.citation for h in hits]


@pytest.mark.parametrize(
    "question, expected_docs",
    [
        # both documents state that restricting access needs Reviewer approval
        ("who must approve restricting a person's access", {"escalation-matrix", "insider-risk-handling-policy"}),
        ("words we must never use in a case summary", {"privacy-and-fairness-standard"}),
        ("can analysts open the contents of files", {"evidence-handling-standard"}),
        ("someone logged in at 2am on several nights", {"playbook-after-hours"}),
    ],
)
@pytest.mark.skipif(not OllamaEmbedder().available(), reason="Ollama with embeddinggemma not reachable")
def test_free_text_questions_find_the_right_document_with_hybrid_search(question: str, expected_docs: set[str]) -> None:
    # Keyword search misses paraphrases ("open the contents" vs "opening file contents") and
    # embeddings miss some exact terms; hybrid search is expected to handle both.
    hits = hybrid_index().search(question, k=3)
    assert expected_docs & {h.passage.doc for h in hits}, [h.passage.citation for h in hits]


def test_finding_type_filter_returns_that_playbook_plus_general_policy(index: PolicyIndex) -> None:
    hits = index.search("recommended actions", k=6, finding_type="NEW_USB_USER")
    assert hits
    assert all(h.passage.applies_to in ((), ("NEW_USB_USER",)) for h in hits)


def test_scores_are_sorted_and_k_is_respected(index: PolicyIndex) -> None:
    hits = index.search("mass download", k=4)
    assert len(hits) == 4
    scores = [h.score for h in hits]
    assert scores == sorted(scores, reverse=True)


def test_citations_resolve_and_unknown_ones_raise(index: PolicyIndex) -> None:
    p = index.get("escalation-matrix#medium-risk")
    assert p.title == "Escalation Matrix" and "2 business days" in p.text
    assert index.resolves("escalation-matrix#medium-risk")
    assert not index.resolves("made-up#section")
    with pytest.raises(KeyError):
        index.get("made-up#section")


# --- dense backend (integration, needs local Ollama with embeddinggemma) ----------


@pytest.mark.skipif(not OllamaEmbedder().available(), reason="Ollama with embeddinggemma not reachable")
def test_ollama_backend_retrieves_playbooks_semantically() -> None:
    index = build_index(POLICIES, backend="ollama")
    assert index.backend == "ollama:embeddinggemma"
    hits = index.search("an employee copied hundreds of files onto a thumb drive in one afternoon", k=3)
    assert any(h.passage.applies_to and h.passage.applies_to[0] in {"MASS_DOWNLOAD", "NEW_USB_USER"} for h in hits)


def test_auto_backend_falls_back_to_tfidf_when_ollama_is_down() -> None:
    index = build_index(POLICIES, backend="auto", embedder=OllamaEmbedder(url="http://127.0.0.1:9"))
    assert index.backend == "tfidf"


@pytest.mark.skipif(not OllamaEmbedder().available(), reason="Ollama with embeddinggemma not reachable")
@pytest.mark.parametrize("rule", sorted(RULES))
def test_hybrid_agent_query_for_each_finding_returns_its_playbook_in_the_top_3(rule: str) -> None:
    index = hybrid_index()
    assert index.backend == "hybrid:tfidf+ollama:embeddinggemma"
    hits = index.search(agent_query(rule), k=3)
    assert any(rule in h.passage.applies_to for h in hits), [h.passage.citation for h in hits]


@pytest.mark.skipif(not OllamaEmbedder().available(), reason="Ollama with embeddinggemma not reachable")
def test_auto_backend_prefers_hybrid_when_ollama_is_up() -> None:
    assert build_index(POLICIES, backend="auto").backend.startswith("hybrid:")
