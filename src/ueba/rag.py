"""Policy RAG: retrieval over the local insider-risk policy corpus (FR-4).

Markdown files in `policies/` are split at their `##` headings into Policy Passages.
Each passage has a citation ID `<doc>#<section-slug>` that `PolicyIndex.get` can
resolve, so every citation in a Case Summary can be checked.

Backends, each searched with a FAISS inner-product index:
* `tfidf`: scikit-learn TF-IDF (keyword; offline and deterministic)
* `ollama`: embeddinggemma through the local Ollama server (semantic)
* `hybrid`: both, merged with reciprocal rank fusion. Keyword search misses paraphrases and
  embeddings miss some exact terms, so the two are combined. `auto` picks hybrid when Ollama
  is reachable, otherwise TF-IDF.

Run: .venv/bin/python -m ueba.rag "who approves restricting access?"
"""

from __future__ import annotations

import argparse
import json
import re
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

import faiss
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer

DEFAULT_POLICIES = Path(__file__).resolve().parents[2] / "policies"


@dataclass(frozen=True)
class Passage:
    citation: str
    doc: str
    title: str
    section: str
    text: str
    applies_to: tuple[str, ...]

    def indexed_text(self) -> str:
        rules = " ".join(self.applies_to)
        return f"{self.title}. {self.section}. {rules}\n{self.text}"


@dataclass(frozen=True)
class Hit:
    passage: Passage
    score: float


# --- corpus ---------------------------------------------------------------------


def _slug(heading: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", heading.lower()).strip("-")


def _front_matter(raw: str) -> tuple[dict[str, str], str]:
    if not raw.startswith("---\n"):
        return {}, raw
    end = raw.index("\n---", 4)
    meta: dict[str, str] = {}
    for line in raw[4:end].splitlines():
        if ":" in line:
            key, value = line.split(":", 1)
            meta[key.strip()] = value.strip()
    return meta, raw[end + 4 :].lstrip("\n")


def load_corpus(policies_dir: Path = DEFAULT_POLICIES) -> list[Passage]:
    passages: list[Passage] = []
    for path in sorted(Path(policies_dir).rglob("*.md")):
        meta, body = _front_matter(path.read_text())
        doc = f"playbook-{path.stem}" if path.parent.name == "playbooks" else path.stem
        title = meta.get("title", path.stem)
        applies_to = tuple(r.strip() for r in meta.get("applies_to", "").split(",") if r.strip())

        sections: list[tuple[str, list[str]]] = [("Overview", [])]
        for line in body.splitlines():
            if line.startswith("## "):
                sections.append((line[3:].strip(), []))
            elif not line.startswith("# "):
                sections[-1][1].append(line)
        for heading, lines in sections:
            text = "\n".join(lines).strip()
            if text:
                passages.append(Passage(f"{doc}#{_slug(heading)}", doc, title, heading, text, applies_to))
    return passages


# --- embedders ------------------------------------------------------------------


class Embedder(Protocol):
    name: str

    def embed_documents(self, texts: list[str]) -> np.ndarray: ...

    def embed_query(self, text: str) -> np.ndarray: ...


def _normalise(vectors: np.ndarray) -> np.ndarray:
    v = np.asarray(vectors, dtype=np.float32)
    norms = np.linalg.norm(v, axis=1, keepdims=True)
    return np.asarray(v / np.where(norms == 0, 1, norms), dtype=np.float32)


class TfidfEmbedder:
    name = "tfidf"

    def __init__(self) -> None:
        self._vectorizer = TfidfVectorizer(stop_words="english", ngram_range=(1, 2), sublinear_tf=True)

    def embed_documents(self, texts: list[str]) -> np.ndarray:
        return _normalise(self._vectorizer.fit_transform(texts).toarray())

    def embed_query(self, text: str) -> np.ndarray:
        return _normalise(self._vectorizer.transform([text]).toarray())


class OllamaEmbedder:
    """embeddinggemma via Ollama's /api/embed, with the model's recommended task prefixes."""

    def __init__(self, model: str = "embeddinggemma", url: str = "http://localhost:11434", timeout: float = 60) -> None:
        self.model, self.url, self.timeout = model, url.rstrip("/"), timeout
        self.name = f"ollama:{model}"

    def available(self) -> bool:
        try:
            with urllib.request.urlopen(f"{self.url}/api/tags", timeout=2) as resp:
                models = [m["name"].split(":")[0] for m in json.load(resp)["models"]]
            return self.model.split(":")[0] in models
        except (urllib.error.URLError, OSError, ValueError, KeyError):
            return False

    def _embed(self, inputs: list[str]) -> np.ndarray:
        req = urllib.request.Request(
            f"{self.url}/api/embed",
            data=json.dumps({"model": self.model, "input": inputs}).encode(),
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:
            return _normalise(np.array(json.load(resp)["embeddings"]))

    def embed_documents(self, texts: list[str]) -> np.ndarray:
        return self._embed([f"title: none | text: {t}" for t in texts])

    def embed_query(self, text: str) -> np.ndarray:
        return self._embed([f"task: search result | query: {text}"])


# --- index ----------------------------------------------------------------------


class PolicyIndex:
    def __init__(self, passages: list[Passage], embedder: Embedder) -> None:
        if not passages:
            raise ValueError("policy corpus is empty")
        self.passages = passages
        self.embedder = embedder
        self.backend = embedder.name
        self._by_citation = {p.citation: p for p in passages}
        vectors = embedder.embed_documents([p.indexed_text() for p in passages])
        self._index = faiss.IndexFlatIP(vectors.shape[1])
        self._index.add(vectors)

    def rank(self, query: str) -> list[tuple[int, float]]:
        """Every passage index with its similarity, best first."""
        scores, ids = self._index.search(self.embedder.embed_query(query), len(self.passages))
        return [(int(i), float(sc)) for sc, i in zip(scores[0], ids[0])]

    def search(self, query: str, k: int = 3, finding_type: str | None = None) -> list[Hit]:
        """Top-k passages. With `finding_type`, only that Finding's playbook and general policy are eligible."""
        return _top_k(self.passages, self.rank(query), k, finding_type)

    def get(self, citation: str) -> Passage:
        return self._by_citation[citation]

    def resolves(self, citation: str) -> bool:
        return citation in self._by_citation


def _top_k(passages: list[Passage], ranked: list[tuple[int, float]], k: int, finding_type: str | None) -> list[Hit]:
    hits = []
    for i, score in ranked:
        p = passages[i]
        if finding_type is None or p.applies_to in ((), (finding_type,)):
            hits.append(Hit(p, score))
        if len(hits) == k:
            break
    return hits


RRF_K = 60  # standard reciprocal-rank-fusion constant


class HybridIndex:
    """Reciprocal rank fusion of several indexes over the same passages."""

    def __init__(self, indexes: list[PolicyIndex]) -> None:
        self.indexes = indexes
        self.passages = indexes[0].passages
        self.backend = "hybrid:" + "+".join(ix.backend for ix in indexes)

    def search(self, query: str, k: int = 3, finding_type: str | None = None) -> list[Hit]:
        fused: dict[int, float] = {}
        for ix in self.indexes:
            for rank, (i, _) in enumerate(ix.rank(query)):
                fused[i] = fused.get(i, 0.0) + 1.0 / (RRF_K + rank + 1)
        ranked = sorted(fused.items(), key=lambda kv: kv[1], reverse=True)
        return _top_k(self.passages, ranked, k, finding_type)

    def get(self, citation: str) -> Passage:
        return self.indexes[0].get(citation)

    def resolves(self, citation: str) -> bool:
        return self.indexes[0].resolves(citation)


class Retriever(Protocol):
    backend: str
    passages: list[Passage]

    def search(self, query: str, k: int = 3, finding_type: str | None = None) -> list[Hit]: ...

    def get(self, citation: str) -> Passage: ...

    def resolves(self, citation: str) -> bool: ...


def build_index(
    policies_dir: Path = DEFAULT_POLICIES, backend: str = "auto", embedder: OllamaEmbedder | None = None
) -> Retriever:
    """backend: "tfidf", "ollama", "hybrid", or "auto" (hybrid when Ollama is reachable, else TF-IDF)."""
    passages = load_corpus(policies_dir)
    ollama = embedder or OllamaEmbedder()
    if backend == "auto":
        backend = "hybrid" if ollama.available() else "tfidf"
    if backend == "tfidf":
        return PolicyIndex(passages, TfidfEmbedder())
    if backend == "ollama":
        return PolicyIndex(passages, ollama)
    if backend == "hybrid":
        return HybridIndex([PolicyIndex(passages, TfidfEmbedder()), PolicyIndex(passages, ollama)])
    raise ValueError(f"unknown backend {backend!r}")


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="Search the insider-risk policy corpus.")
    parser.add_argument("query")
    parser.add_argument("--k", type=int, default=3)
    parser.add_argument("--backend", default="auto", choices=["auto", "hybrid", "ollama", "tfidf"])
    parser.add_argument("--finding-type", help="restrict to one Finding's playbook plus general policy")
    args = parser.parse_args(argv)

    index = build_index(backend=args.backend)
    print(f"backend: {index.backend} · {len(index.passages)} passages\n")
    for hit in index.search(args.query, k=args.k, finding_type=args.finding_type):
        p = hit.passage
        print(f"[{hit.score:.3f}] {p.citation}  ({p.title} — {p.section})")
        print("    " + p.text[:300].replace("\n", "\n    ") + ("…" if len(p.text) > 300 else "") + "\n")


if __name__ == "__main__":
    main()
