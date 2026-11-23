"""A small in-memory vector store (cosine similarity over numpy arrays)."""

from __future__ import annotations

import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

import numpy as np

from targets.lab.llm import Embedder

Visibility = Literal["public", "internal"]
Source = Literal["corpus", "review", "web"]


@dataclass(frozen=True)
class Doc:
    id: str
    title: str
    text: str
    visibility: Visibility = "public"
    source: Source = "corpus"


def load_corpus(directory: Path, fill: dict[str, str]) -> list[Doc]:
    """Read `---`-headed markdown files; `{placeholders}` are filled with lab secrets."""
    docs = []
    for path in sorted(directory.glob("*.md")):
        _, header, body = path.read_text().split("---", 2)
        meta = dict(line.split(":", 1) for line in header.strip().splitlines() if ":" in line)
        visibility = meta.get("visibility", "public").strip()
        if visibility not in ("public", "internal"):
            raise ValueError(f"{path.name}: bad visibility {visibility!r}")
        docs.append(
            Doc(
                id=path.stem,
                title=meta.get("title", path.stem).strip(),
                text=body.strip().format(**fill),
                visibility=visibility,  # type: ignore[arg-type]
            )
        )
    return docs


class VectorStore:
    def __init__(self, embedder: Embedder) -> None:
        self._embedder = embedder
        self._lock = threading.Lock()
        self._docs: list[Doc] = []
        self._matrix = np.zeros((0, 0), dtype=np.float32)

    def add(self, docs: list[Doc]) -> None:
        if not docs:
            return
        vecs = np.asarray(
            self._embedder.embed_documents([f"{d.title}\n{d.text}" for d in docs]),
            dtype=np.float32,
        )
        vecs /= np.linalg.norm(vecs, axis=1, keepdims=True) + 1e-12
        with self._lock:
            self._docs.extend(docs)
            self._matrix = vecs if self._matrix.size == 0 else np.vstack([self._matrix, vecs])

    def remove_where(self, keep: Literal["corpus"]) -> None:
        with self._lock:
            idx = [i for i, d in enumerate(self._docs) if d.source == keep]
            self._docs = [self._docs[i] for i in idx]
            self._matrix = self._matrix[idx] if idx else np.zeros((0, 0), dtype=np.float32)

    def search(
        self, query: str, k: int = 4, visibility: set[Visibility] | None = None
    ) -> list[Doc]:
        q = np.asarray(self._embedder.embed_query(query), dtype=np.float32)
        q /= np.linalg.norm(q) + 1e-12
        with self._lock:
            if not self._docs:
                return []
            scores = self._matrix @ q
            order = np.argsort(-scores, kind="stable")
            hits = [
                self._docs[i]
                for i in order
                if visibility is None or self._docs[i].visibility in visibility
            ]
        return hits[:k]

    def __len__(self) -> int:
        return len(self._docs)
