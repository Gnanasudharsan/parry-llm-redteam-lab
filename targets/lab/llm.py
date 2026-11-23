"""Model access for lab targets: local Ollama by default, deterministic settings."""

from __future__ import annotations

import hashlib
import math
import os
import re
from typing import Protocol

from langchain_core.language_models import BaseChatModel

DEFAULT_CHAT_MODEL = "qwen2.5:7b-instruct"
DEFAULT_EMBED_MODEL = "nomic-embed-text"
MAX_OUTPUT_TOKENS = 512


def ollama_url() -> str:
    return os.environ.get("OLLAMA_BASE_URL", "http://localhost:11434")


def model_seed() -> int:
    return int(os.environ.get("LAB_MODEL_SEED", "1337"))


def chat_model() -> BaseChatModel:
    from langchain_ollama import ChatOllama

    return ChatOllama(
        model=os.environ.get("LAB_CHAT_MODEL", DEFAULT_CHAT_MODEL),
        base_url=ollama_url(),
        temperature=0,
        seed=model_seed(),
        num_ctx=8192,
        num_predict=MAX_OUTPUT_TOKENS,  # stops runaway repetition loops
    )


class Embedder(Protocol):
    def embed_documents(self, texts: list[str]) -> list[list[float]]: ...
    def embed_query(self, text: str) -> list[float]: ...


class OllamaEmbedder:
    """nomic-embed-text expects task prefixes on queries and documents."""

    def __init__(self) -> None:
        from langchain_ollama import OllamaEmbeddings

        self._inner = OllamaEmbeddings(
            model=os.environ.get("LAB_EMBED_MODEL", DEFAULT_EMBED_MODEL), base_url=ollama_url()
        )

    def embed_documents(self, texts: list[str]) -> list[list[float]]:
        return self._inner.embed_documents([f"search_document: {t}" for t in texts])

    def embed_query(self, text: str) -> list[float]:
        return self._inner.embed_query(f"search_query: {text}")


class HashingEmbedder:
    """Deterministic bag-of-words embedder for tests and offline runs (LAB_EMBEDDER=hashing)."""

    def __init__(self, dim: int = 512) -> None:
        self.dim = dim

    def _vec(self, text: str) -> list[float]:
        v = [0.0] * self.dim
        for tok in re.findall(r"[a-z0-9]+", text.lower()):
            h = int.from_bytes(hashlib.blake2b(tok.encode(), digest_size=4).digest(), "big")
            v[h % self.dim] += 1.0
        norm = math.sqrt(sum(x * x for x in v)) or 1.0
        return [x / norm for x in v]

    def embed_documents(self, texts: list[str]) -> list[list[float]]:
        return [self._vec(t) for t in texts]

    def embed_query(self, text: str) -> list[float]:
        return self._vec(text)


def embedder() -> Embedder:
    if os.environ.get("LAB_EMBEDDER", "ollama") == "hashing":
        return HashingEmbedder()
    return OllamaEmbedder()
