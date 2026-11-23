"""`parry guard serve`: serve encoder classifiers over HTTP for lab apps and scans.

Needs the `lab` and `ml` dependency groups (FastAPI, Transformers, PyTorch). Models load
lazily from the local Hugging Face cache; nothing is downloaded at request time unless the
cache is empty.
"""

from __future__ import annotations

import threading
from typing import Any

from pydantic import BaseModel, Field

MODELS = {
    # Apache-2.0. https://huggingface.co/protectai/deberta-v3-base-prompt-injection-v2
    "protectai": ("protectai/deberta-v3-base-prompt-injection-v2", "INJECTION"),
}
MAX_TOKENS = 512  # longer inputs are truncated (a known blind spot for long documents)


class ClassifyRequest(BaseModel):
    model: str = "protectai"
    texts: list[str] = Field(min_length=1, max_length=64)


def create_app() -> Any:
    from fastapi import FastAPI, HTTPException

    app = FastAPI(title="Parry guard server", docs_url=None, redoc_url=None)
    lock = threading.Lock()
    loaded: dict[str, Any] = {}

    def pipeline(name: str) -> Any:
        if name not in MODELS:
            raise HTTPException(404, f"unknown model {name!r}")
        with lock:
            if name not in loaded:
                from transformers import pipeline as hf_pipeline

                loaded[name] = hf_pipeline(
                    "text-classification",
                    model=MODELS[name][0],
                    truncation=True,
                    max_length=MAX_TOKENS,
                    device="cpu",
                )
            return loaded[name]

    @app.get("/health")
    def health() -> dict[str, Any]:
        return {"status": "ok", "models": sorted(MODELS), "loaded": sorted(loaded)}

    @app.post("/classify")
    def classify(req: ClassifyRequest) -> dict[str, Any]:
        pipe = pipeline(req.model)
        positive = MODELS[req.model][1]
        outs = pipe(req.texts, top_k=None)
        results = []
        for text, scores in zip(req.texts, outs, strict=True):
            by_label = {s["label"]: float(s["score"]) for s in scores}
            n_tokens = len(
                pipe.tokenizer(text, truncation=True, max_length=MAX_TOKENS)["input_ids"]
            )
            results.append({"injection_score": by_label.get(positive, 0.0), "tokens": n_tokens})
        return {"model": MODELS[req.model][0], "results": results}

    return app
