"""Fine-tune DeBERTa-v3-small as a binary prompt-injection classifier (plain PyTorch loop).

Deterministic where the hardware allows: fixed seeds for Python, NumPy and PyTorch and a
seeded data order. MPS kernels are not bit-for-bit deterministic, so the run is repeated with
three seeds and the spread is reported. Weights go to classifier/artifacts/ (git-ignored);
MLflow logs parameters and metrics to a local file store (mlruns/, git-ignored).
"""

from __future__ import annotations

import json
import math
import random
import time
from pathlib import Path
from typing import Any

BASE = "microsoft/deberta-v3-small"
BASE_REVISION = "a36c739020e01763fe789b4b85e2df55d6180012"
ARTIFACTS = Path("classifier/artifacts")
DEFAULTS: dict[str, Any] = {
    "max_len": 256,
    "batch_size": 16,
    "lr": 3e-5,
    "weight_decay": 0.01,
    "epochs": 2,
    "warmup": 0.1,
}


def device() -> Any:
    import torch

    return torch.device("mps" if torch.backends.mps.is_available() else "cpu")


def set_seed(seed: int) -> None:
    import numpy as np
    import torch

    random.seed(seed)
    np.random.seed(seed)
    torch.manual_seed(seed)


def load_base() -> tuple[Any, Any]:
    import torch
    from transformers import AutoModelForSequenceClassification, AutoTokenizer

    tok = AutoTokenizer.from_pretrained(BASE, revision=BASE_REVISION)
    # The checkpoint is stored in float16 and Transformers 5 keeps the stored dtype; AdamW's
    # epsilon underflows in float16 and the first update turns weights into NaN. Train in fp32.
    model = AutoModelForSequenceClassification.from_pretrained(
        BASE, revision=BASE_REVISION, num_labels=2, dtype=torch.float32
    )
    return tok, model


def logits_for(
    model: Any, tok: Any, texts: list[str], max_len: int, batch_size: int = 32
) -> list[list[float]]:
    """Raw two-class logits for texts, in order (no calibration)."""
    import torch

    dev = next(model.parameters()).device
    model.eval()
    out: list[list[float]] = []
    with torch.no_grad():
        for i in range(0, len(texts), batch_size):
            enc = tok(
                texts[i : i + batch_size],
                truncation=True,
                max_length=max_len,
                padding="max_length",  # fixed shapes: MPS caches per shape (memory grows)
                return_tensors="pt",
            ).to(dev)
            out += model(**enc).logits.float().cpu().tolist()
    return out


def _nll(logits: list[list[float]], labels: list[int]) -> float:
    total = 0.0
    for (a, b), y in zip(logits, labels, strict=True):
        m = max(a, b)
        lse = m + math.log(math.exp(a - m) + math.exp(b - m))
        total += lse - (b if y == 1 else a)
    return total / max(1, len(labels))


def train(
    seed: int,
    train_items: list[dict[str, Any]],
    val_items: list[dict[str, Any]],
    out_dir: Path,
    params: dict[str, Any] | None = None,
    limit: int | None = None,
    log: Any = print,
) -> dict[str, Any]:
    """Train one seed; keep the epoch with the lowest validation loss. Returns metrics."""
    import torch

    p = {**DEFAULTS, **(params or {})}
    set_seed(seed)
    tok, model = load_base()
    dev = device()
    model.to(dev)
    items = train_items[:limit] if limit else train_items
    val = val_items[:limit] if limit else val_items
    order = random.Random(seed)  # noqa: S311 - reproducible data order
    steps_per_epoch = math.ceil(len(items) / p["batch_size"])
    total_steps: int = steps_per_epoch * int(p["epochs"])
    opt = torch.optim.AdamW(model.parameters(), lr=p["lr"], weight_decay=p["weight_decay"])
    warm: int = max(1, int(p["warmup"] * total_steps))

    def lr_factor(step: int) -> float:  # linear warmup, then linear decay to 0
        if step < warm:
            return float(step) / warm
        return max(0.0, float(total_steps - step) / max(1, total_steps - warm))

    sched = torch.optim.lr_scheduler.LambdaLR(opt, lr_factor)
    best: dict[str, Any] = {"val_loss": float("inf")}
    history = []
    t0 = time.perf_counter()
    for epoch in range(1, p["epochs"] + 1):
        model.train()
        idx = list(range(len(items)))
        order.shuffle(idx)
        running = 0.0
        for step in range(steps_per_epoch):
            batch = [items[j] for j in idx[step * p["batch_size"] : (step + 1) * p["batch_size"]]]
            enc = tok(
                [b["text"] for b in batch],
                truncation=True,
                max_length=p["max_len"],
                padding="max_length",  # fixed shapes: MPS caches per shape (memory grows)
                return_tensors="pt",
            ).to(dev)
            labels = torch.tensor([b["label"] for b in batch], device=dev)
            loss = model(**enc, labels=labels).loss
            if not torch.isfinite(loss):
                raise FloatingPointError(f"non-finite loss at epoch {epoch} step {step}")
            loss.backward()
            torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
            opt.step()
            sched.step()
            opt.zero_grad()
            running += float(loss)
            if (step + 1) % 100 == 0:
                avg = running / (step + 1)
                log(f"seed {seed} epoch {epoch} step {step + 1}/{steps_per_epoch} loss {avg:.4f}")
        vlog = logits_for(model, tok, [v["text"] for v in val], p["max_len"])
        vloss = _nll(vlog, [v["label"] for v in val])
        row = {
            "epoch": epoch,
            "train_loss": running / steps_per_epoch,
            "val_loss": vloss,
            "elapsed_s": round(time.perf_counter() - t0, 1),
        }
        history.append(row)
        log(f"seed {seed} epoch {epoch} done: {row}")
        if vloss < best["val_loss"]:
            best = {**row}
            out_dir.mkdir(parents=True, exist_ok=True)
            model.save_pretrained(out_dir, safe_serialization=True)
            tok.save_pretrained(out_dir)
    meta = {
        "seed": seed,
        "base": BASE,
        "base_revision": BASE_REVISION,
        "params": p,
        "device": str(dev),
        "n_train": len(items),
        "n_val": len(val),
        "best_epoch": best["epoch"],
        "best_val_loss": best["val_loss"],
        "history": history,
    }
    (out_dir / "training.json").write_text(json.dumps(meta, indent=2) + "\n")
    return meta


def load_trained(path: Path) -> tuple[Any, Any]:
    import torch
    from transformers import AutoModelForSequenceClassification, AutoTokenizer

    tok = AutoTokenizer.from_pretrained(path)
    model = AutoModelForSequenceClassification.from_pretrained(path, dtype=torch.float32)
    model.to(device())
    return tok, model
