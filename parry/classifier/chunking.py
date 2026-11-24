"""Sliding-window scoring for inputs longer than a classifier's window.

The text is tokenized in full (no truncation) and cut into windows of `window` tokens
(special tokens included) that overlap by `overlap` tokens. Each window is scored on its
own; the input's logits are those of the window most likely to be an injection, so the input
is flagged when any window is. Calibration and threshold use the same chunked scores.
"""

from __future__ import annotations

from typing import Any

OVERLAP = 64


def windows(tok: Any, text: str, window: int, overlap: int = OVERLAP) -> list[list[int]]:
    """Token-id windows (with special tokens) covering the whole text."""
    ids: list[int] = tok(text, add_special_tokens=False)["input_ids"]
    body = window - tok.num_special_tokens_to_add(pair=False)
    if body <= overlap:
        raise ValueError("window too small for the overlap")
    step = body - overlap
    starts = list(range(0, max(1, len(ids) - overlap), step)) or [0]
    out = []
    for s in starts:
        chunk = ids[s : s + body]
        out.append(tok.build_inputs_with_special_tokens(chunk))
        if s + body >= len(ids):
            break
    return out


def chunked_logits(
    model: Any,
    tok: Any,
    texts: list[str],
    window: int,
    positive: int = 1,
    batch_size: int = 32,
    overlap: int = OVERLAP,
    max_windows: int | None = None,
) -> tuple[list[list[float]], list[int]]:
    """Per-text logits of the most injection-like window, and the number of windows used.
    `max_windows=1` scores only the first window, i.e. plain truncation."""
    import torch

    dev = next(model.parameters()).device
    model.eval()
    flat: list[tuple[int, list[int]]] = [
        (i, w) for i, t in enumerate(texts) for w in windows(tok, t, window, overlap)[:max_windows]
    ]
    scores: list[list[float]] = []
    pad = tok.pad_token_id
    with torch.no_grad():
        for b in range(0, len(flat), batch_size):
            batch = [w for _, w in flat[b : b + batch_size]]
            ids = torch.full((len(batch), window), pad, dtype=torch.long)
            mask = torch.zeros((len(batch), window), dtype=torch.long)
            for r, w in enumerate(batch):
                ids[r, : len(w)] = torch.tensor(w)
                mask[r, : len(w)] = 1
            out = model(input_ids=ids.to(dev), attention_mask=mask.to(dev)).logits
            scores += out.float().cpu().tolist()
    best: dict[int, list[float]] = {}
    count = [0] * len(texts)
    for (i, _), lg in zip(flat, scores, strict=True):
        count[i] += 1
        margin = lg[positive] - lg[1 - positive]
        if i not in best or margin > best[i][positive] - best[i][1 - positive]:
            best[i] = lg
    # return in [benign, injection] order regardless of the model's label order
    ordered = [[best[i][1 - positive], best[i][positive]] for i in range(len(texts))]
    return ordered, count


def window_logits(
    model: Any,
    tok: Any,
    texts: list[str],
    window: int,
    positive: int = 1,
    batch_size: int = 32,
    overlap: int = OVERLAP,
) -> list[list[list[float]]]:
    """Every window's logits per text, in [benign, injection] order (for exploratory
    aggregations such as a window-count-adjusted threshold or top-k averaging)."""
    import torch

    dev = next(model.parameters()).device
    model.eval()
    flat = [(i, w) for i, t in enumerate(texts) for w in windows(tok, t, window, overlap)]
    pad = tok.pad_token_id
    per: list[list[list[float]]] = [[] for _ in texts]
    with torch.no_grad():
        for b in range(0, len(flat), batch_size):
            part = flat[b : b + batch_size]
            ids = torch.full((len(part), window), pad, dtype=torch.long)
            mask = torch.zeros((len(part), window), dtype=torch.long)
            for r, (_, w) in enumerate(part):
                ids[r, : len(w)] = torch.tensor(w)
                mask[r, : len(w)] = 1
            out = model(input_ids=ids.to(dev), attention_mask=mask.to(dev)).logits.float().cpu()
            for (i, _), lg in zip(part, out.tolist(), strict=True):
                per[i].append([lg[1 - positive], lg[positive]])
    return per
