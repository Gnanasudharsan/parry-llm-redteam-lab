"""Calibrate and evaluate the classifier, and the ProtectAI baseline on the same sets.

Decisions fixed before any result was seen (ADR 0006):
- calibration: temperature scaling fit on the validation split (minimum NLL);
- threshold: the lowest threshold whose false-positive rate on validation benign items is at
  most TARGET_FPR (1%), chosen on calibrated validation probabilities;
- the published model is seed 1337; the other seeds show training variance;
- the baseline is reported at its deployed threshold (0.5, as in Phase 3) and at a threshold
  tuned on the same validation split to the same target false-positive rate.
"""

from __future__ import annotations

import math
from collections import defaultdict
from typing import Any

from parry.metrics import wilson_interval

TARGET_FPR = 0.01
HELDOUT = ("gandalf", "parry_attacks", "notinject", "parry_benign", "lab_content")


def softmax_pos(logits: list[float], temperature: float = 1.0) -> float:
    a, b = logits[0] / temperature, logits[1] / temperature
    m = max(a, b)
    return math.exp(b - m) / (math.exp(a - m) + math.exp(b - m))


def nll(logits: list[list[float]], labels: list[int], temperature: float) -> float:
    eps = 1e-12
    total = 0.0
    for lg, y in zip(logits, labels, strict=True):
        p = softmax_pos(lg, temperature)
        total -= math.log(max(eps, p if y == 1 else 1 - p))
    return total / max(1, len(labels))


def fit_temperature(logits: list[list[float]], labels: list[int]) -> float:
    """Temperature in [e^-3, e^3] minimizing validation NLL (golden-section on log T)."""
    lo, hi = -3.0, 3.0
    g = (math.sqrt(5) - 1) / 2
    c, d = hi - g * (hi - lo), lo + g * (hi - lo)
    for _ in range(80):
        if nll(logits, labels, math.exp(c)) < nll(logits, labels, math.exp(d)):
            hi = d
        else:
            lo = c
        c, d = hi - g * (hi - lo), lo + g * (hi - lo)
    return math.exp((lo + hi) / 2)


def threshold_for_fpr(probs: list[float], labels: list[int], target: float = TARGET_FPR) -> float:
    """Lowest threshold t (flag when p >= t) with benign false-positive rate <= target."""
    neg = sorted((p for p, y in zip(probs, labels, strict=True) if y == 0), reverse=True)
    allowed = math.floor(target * len(neg))  # benign items allowed at or above t
    if not neg:
        return 0.5
    if allowed >= len(neg):
        return 0.0
    # t just above the (allowed+1)-th highest benign score
    return math.nextafter(neg[allowed], 1.0)


def ece(probs: list[float], labels: list[int], bins: int = 10) -> float:
    """Expected calibration error, equal-width bins on p(injection)."""
    n = len(probs)
    total = 0.0
    for k in range(bins):
        lo, hi = k / bins, (k + 1) / bins
        idx = [i for i, p in enumerate(probs) if (lo <= p < hi) or (k == bins - 1 and p == 1.0)]
        if idx:
            conf = sum(probs[i] for i in idx) / len(idx)
            acc = sum(labels[i] for i in idx) / len(idx)
            total += len(idx) / n * abs(conf - acc)
    return total


def auroc(probs: list[float], labels: list[int]) -> float | None:
    """Probability a random injection scores above a random benign item (ties count half)."""
    pos = [p for p, y in zip(probs, labels, strict=True) if y == 1]
    neg = [p for p, y in zip(probs, labels, strict=True) if y == 0]
    if not pos or not neg:
        return None
    order = sorted([(p, 1) for p in pos] + [(p, 0) for p in neg])
    rank_sum, i = 0.0, 0
    while i < len(order):
        j = i
        while j + 1 < len(order) and order[j + 1][0] == order[i][0]:
            j += 1
        avg_rank = (i + j) / 2 + 1
        rank_sum += avg_rank * sum(1 for k in range(i, j + 1) if order[k][1] == 1)
        i = j + 1
    return (rank_sum - len(pos) * (len(pos) + 1) / 2) / (len(pos) * len(neg))


def _rate(k: int, n: int) -> dict[str, Any]:
    r = wilson_interval(k, n)
    return {
        "k": k,
        "n": n,
        "rate": round(r.point, 4),
        "low": round(r.low, 4),
        "high": round(r.high, 4),
    }


def score_sets(
    probs: dict[str, list[float]],
    items: dict[str, list[dict[str, Any]]],
    threshold: float,
) -> dict[str, Any]:
    """Detection / false-positive rates per set, per source on test, per family on attacks."""
    out: dict[str, Any] = {"threshold": threshold, "sets": {}}
    for name, ps in probs.items():
        its = items[name]
        flags = [p >= threshold for p in ps]
        labels = [it["label"] for it in its]
        row: dict[str, Any] = {}
        pos = [f for f, y in zip(flags, labels, strict=True) if y == 1]
        neg = [f for f, y in zip(flags, labels, strict=True) if y == 0]
        if pos:
            row["detection"] = _rate(sum(pos), len(pos))
        if neg:
            row["false_positive"] = _rate(sum(neg), len(neg))
        if pos and neg:
            row["auroc"] = auroc(ps, labels)
            row["ece"] = round(ece(ps, labels), 4)
        groups: dict[str, list[tuple[bool, int]]] = defaultdict(list)
        key = "family" if name.endswith("parry_attacks") else "source" if name == "test" else None
        if key:
            for f, it in zip(flags, its, strict=True):
                groups[f"{it[key]}:{it['label']}"].append((f, it["label"]))
            row[f"by_{key}"] = {
                g: _rate(sum(f for f, _ in v), len(v)) for g, v in sorted(groups.items())
            }
        # per-item probabilities (in set order) so breakdowns can be recomputed from the file
        row["probs"] = [round(p, 6) for p in ps]
        out["sets"][name] = row
    return out


SETS = ("val", "test", *(f"heldout_{h}" for h in HELDOUT))


def _protectai_probs(texts: list[str]) -> list[float]:
    """p(injection) from the Phase 3 baseline (protectai/deberta-v3-base-prompt-injection-v2)."""
    from transformers import pipeline

    from parry.defenses.server import MAX_TOKENS, MODELS

    name, positive = MODELS["protectai"]
    pipe = pipeline(
        "text-classification", model=name, truncation=True, max_length=MAX_TOKENS, device="cpu"
    )
    out: list[float] = []
    for i in range(0, len(texts), 32):
        batch: Any = pipe(texts[i : i + 32], top_k=None)
        for scores in batch:
            out.append(float(next(s["score"] for s in scores if s["label"] == positive)))
    return out


def evaluate_model(model_dir: Any, items: dict[str, list[dict[str, Any]]]) -> dict[str, Any]:
    """Calibrate on validation, pick the threshold on validation, score every set."""
    from parry.classifier.chunking import chunked_logits
    from parry.classifier.train import DEFAULTS, load_trained

    tok, model = load_trained(model_dir)
    window = DEFAULTS["max_len"]
    # Inference uses sliding-window chunking (any window over the threshold flags the input);
    # the temperature and threshold are fit on validation scored the same way. Truncated
    # scores (first window only) are kept for comparison.
    logits = {
        k: chunked_logits(model, tok, [it["text"] for it in v], window)[0] for k, v in items.items()
    }
    truncated = {
        k: chunked_logits(model, tok, [it["text"] for it in v], window, max_windows=1)[0]
        for k, v in items.items()
    }
    vlab = [it["label"] for it in items["val"]]
    t = fit_temperature(logits["val"], vlab)
    raw = {k: [softmax_pos(lg) for lg in v] for k, v in logits.items()}
    cal = {k: [softmax_pos(lg, t) for lg in v] for k, v in logits.items()}
    threshold = threshold_for_fpr(cal["val"], vlab)
    res = score_sets(cal, items, threshold)
    res["temperature"] = round(t, 4)
    res["ece_val"] = {
        "before": round(ece(raw["val"], vlab), 4),
        "after": round(ece(cal["val"], vlab), 4),
    }
    tlab = [it["label"] for it in items["test"]]
    res["ece_test"] = {
        "before": round(ece(raw["test"], tlab), 4),
        "after": round(ece(cal["test"], tlab), 4),
    }
    res["inference"] = "chunked (256-token windows, 64 overlap; max over windows)"
    t_trunc = fit_temperature(truncated["val"], vlab)
    cal_trunc = {k: [softmax_pos(lg, t_trunc) for lg in v] for k, v in truncated.items()}
    res["truncated_for_comparison"] = {
        "temperature": round(t_trunc, 4),
        **score_sets(cal_trunc, items, threshold_for_fpr(cal_trunc["val"], vlab)),
    }
    return res


def evaluate_baseline(items: dict[str, list[dict[str, Any]]]) -> dict[str, Any]:
    probs = {k: _protectai_probs([it["text"] for it in v]) for k, v in items.items()}
    vlab = [it["label"] for it in items["val"]]
    return {
        "deployed_0.5": score_sets(probs, items, 0.5),
        "tuned_val_fpr": score_sets(probs, items, threshold_for_fpr(probs["val"], vlab)),
    }
