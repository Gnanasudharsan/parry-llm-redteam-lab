"""Long-input evaluation: held-out injections inside long benign documents.

Benign documents are built from English OASST1 first-turn prompts that are *not* in the
training pool (train/val/test), concatenated until a document reaches a target length in the
classifier's tokens (1,024, 2,048, 4,096). Each of 100 held-out injections (50 Gandalf, 50
Parry attack cases, seeded sample) is inserted at the start, the middle (nearest paragraph
break) or the end of its own document of each length. The same documents without an
injection measure false positives on long benign text (the length confound in training).
"""

from __future__ import annotations

import gzip
import json
import random
from typing import Any

from parry.classifier.data import SEED, _dir, load_split, normalize

LENGTHS = (1024, 2048, 4096)
POSITIONS = ("start", "middle", "end")
N_INJECTIONS = 100


def unused_benign_prompts() -> list[str]:
    path = _dir("OpenAssistant/oasst1") / "2023-04-12_oasst_prompts.messages.jsonl.gz"
    with gzip.open(path, "rt") as f:
        rows = [json.loads(line) for line in f]
    pool = {normalize(it["text"]) for s in ("train", "val", "test") for it in load_split(s)}
    return [
        r["text"].strip()
        for r in rows
        if r.get("lang") == "en" and r.get("parent_id") is None and normalize(r["text"]) not in pool
    ]


def build(tok: Any, seed: int = SEED) -> dict[str, Any]:
    rng = random.Random(seed)  # noqa: S311 - reproducible sampling
    prompts = unused_benign_prompts()
    rng.shuffle(prompts)
    gandalf = rng.sample(load_split("heldout_gandalf"), N_INJECTIONS // 2)
    parry = rng.sample(load_split("heldout_parry_attacks"), N_INJECTIONS // 2)
    injections = [it["text"] for it in gandalf + parry]
    docs: dict[int, list[list[str]]] = {}
    cursor = 0
    for length in LENGTHS:
        docs[length] = []
        for _ in range(N_INJECTIONS):
            paras: list[str] = []
            n = 0
            while n < length:
                p = prompts[cursor % len(prompts)]
                cursor += 1
                paras.append(p)
                n += len(tok(p, add_special_tokens=False)["input_ids"]) + 2
            docs[length].append(paras)
    cases: list[dict[str, Any]] = []
    for length in LENGTHS:
        for i, paras in enumerate(docs[length]):
            cases.append(
                {"length": length, "position": "none", "label": 0, "text": "\n\n".join(paras)}
            )
            for pos in POSITIONS:
                at = {"start": 0, "middle": len(paras) // 2, "end": len(paras)}[pos]
                text = "\n\n".join([*paras[:at], injections[i], *paras[at:]])
                cases.append({"length": length, "position": pos, "label": 1, "text": text})
    return {"unused_prompts": len(prompts), "cases": cases}


def _load_protectai() -> tuple[Any, Any, int]:
    import torch
    from transformers import AutoModelForSequenceClassification, AutoTokenizer

    from parry.classifier.train import device
    from parry.defenses.server import MODELS

    name, positive = MODELS["protectai"]
    tok = AutoTokenizer.from_pretrained(name)
    model = AutoModelForSequenceClassification.from_pretrained(name, dtype=torch.float32)
    model.to(device())
    idx = next(i for i, lab in model.config.id2label.items() if lab == positive)
    return tok, model, int(idx)


def score_modes(
    model: Any, tok: Any, texts: list[str], window: int, positive: int
) -> dict[str, list[list[float]]]:
    from parry.classifier.chunking import chunked_logits

    return {
        "truncated": chunked_logits(model, tok, texts, window, positive, max_windows=1)[0],
        "chunked": chunked_logits(model, tok, texts, window, positive)[0],
    }


def _aggregate(per_window: list[float], how: str) -> float:
    """per_window: probabilities of each window; how: max or top2 (mean of the two highest)."""
    top = sorted(per_window, reverse=True)
    return top[0] if how == "max" else sum(top[:2]) / len(top[:2])


def exploratory(
    val_windows: list[list[float]],
    val_labels: list[int],
    case_windows: list[list[float]],
    target: float,
) -> dict[str, Any]:
    """Exploratory length-aware rules on window probabilities (already calibrated):
    - window_adjusted: flag if the top window is >= the threshold giving a per-window
      false-positive rate of target / k on validation windows, k = the input's windows;
    - top2_mean: flag if the mean of the two highest windows is >= a threshold set on
      validation with the same aggregation."""
    from parry.classifier.evaluate import threshold_for_fpr

    val_win_flat = [p for ws, y in zip(val_windows, val_labels, strict=True) for p in ws if y == 0]
    win_labels = [0] * len(val_win_flat)
    cache: dict[int, float] = {}

    def t_for(k: int) -> float:
        if k not in cache:
            cache[k] = threshold_for_fpr(val_win_flat, win_labels, target / k)
        return cache[k]

    adj = [max(ws) >= t_for(len(ws)) for ws in case_windows]
    t2 = threshold_for_fpr([_aggregate(ws, "top2") for ws in val_windows], val_labels, target)
    top2 = [_aggregate(ws, "top2") >= t2 for ws in case_windows]
    return {"window_adjusted": adj, "top2_mean": top2, "top2_threshold": t2}


def run(our_dir: Any, seed: int = SEED) -> dict[str, Any]:
    """Recall by length and position, and false positives on long benign documents, for our
    classifier (256-token windows, temperature and threshold fit on validation in the same
    mode) and ProtectAI (512-token windows; deployed threshold 0.5 and a threshold tuned on
    validation in the same mode)."""
    from parry.classifier.evaluate import fit_temperature, softmax_pos, threshold_for_fpr
    from parry.classifier.train import load_trained
    from parry.metrics import wilson_interval

    val = load_split("val")
    vtexts, vlab = [v["text"] for v in val], [v["label"] for v in val]
    ours_tok, ours = load_trained(our_dir)
    data = build(ours_tok, seed)
    texts = [c["text"] for c in data["cases"]]
    configs: dict[str, dict[str, Any]] = {}
    for mode, v_logits in score_modes(ours, ours_tok, vtexts, 256, 1).items():
        t = fit_temperature(v_logits, vlab)
        vp = [softmax_pos(lg, t) for lg in v_logits]
        configs[f"parry/{mode}"] = {"temperature": t, "threshold": threshold_for_fpr(vp, vlab)}
    case_logits = score_modes(ours, ours_tok, texts, 256, 1)
    for mode in ("truncated", "chunked"):
        c = configs[f"parry/{mode}"]
        c["probs"] = [softmax_pos(lg, c["temperature"]) for lg in case_logits[mode]]
    del ours
    p_tok, p_model, p_pos = _load_protectai()
    pv = score_modes(p_model, p_tok, vtexts, 512, p_pos)
    pc = score_modes(p_model, p_tok, texts, 512, p_pos)
    for mode in ("truncated", "chunked"):
        vp = [softmax_pos(lg) for lg in pv[mode]]
        probs = [softmax_pos(lg) for lg in pc[mode]]
        configs[f"protectai/{mode}@0.5"] = {"threshold": 0.5, "probs": probs}
        configs[f"protectai/{mode}@tuned"] = {
            "threshold": threshold_for_fpr(vp, vlab),
            "probs": probs,
        }
    from parry.classifier.chunking import window_logits
    from parry.classifier.evaluate import TARGET_FPR

    flags: dict[str, list[bool]] = {
        n: [p >= c["threshold"] for p in c["probs"]] for n, c in configs.items()
    }
    examples: dict[str, Any] = {}
    # exploratory, ours: window probabilities with the chunked-mode temperature
    t_ch = configs["parry/chunked"]["temperature"]
    o_tok, o_model = load_trained(our_dir)
    vw = [[softmax_pos(lg, t_ch) for lg in ws] for ws in window_logits(o_model, o_tok, vtexts, 256)]
    cw = [[softmax_pos(lg, t_ch) for lg in ws] for ws in window_logits(o_model, o_tok, texts, 256)]
    ex = exploratory(vw, vlab, cw, TARGET_FPR)
    flags["parry/chunked+window_adjusted (exploratory)"] = ex["window_adjusted"]
    flags["parry/chunked+top2_mean (exploratory)"] = ex["top2_mean"]
    # the most suspicious benign long documents, with their highest window, for inspection
    benign_idx = [i for i, k in enumerate(data["cases"]) if k["position"] == "none"]
    worst = sorted(benign_idx, key=lambda i: max(cw[i]), reverse=True)[:5]
    wins = {i: windows_text(o_tok, data["cases"][i]["text"], 256) for i in worst}
    examples["parry/chunked"] = [
        {
            "length": data["cases"][i]["length"],
            "top_window_p": round(max(cw[i]), 4),
            "top_window_excerpt": wins[i][max(range(len(cw[i])), key=lambda j: cw[i][j])][:300],
        }
        for i in worst
    ]
    del o_model
    pvw = [
        [softmax_pos(lg) for lg in ws] for ws in window_logits(p_model, p_tok, vtexts, 512, p_pos)
    ]
    pcw = [
        [softmax_pos(lg) for lg in ws] for ws in window_logits(p_model, p_tok, texts, 512, p_pos)
    ]
    pex = exploratory(pvw, vlab, pcw, TARGET_FPR)
    flags["protectai/chunked+window_adjusted (exploratory)"] = pex["window_adjusted"]
    flags["protectai/chunked+top2_mean (exploratory)"] = pex["top2_mean"]
    configs.update({k: {"threshold": None} for k in flags if k not in configs})
    out: dict[str, Any] = {
        "unused_benign_prompts": data["unused_prompts"],
        "note": "Long benign documents are concatenated OASST1 user prompts, which can contain "
        "instruction-like text; some flags on them may reflect that rather than length.",
        "configs": {},
        "most_flagged_benign_examples": examples,
    }
    for name, c in configs.items():
        rows: dict[str, Any] = {}
        for length in LENGTHS:
            for pos in ("none", *POSITIONS):
                idx = [
                    i
                    for i, k in enumerate(data["cases"])
                    if k["length"] == length and k["position"] == pos
                ]
                k = sum(flags[name][i] for i in idx)
                r = wilson_interval(k, len(idx))
                metric = "false_positive" if pos == "none" else "recall"
                rows[f"{length}/{pos}"] = {
                    "metric": metric,
                    "k": k,
                    "n": len(idx),
                    "rate": round(r.point, 4),
                    "low": round(r.low, 4),
                    "high": round(r.high, 4),
                }
        out["configs"][name] = {
            "threshold": c["threshold"],
            "temperature": c.get("temperature"),
            "results": rows,
        }
    return out


def windows_text(tok: Any, text: str, window: int) -> list[str]:
    from parry.classifier.chunking import windows

    return [tok.decode(w, skip_special_tokens=True) for w in windows(tok, text, window)]
