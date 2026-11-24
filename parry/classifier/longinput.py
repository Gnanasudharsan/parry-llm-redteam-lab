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


def _pick(ws: list[list[float]], mode: str) -> list[float]:
    """truncated: the first window only; chunked: the most injection-like window."""
    return ws[0] if mode == "truncated" else max(ws, key=lambda lg: lg[1] - lg[0])


def _free_gpu() -> None:
    import gc

    import torch

    gc.collect()
    if torch.backends.mps.is_available():
        torch.mps.empty_cache()


def run(our_dir: Any, seed: int = SEED, log: Any = print) -> dict[str, Any]:
    """Recall by length and position, and false positives on long benign documents, for our
    classifier (256-token windows; temperature and threshold fit on validation in the same
    mode) and ProtectAI (512-token windows; deployed threshold 0.5 and a threshold tuned on
    validation in the same mode). Each model scores every text once, window by window; the
    truncated, chunked and exploratory rules all come from those window logits."""
    from parry.classifier.chunking import window_logits
    from parry.classifier.evaluate import (
        TARGET_FPR,
        fit_temperature,
        softmax_pos,
        threshold_for_fpr,
    )
    from parry.classifier.train import load_trained
    from parry.metrics import wilson_interval

    val = load_split("val")
    vtexts, vlab = [v["text"] for v in val], [v["label"] for v in val]
    o_tok, o_model = load_trained(our_dir)
    data = build(o_tok, seed)
    cases = data["cases"]
    texts = [c["text"] for c in cases]
    log(f"built {len(cases)} long-input cases from {data['unused_prompts']} unused prompts")

    def score(model: Any, tok: Any, txts: list[str], window: int, pos: int, label: str) -> Any:
        out = window_logits(model, tok, txts, window, pos, batch_size=16)
        log(f"scored {label}: {len(txts)} texts, {sum(len(w) for w in out)} windows")
        return out

    ov = score(o_model, o_tok, vtexts, 256, 1, "ours / validation")
    oc = score(o_model, o_tok, texts, 256, 1, "ours / long-input cases")
    del o_model
    _free_gpu()
    p_tok, p_model, p_pos = _load_protectai()
    pv = score(p_model, p_tok, vtexts, 512, p_pos, "protectai / validation")
    pc = score(p_model, p_tok, texts, 512, p_pos, "protectai / long-input cases")
    del p_model
    _free_gpu()

    flags: dict[str, list[bool]] = {}
    meta: dict[str, dict[str, Any]] = {}
    t_chunked = 1.0
    for mode in ("truncated", "chunked"):
        vl = [_pick(ws, mode) for ws in ov]
        t = fit_temperature(vl, vlab)
        thr = threshold_for_fpr([softmax_pos(lg, t) for lg in vl], vlab)
        probs = [softmax_pos(_pick(ws, mode), t) for ws in oc]
        flags[f"parry/{mode}"] = [p >= thr for p in probs]
        meta[f"parry/{mode}"] = {"temperature": round(t, 4), "threshold": thr}
        if mode == "chunked":
            t_chunked = t
    vw = [[softmax_pos(lg, t_chunked) for lg in ws] for ws in ov]
    cw = [[softmax_pos(lg, t_chunked) for lg in ws] for ws in oc]
    ex = exploratory(vw, vlab, cw, TARGET_FPR)
    flags["parry/chunked+window_adjusted (exploratory)"] = ex["window_adjusted"]
    flags["parry/chunked+top2_mean (exploratory)"] = ex["top2_mean"]
    for mode in ("truncated", "chunked"):
        vp = [softmax_pos(_pick(ws, mode)) for ws in pv]
        probs = [softmax_pos(_pick(ws, mode)) for ws in pc]
        tuned = threshold_for_fpr(vp, vlab)
        flags[f"protectai/{mode}@0.5"] = [p >= 0.5 for p in probs]
        flags[f"protectai/{mode}@tuned"] = [p >= tuned for p in probs]
        meta[f"protectai/{mode}@0.5"] = {"threshold": 0.5}
        meta[f"protectai/{mode}@tuned"] = {"threshold": tuned}
    pvw = [[softmax_pos(lg) for lg in ws] for ws in pv]
    pcw = [[softmax_pos(lg) for lg in ws] for ws in pc]
    pex = exploratory(pvw, vlab, pcw, TARGET_FPR)
    flags["protectai/chunked+window_adjusted (exploratory)"] = pex["window_adjusted"]
    flags["protectai/chunked+top2_mean (exploratory)"] = pex["top2_mean"]

    benign_idx = [i for i, k in enumerate(cases) if k["position"] == "none"]
    worst = sorted(benign_idx, key=lambda i: max(cw[i]), reverse=True)[:5]
    examples = []
    for i in worst:
        wins = windows_text(o_tok, cases[i]["text"], 256)
        j = max(range(len(cw[i])), key=lambda k: cw[i][k])
        examples.append(
            {
                "length": cases[i]["length"],
                "top_window_p": round(cw[i][j], 4),
                "flagged_by_parry_chunked": flags["parry/chunked"][i],
                "top_window_excerpt": wins[j][:300],
            }
        )
    out: dict[str, Any] = {
        "unused_benign_prompts": data["unused_prompts"],
        "note": "Long benign documents are concatenated OASST1 user prompts, which can contain "
        "instruction-like text; some flags on them may reflect that rather than length.",
        "configs": {},
        "most_flagged_benign_examples": {"parry/chunked": examples},
    }
    for name, fl in flags.items():
        rows: dict[str, Any] = {}
        for length in LENGTHS:
            for pos in ("none", *POSITIONS):
                idx = [
                    i for i, k in enumerate(cases) if k["length"] == length and k["position"] == pos
                ]
                k = sum(fl[i] for i in idx)
                r = wilson_interval(k, len(idx))
                rows[f"{length}/{pos}"] = {
                    "metric": "false_positive" if pos == "none" else "recall",
                    "k": k,
                    "n": len(idx),
                    "rate": round(r.point, 4),
                    "low": round(r.low, 4),
                    "high": round(r.high, 4),
                }
        out["configs"][name] = {**meta.get(name, {}), "results": rows}
    return out


def windows_text(tok: Any, text: str, window: int) -> list[str]:
    from parry.classifier.chunking import windows

    return [tok.decode(w, skip_special_tokens=True) for w in windows(tok, text, window)]
