"""Model-card tables, rendered from the committed result files (no number is typed by hand).

`MODEL_CARD.md` holds the output between `<!-- tables:begin -->` and `<!-- tables:end -->`;
`tests/test_model_card.py` fails if the card and this renderer disagree.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from parry.classifier.evaluate import auroc

RESULTS = Path("classifier/results")
CARD = Path("classifier/MODEL_CARD.md")
SEEDS = ("1337", "1338", "1339")
PUBLISHED = "1337"
BEGIN, END = "<!-- tables:begin -->", "<!-- tables:end -->"
HELD_POS = ("heldout_gandalf", "heldout_parry_attacks")
HELD_NEG = ("heldout_notinject", "heldout_parry_benign", "heldout_lab_content")


def _load(name: str) -> Any:
    return json.loads((RESULTS / name).read_text())


def _pct(x: float) -> str:
    return f"{100 * x:.1f}%"


def _cell(r: dict[str, Any]) -> str:
    return f"{_pct(r['rate'])} ({r['k']}/{r['n']})"


def _ci(r: dict[str, Any]) -> str:
    return f"{_pct(r['rate'])} [{_pct(r['low'])}, {_pct(r['high'])}]"


def _spread(vals: list[float], pct: bool = True) -> str:
    f = _pct if pct else (lambda v: f"{v:.3f}")
    return f"{f(sum(vals) / len(vals))} [{f(min(vals))}-{f(max(vals))}]"


def _pooled_auroc(sets: dict[str, Any]) -> float:
    probs = [p for s in HELD_POS for p in sets[s]["probs"]]
    probs += [p for s in HELD_NEG for p in sets[s]["probs"]]
    labels = [1] * sum(len(sets[s]["probs"]) for s in HELD_POS)
    labels += [0] * sum(len(sets[s]["probs"]) for s in HELD_NEG)
    a = auroc(probs, labels)
    if a is None:
        raise ValueError("pooled held-out sets need both labels")
    return a


ROWS = (
    ("test", "detection", "Test split: detection"),
    ("test", "false_positive", "Test split: false positives"),
    ("test", "auroc", "Test split: AUROC"),
    ("heldout_gandalf", "detection", "Gandalf (held-out source): detection"),
    ("heldout_parry_attacks", "detection", "Parry attacks (held-out families): detection"),
    ("heldout_notinject", "false_positive", "NotInject (trigger words): false positives"),
    ("heldout_parry_benign", "false_positive", "Lab benign tasks: false positives"),
    ("heldout_lab_content", "false_positive", "Lab pages and documents: false positives"),
    ("pooled", "auroc", "All held-out sets pooled: AUROC"),
)


def _value(sets: dict[str, Any], set_name: str, metric: str) -> float:
    if set_name == "pooled":
        return _pooled_auroc(sets)
    v = sets[set_name][metric]
    return float(v if metric == "auroc" else v["rate"])


def main_table(ev: dict[str, Any]) -> str:
    ours = {s: ev["seeds"][s]["sets"] for s in SEEDS}
    pa = {k: ev["protectai"][k]["sets"] for k in ("deployed_0.5", "tuned_val_fpr")}
    lines = [
        "| metric | v1 seed 1337 (published) | v1, 3 seeds: mean [min-max] | ProtectAI @0.5 "
        "| ProtectAI @tuned |",
        "|---|---|---|---|---|",
    ]
    for set_name, metric, label in ROWS:
        if metric == "auroc":
            pub = f"{_value(ours[PUBLISHED], set_name, metric):.3f}"
            spread = _spread([_value(ours[s], set_name, metric) for s in SEEDS], pct=False)
            base = [f"{_value(pa[k], set_name, metric):.3f}" for k in pa]
        else:
            pub = _ci(ours[PUBLISHED][set_name][metric])
            spread = _spread([_value(ours[s], set_name, metric) for s in SEEDS])
            base = [_ci(pa[k][set_name][metric]) for k in pa]
        lines.append(f"| {label} | {pub} | {spread} | {base[0]} | {base[1]} |")
    thr = [ev["seeds"][s]["threshold"] for s in SEEDS]
    temps = [ev["seeds"][s]["temperature"] for s in SEEDS]
    lines += [
        "",
        f"Thresholds (calibrated p(injection), chunked): seed 1337 "
        f"{ev['seeds'][PUBLISHED]['threshold']:.4f}; seeds {', '.join(f'{t:.4f}' for t in thr)}. "
        f"Temperatures {', '.join(f'{t:.2f}' for t in temps)}. ProtectAI tuned threshold "
        f"{ev['protectai']['tuned_val_fpr']['threshold']:.4f}. Validation ECE, seed 1337: "
        f"{ev['seeds'][PUBLISHED]['ece_val']['before']:.4f} before, "
        f"{ev['seeds'][PUBLISHED]['ece_val']['after']:.4f} after temperature scaling.",
    ]
    return "\n".join(lines)


def family_table(ev: dict[str, Any]) -> str:
    fam = {s: ev["seeds"][s]["sets"]["heldout_parry_attacks"]["by_family"] for s in SEEDS}
    pa = {
        k: ev["protectai"][k]["sets"]["heldout_parry_attacks"]["by_family"]
        for k in ("deployed_0.5", "tuned_val_fpr")
    }
    lines = [
        "| attack family (n) | v1 seed 1337 | v1, 3 seeds (detected) | ProtectAI @0.5 "
        "| ProtectAI @tuned |",
        "|---|---|---|---|---|",
    ]
    for key in sorted(fam[PUBLISHED]):
        n = fam[PUBLISHED][key]["n"]
        ks = [fam[s][key]["k"] for s in SEEDS]
        lines.append(
            f"| {key.split(':')[0]} ({n}) | {fam[PUBLISHED][key]['k']}/{n} | "
            f"{', '.join(map(str, ks))} | {pa['deployed_0.5'][key]['k']}/{n} | "
            f"{pa['tuned_val_fpr'][key]['k']}/{n} |"
        )
    return "\n".join(lines)


LONG_CONFIGS = (
    ("parry/truncated", "v1, truncated to 256 tokens"),
    ("parry/chunked", "v1, chunked (any window)"),
    ("parry/chunked+window_adjusted (exploratory)", "v1, window-adjusted threshold *"),
    ("parry/chunked+top2_mean (exploratory)", "v1, top-2 window mean *"),
    ("protectai/truncated@0.5", "ProtectAI, truncated to 512, @0.5"),
    ("protectai/chunked@0.5", "ProtectAI, chunked, @0.5"),
    ("protectai/chunked@tuned", "ProtectAI, chunked, @tuned"),
    ("protectai/chunked+window_adjusted (exploratory)", "ProtectAI, window-adjusted *"),
    ("protectai/chunked+top2_mean (exploratory)", "ProtectAI, top-2 window mean *"),
)


def long_tables(li: dict[str, Any], extra: dict[str, dict[str, Any]]) -> str:
    out = []
    for length in (1024, 2048, 4096):
        out += [
            f"**{length:,}-token documents** (100 per cell; false positives on the same "
            "documents without an injection)",
            "",
            "| config | false positives | recall, start | recall, middle | recall, end |",
            "|---|---|---|---|---|",
        ]
        for key, label in LONG_CONFIGS:
            r = li["configs"][key]["results"]
            cells = [_cell(r[f"{length}/{p}"]) for p in ("none", "start", "middle", "end")]
            out.append(f"| {label} | {' | '.join(cells)} |")
        out.append("")
    out.append("\\* exploratory, not used for any decision.")
    if extra:
        seeds = [PUBLISHED, *sorted(extra)]
        runs = {PUBLISHED: li, **extra}
        out += [
            "",
            f"**v1 across seeds {', '.join(seeds)}**: mean [min-max] (ProtectAI does not "
            "depend on the seed)",
            "",
            "| config | length | false positives | recall, start | recall, middle | recall, end |",
            "|---|---|---|---|---|---|",
        ]
        for key, label in LONG_CONFIGS[:4]:
            for length in (1024, 2048, 4096):
                cells = [
                    _spread(
                        [runs[s]["configs"][key]["results"][f"{length}/{p}"]["rate"] for s in seeds]
                    )
                    for p in ("none", "start", "middle", "end")
                ]
                out.append(f"| {label} | {length:,} | {' | '.join(cells)} |")
    return "\n".join(out)


def examples(li: dict[str, Any]) -> str:
    lines = [
        "| length | top window p | excerpt of the window (first 120 characters) |",
        "|---|---|---|",
    ]
    for ex in li["most_flagged_benign_examples"]["parry/chunked"]:
        text = " ".join(ex["top_window_excerpt"].split())[:120].replace("|", "\\|")
        lines.append(f"| {ex['length']:,} | {ex['top_window_p']:.3f} | {text} |")
    return "\n".join(lines)


def render() -> str:
    ev = _load("phase4-eval.json")
    li = _load("phase4-longinput.json")
    extra = {
        s: _load(f"phase4-longinput-seed{s}.json")
        for s in SEEDS[1:]
        if (RESULTS / f"phase4-longinput-seed{s}.json").exists()
    }
    parts = [
        BEGIN,
        "### Main results (95% Wilson intervals; v1 uses chunked inference)",
        "",
        main_table(ev),
        "",
        "### Held-out Parry attack families (detected / n)",
        "",
        family_table(ev),
        "",
        "### Long inputs",
        "",
        long_tables(li, extra),
        "",
        "### Benign long documents v1 flagged most (seed 1337, chunked)",
        "",
        examples(li),
        END,
    ]
    return "\n".join(parts)


def write() -> None:
    text = CARD.read_text()
    a, b = text.index(BEGIN), text.index(END) + len(END)
    CARD.write_text(text[:a] + render() + text[b:])
