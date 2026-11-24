"""Build the classifier's train / validation / test splits and held-out evaluation sets.

Training pool (labeled, 1 = prompt injection):
  - deepset/prompt-injections (Apache-2.0): both labels.
  - SPML (MIT): both labels; rows whose `Source` is Gandalf are dropped, because Lakera's
    Gandalf set is a held-out source. Positives are capped so one generator's style does not
    dominate.
  - OASST1 prompts (Apache-2.0): English first-turn user prompts, all benign.
The pool is split 80 / 10 / 10, stratified by (source, label), with a fixed seed.

Held-out sets (never trained or tuned on):
  - gandalf: Lakera/gandalf_ignore_instructions (MIT), all injections: a held-out source.
  - parry_attacks: Parry's own attack catalog (one item per case; multi-turn turns joined),
    tagged by attack family: held-out families.
  - notinject: leolee99/NotInject (MIT), benign prompts with trigger words: over-defense.
  - parry_benign: the lab apps' benign task messages.
  - lab_content: the lab's first-party web pages and RAG documents, by paragraph: benign
    untrusted content (the case the ProtectAI classifier flagged in Phase 3).

Any training-pool item whose normalized text also appears in a held-out set is removed, and
duplicates inside the pool are dropped; the counts are recorded in the manifest.
"""

from __future__ import annotations

import csv
import gzip
import hashlib
import html
import json
import random
import re
from collections import Counter
from pathlib import Path
from typing import Any

import yaml

EXTERNAL = Path("datasets/external")
SPLITS = EXTERNAL / "splits"
MANIFEST = Path("classifier/data-manifest.json")
SEED = 1337
SPML_POSITIVE_CAP = 4000
OASST_SAMPLE = 4000
MIN_CHARS, MAX_CHARS = 8, 4000

Item = dict[str, Any]


def normalize(text: str) -> str:
    return re.sub(r"\s+", " ", re.sub(r"[^\w\s]", " ", text.lower())).strip()


def _item(text: str, label: int, source: str, **extra: Any) -> Item:
    return {"text": text.strip(), "label": label, "source": source, **extra}


def _parquet(path: Path) -> list[dict[str, Any]]:
    import pyarrow.parquet as pq

    rows: list[dict[str, Any]] = pq.read_table(path).to_pylist()
    return rows


def _dir(dataset_id: str) -> Path:
    return EXTERNAL / dataset_id.replace("/", "__")


def load_deepset() -> list[Item]:
    d = _dir("deepset/prompt-injections") / "data"
    rows = [r for f in sorted(d.glob("*.parquet")) for r in _parquet(f)]
    return [_item(r["text"], int(r["label"]), "deepset") for r in rows]


def load_spml(rng: random.Random) -> tuple[list[Item], dict[str, int]]:
    csv.field_size_limit(10**8)
    path = _dir("reshabhs/SPML_Chatbot_Prompt_Injection") / "spml_prompt_injection.csv"
    with path.open(newline="") as f:
        rows = list(csv.DictReader(f))
    kept = [r for r in rows if r["Source"].strip().lower() != "gandalf"]
    pos = [r for r in kept if r["Prompt injection"] == "1"]
    neg = [r for r in kept if r["Prompt injection"] == "0"]
    pos = rng.sample(pos, min(SPML_POSITIVE_CAP, len(pos)))
    stats = {
        "rows": len(rows),
        "dropped_gandalf_source": len(rows) - len(kept),
        "pos_kept": len(pos),
        "neg_kept": len(neg),
    }
    items = [_item(r["User Prompt"], 1, "spml", degree=int(r["Degree"])) for r in pos]
    items += [_item(r["User Prompt"], 0, "spml", degree=0) for r in neg]
    return items, stats


def load_oasst(rng: random.Random) -> list[Item]:
    path = _dir("OpenAssistant/oasst1") / "2023-04-12_oasst_prompts.messages.jsonl.gz"
    with gzip.open(path, "rt") as f:
        rows = [json.loads(line) for line in f]
    en = [
        r
        for r in rows
        if r.get("lang") == "en" and not r.get("deleted") and r.get("parent_id") is None
    ]
    pick = rng.sample(en, min(OASST_SAMPLE, len(en)))
    return [_item(r["text"], 0, "oasst") for r in pick]


def load_gandalf() -> list[Item]:
    d = _dir("Lakera/gandalf_ignore_instructions") / "data"
    return [
        _item(r["text"], 1, "gandalf") for f in sorted(d.glob("*.parquet")) for r in _parquet(f)
    ]


def load_notinject() -> list[Item]:
    d = _dir("leolee99/NotInject") / "data"
    return [
        _item(r["prompt"], 0, "notinject", category=r.get("category"))
        for f in sorted(d.glob("NotInject_*.parquet"))
        for r in _parquet(f)
    ]


def load_parry_attacks(seed: int = SEED) -> list[Item]:
    from parry.attacks.catalog import expand, load_templates

    out = []
    for c in expand(load_templates(), seed):
        text = c.payload if isinstance(c.payload, str) else "\n".join(c.payload)
        out.append(
            _item(
                text, 1, "parry_attacks", family=c.family, channel=str(c.channel), case_id=c.case_id
            )
        )
    return out


def load_parry_benign() -> list[Item]:
    out = []
    for f in sorted(Path("targets/benign").glob("*.yaml")):
        for t in yaml.safe_load(f.read_text())["tasks"]:
            texts = [t["message"]] if t.get("message") else []
            for call in t.get("calls", []):
                texts += [
                    str(v) for v in (call.get("arguments") or {}).values() if isinstance(v, str)
                ]
            out += [_item(x, 0, "parry_benign", task=t["id"], app=f.stem) for x in texts]
    return out


def load_lab_content() -> list[Item]:
    out = []
    for f in sorted(Path("targets/mockweb/pages").glob("*.html")):
        text = html.unescape(re.sub(r"<[^>]+>", "\n", f.read_text()))
        out += [
            _item(p, 0, "lab_content", doc=f.name)
            for p in re.split(r"\n\s*\n", text)
            if len(p.strip()) >= 40
        ]
    for f in sorted(Path("targets/rag/corpus").glob("*.md")):
        out += [
            _item(p, 0, "lab_content", doc=f.name)
            for p in re.split(r"\n\s*\n", f.read_text())
            if len(p.strip()) >= 40
        ]
    return out


def _ok(it: Item) -> bool:
    return MIN_CHARS <= len(it["text"]) <= MAX_CHARS


def build(seed: int = SEED) -> dict[str, Any]:
    rng = random.Random(seed)  # noqa: S311 - reproducible sampling
    heldout = {
        "gandalf": load_gandalf(),
        "parry_attacks": load_parry_attacks(seed),
        "notinject": load_notinject(),
        "parry_benign": load_parry_benign(),
        "lab_content": load_lab_content(),
    }
    held_keys = {normalize(it["text"]) for items in heldout.values() for it in items}
    spml, spml_stats = load_spml(rng)
    pool_raw = load_deepset() + spml + load_oasst(rng)
    removed: Counter[str] = Counter()
    seen: set[str] = set()
    pool: list[Item] = []
    for it in pool_raw:
        key = normalize(it["text"])
        if not _ok(it):
            removed["length"] += 1
        elif key in held_keys:
            removed[f"overlaps_heldout:{it['source']}"] += 1
        elif key in seen:
            removed[f"duplicate:{it['source']}"] += 1
        else:
            seen.add(key)
            pool.append(it)
    # stratified 80/10/10 by (source, label)
    strata: dict[tuple[str, int], list[Item]] = {}
    for it in pool:
        strata.setdefault((it["source"], it["label"]), []).append(it)
    splits: dict[str, list[Item]] = {"train": [], "val": [], "test": []}
    for stratum in sorted(strata):
        items = strata[stratum]
        rng.shuffle(items)
        n = len(items)
        a, b = round(n * 0.8), round(n * 0.9)
        splits["train"] += items[:a]
        splits["val"] += items[a:b]
        splits["test"] += items[b:]
    for name in splits:
        rng.shuffle(splits[name])
    SPLITS.mkdir(parents=True, exist_ok=True)
    manifest: dict[str, Any] = {
        "seed": seed,
        "spml": spml_stats,
        "removed": dict(removed),
        "sets": {},
    }
    for name, items in {**splits, **{f"heldout_{k}": v for k, v in heldout.items()}}.items():
        path = SPLITS / f"{name}.jsonl"
        path.write_text("".join(json.dumps(it, ensure_ascii=False) + "\n" for it in items))
        manifest["sets"][name] = {
            "n": len(items),
            "by_source_label": {
                f"{s}:{lab}": c
                for (s, lab), c in sorted(Counter((i["source"], i["label"]) for i in items).items())
            },
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        }
    MANIFEST.write_text(json.dumps(manifest, indent=2) + "\n")
    return manifest


def load_split(name: str) -> list[Item]:
    return [json.loads(x) for x in (SPLITS / f"{name}.jsonl").read_text().splitlines() if x]
