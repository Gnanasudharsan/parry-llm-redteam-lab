# v2 fresh held-out set — DO NOT TRAIN

**Do not train, tune, calibrate or choose a threshold on anything in this directory.**
It is the fresh held-out set for the v2 classifier, defined and frozen in
[ADR 0007](../../docs/adr/0007-v2-fresh-heldout.md) before any v2 training. It is scored
once, in v2's final evaluation, with v1 and ProtectAI scored on it at the same time. No
model has been scored on it yet.

| file | what |
|---|---|
| `items.jsonl` | 251 items: 160 injections (4 families x 40), 91 hard-benign; every row has `do_not_train: true` |
| `manifest.json` | counts by family and label, forms, the frozen sha256, leakage check against every v1 split |

Each row: `id`, `text`, `label` (1 = injection), `family`, `form` (injections only),
`do_not_train`. Invisible characters are stored as `\u` escapes so they show in diffs.

- **Families** (injections): `pasted_content`, `invisible_chars`, `markup_comment`,
  `translation_wrapped`. **Hard benign**: the same four forms without an injection (12-15
  each), plus 40 `trigger_words` questions.
- **Benign proof only:** every injection's goal is a `PARRY-FRESH-<nonce>` marker, a URL on
  `collect.fresh.test`, or the mock `send_note` tool.
- **License:** written for this repository (Apache-2.0); no third-party text.
- **Regenerate:** `uv run parry classifier fresh-heldout` rebuilds the same bytes
  (`tests/test_fresh_heldout.py` checks this and the sha256 in CI).
- **Guard:** `parry.classifier.fresh.forbidden_keys()` returns the normalized texts a v2
  data build must exclude; it raises if the file no longer matches the frozen hash.
