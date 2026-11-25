# Phase 4: Parry's prompt-injection classifier (v1)

v1 is a DeBERTa-v3-small fine-tuned on licensed data (deepset, SPML, OASST1), calibrated on
validation, and judged on held-out sources and attack families it never saw. The full
results, with all three seeds, ProtectAI alongside, and the long-input evaluation, are in
the model card: [classifier/MODEL_CARD.md](../classifier/MODEL_CARD.md). Decisions: ADR
[0006](adr/0006-prompt-injection-classifier.md) (v1) and [0007](adr/0007-v2-fresh-heldout.md)
(v2's fresh held-out set).

**Verdict: strong in-distribution, poor generalization to unseen attack families.**
ProtectAI's `deberta-v3-base-prompt-injection-v2` stays Parry's recommended and default
`pi_classifier` defense until a classifier of Parry's own generalizes.

## Token lengths

`uv run parry classifier lengths` ([results](../classifier/results/phase4-lengths.json)):
tokens of the classifier's tokenizer, without special tokens; "over" = does not fit one
256-token window (more than 254 text tokens).

| set | n | median | p95 | max | over 256 | of which injections |
|---|---|---|---|---|---|---|
| train | 9,585 | 23 | 299 | 864 | 970 (10.1%) | 945 |
| validation | 1,198 | 24 | 288 | 650 | 114 (9.5%) | 111 |
| test | 1,198 | 23 | 286 | 439 | 107 (8.9%) | 105 |
| Gandalf | 1,000 | 11 | 33 | 96 | 0 | 0 |
| Parry attacks | 84 | 28 | 65 | 115 | 0 | 0 |
| NotInject | 339 | 19 | 34 | 55 | 0 | 0 |
| lab benign tasks | 141 | 9 | 23 | 29 | 0 | 0 |
| lab pages and documents | 29 | 45 | 81 | 89 | 0 | 0 |

Almost every long training item is an injection (943 of the 945 from SPML), so length is a
confound: the owner chose to measure its effect (the long-input evaluation) before any
retraining. It shows up as chunked false positives that rise with document length.

## Reproduce

```bash
uv run parry classifier fetch && uv run parry classifier build
uv run parry classifier train          # seeds 1337, 1338, 1339 (MLflow, local SQLite)
uv run parry classifier evaluate       # classifier/results/phase4-eval.json
uv run parry classifier longinput      # seed 1337 with ProtectAI
uv run parry classifier longinput --seed 1338 --no-baseline \
  --out classifier/results/phase4-longinput-seed1338.json
uv run parry classifier lengths
uv run parry classifier card           # model-card tables from the result files
```

## v2 (follow-up, not started)

Planned in [docs/requests.md](requests.md) (follow-up F5) against the fresh held-out set
frozen in ADR 0007 (`datasets/v2-heldout/`, do not train). v1's held-out sets count as
"previously seen" for v2.
