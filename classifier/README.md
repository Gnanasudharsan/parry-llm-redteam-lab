# Prompt-injection classifier

Phase 4: a small encoder (DeBERTa-v3-small) fine-tuned on licensed data to flag prompt
injection, tracked in MLflow, evaluated on held-out sources and attack families, with a model
card for the Hugging Face Hub. Weights are never committed to this repo.

> **Recommendation:** the v1 classifier is strong on data like its training data and poor on
> attack families it did not see (see [MODEL_CARD.md](MODEL_CARD.md)). Until a version
> generalizes, keep ProtectAI's `deberta-v3-base-prompt-injection-v2` as Parry's
> `pi_classifier` defense (the default in `parry guard serve`).

| file | what |
|---|---|
| `sources.yaml` | pinned datasets and base model, with licenses |
| `data-manifest.json` | split sizes by source and label, sha256 of every split, removal counts |
| `results/phase4-eval.json` | all seeds and the ProtectAI baseline on every set |
| `results/phase4-longinput.json` | long-input evaluation (records `git_dirty: true`: the only tracked change during the run was the T-004 note in `docs/deviations.md`; the code that ran is `bfe674a`) |
| `MODEL_CARD.md` | model card (Hugging Face Hub) |

Reproduce: `parry classifier fetch`, `build`, `train`, `evaluate`, `longinput`
(see [ADR 0006](../docs/adr/0006-prompt-injection-classifier.md)).
