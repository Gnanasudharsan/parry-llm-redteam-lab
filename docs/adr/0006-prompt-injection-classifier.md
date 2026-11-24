# ADR 0006: A small prompt-injection classifier, judged on data it never saw

- Status: accepted
- Date: 2026-11-24

## Context

Phase 3 measured an off-the-shelf injection classifier (ProtectAI DeBERTa-v3-base v2) as a
defense layer. It stopped attacks but also flagged the lab company's own web pages as
injection, costing 5 of 43 benign agent tasks. Phase 4 trains Parry's own classifier. The
question is not only "how accurate on a test split" but "how well does it generalize to
attacks and benign content it was not trained on", at a false-positive rate a deployment can
live with.

## Decision

1. **Data:** only sources whose license is stated on the source page and allows this use
   (Apache-2.0 or MIT), pinned to a revision (`classifier/sources.yaml`). Gated data and data
   without a license are left out. Downloads are scripted; data is never committed.
2. **Held out by design:** Lakera's Gandalf set is a held-out *source* and Parry's own attack
   catalog a held-out set of *attack families*; neither is used for training, tuning,
   calibration or threshold choice. Gandalf-sourced rows inside SPML are dropped from
   training. Over-defense is measured on NotInject (benign prompts with trigger words), the
   lab's benign task messages, and the lab's first-party web pages and documents. Any
   training item whose normalized text appears in a held-out set is removed.
3. **Model:** `microsoft/deberta-v3-small` (MIT) over ModernBERT-base (Apache-2.0): about a
   third of the size, fast enough on Apple Silicon to train three seeds, and the same family
   as the Phase 3 baseline, so the comparison is about data and training rather than
   architecture. Plain PyTorch loop, float32 weights, inputs padded to a fixed 256 tokens.
4. **Calibration and threshold, fixed before results:** temperature scaling fit on the
   validation split (minimum negative log-likelihood); the threshold is the lowest one with a
   benign false-positive rate of at most 1% on calibrated validation probabilities.
5. **Variance:** three seeds (1337, 1338, 1339); seed 1337 is the published model, named
   before training; the others show the spread.
6. **Baseline:** ProtectAI v2 on the same sets, at its deployed threshold (0.5, as in Phase 3)
   and at a threshold tuned on the same validation split to the same 1% false-positive rate.
7. **Tracking:** MLflow, local SQLite store; weights in `classifier/artifacts/`; neither is
   committed. Results (`classifier/results/`) record the commit and the data manifest hash.

## Consequences

- Inputs longer than 256 tokens are truncated: long documents with an injection at the end
  are a known blind spot (as for the baseline at 512).
- English only: the training data is English, and so are the held-out sets.
- A 1% validation false-positive rate is a validation property; the held-out benign sets show
  whether it transfers.
