# Deviations log

Every time a reported measurement had to be redone, discarded or qualified, it is logged
here: what went wrong, how it was found, what was changed, and which runs replace which.
Archived runs are kept under [`evals/results/archive/`](../evals/results/archive) and are
never mixed into reported numbers.

## D-001: Output validator matched the word "staff" (Phase 3)

- **Found:** 2026-11-23, while reading the first completed matrix cells (vuln-mcp). Three
  benign MCP tasks (`ask-hiring-store`, `ask-hiring-count`, `ask-hiring-type`) were refused by
  `output_validator` in both the `output_validator` and `hardened+guards` configurations.
- **Cause:** validator version 1 treated each secret format as a literal prefix. Separators
  are stripped so spaced-out secrets still match, which reduced `STAFF-` to the plain word
  `staff`. Any answer mentioning "seasonal staff" was refused.
- **Fix:** commit `6f8055a`, output_validator version 2. Each format is a prefix plus a
  required body of N hex characters, still tolerant of separators. Regression tests added in
  `tests/test_defenses.py`.
- **Scope of the code change:** the only file the lab containers run that changed between the
  matrix commit (`3b4ed31`) and the fix is `parry/defenses/layers.py`. `OutputValidator` is
  constructed only by `make_stack` when a configuration lists `output_validator`; only the
  `output_validator` and `hardened+guards` configurations do. Every result now records the
  layer versions and the commit (`defense_versions`, `validator_version`, `git_commit`).
- **Runs redone:** _filled in after the reruns_ (see below).
- **Archived:** _filled in after the reruns_.

## D-002: Llama Guard calls had no fixed seed (Phase 3)

- **Found:** 2026-11-23, auditing every Ollama call for temperature 0 and a fixed seed (a
  condition set by the owner for the reruns). Target models and the LLM judge set both;
  the Llama Guard layer set `temperature: 0` but no `seed`.
- **Fix:** commit `efd8fa5`. The layer passes `seed` (from `LAB_MODEL_SEED`, default 1337),
  and its recorded version is `ollama:llama-guard3:1b@seed=1337`.
- **Runs redone:** the `llama_guard` configuration on all three apps, because the code
  behind it changed. `hardened+guards` is rerun anyway under D-001. Old cells are archived.

## D-003: A commit landed with a failing test (Phase 3)

- **What happened:** commit `991d62a` ("record defense layer versions") was made while
  `tests/test_pareto.py::test_render` failed. The command was `uv run pytest -q | tail -1
  && git commit ...`; without `pipefail` the pipeline's exit status is `tail`'s, which is 0.
- **Impact:** test-only. The failing assertion was in the new test fixture, not in shipped
  behavior; it was fixed in the next commit `c745aac`. No reported result was produced
  from `991d62a`.
- **Fix:** test-then-commit commands now run with `set -o pipefail`. The pre-commit hook
  still runs ruff and mypy; CI runs the full test suite on every push.

## Checked, no rerun needed: OpenAI-compatible adapter seed (Phase 3)

Commit `efd8fa5` also made `OpenAICompatAdapter` send a fixed seed. It is not on the path of
any matrix cell: all six lab targets are `kind: http` or `kind: mcp_http`, which
`make_adapter` routes to `HttpChatAdapter` and `McpAdapter`; `OpenAICompatAdapter` is only
built for `kind: openai_compat`, and nothing else (judges, guards, garak) uses it.

## Spot-check design (bridge between original and rerun cells)

Two unaffected configurations per app are rerun at the new commit and compared with the
original cells at `3b4ed31`:

1. `none`, a pure baseline-noise check (every configuration imports `layers.py`).
2. `pi_classifier`, the only unaffected configuration that builds and calls a layer from
   `parry/defenses/layers.py` (`PromptInjectionClassifier`) and runs the shared
   `make_stack -> DefenseStack.check -> timed -> Runtime.guard` path. `acl` and spotlighting
   are hardening flags that never touch `layers.py`.

Both must pass: (a) zero `OutputValidator` constructions and calls in the trace, and (b)
per-case verdict changes within the Phase 2 noise allowance and overlapping ASR intervals
(`parry matrix-compare`). If either fails for any app, the full matrix is rerun.

## Tooling note T-001: progress output and stale estimates (Phase 3)

- **Report:** status updates during the Phase 3 matrix repeated an estimate of about 2.5
  hours remaining across several updates.
- **What it was:** the estimate itself was stale; it was restated instead of recomputed from
  completed cells. The progress log was not materially behind: `typer.echo` flushes each
  line, and the log matched the result files within one cell. (An earlier status message
  blamed log buffering; that was wrong and is corrected here.)
- **Fix:** progress is now reported from the result files on disk (cells completed, cases per
  cell, minutes per cell, errors and retries). For future runs the Makefile exports
  `PYTHONUNBUFFERED=1`, and the engine and matrix default progress printers pass
  `flush=True`, so piped logs are line-current from the first line.

## Retry rule (from Phase 3 on)

A case or benign task that ends in an error (transport failure, timeout, crash) is retried
once after the rest of its cell, with the same seed and nonce. Both attempts are kept in
`trials.jsonl` / `benign.jsonl` (`attempt: 1` and `attempt: 2`); rates use the latest
attempt; `run.json` lists `retried` and `failed_after_retry` per target. Cases that still
fail are reported, never dropped.

## Known non-determinism (context for D-001)

Two identical Phase 2 runs (same commit, seed, model, catalog) gave byte-identical replies on
246 of 256 trials and one changed verdict. Ollama inference is not bit-for-bit deterministic
at temperature 0 with a fixed seed. A spot-check that reruns an unaffected configuration can
therefore differ for reasons that have nothing to do with a code change.
