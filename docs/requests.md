# Requests ledger

Every instruction the owner gave from Phase 3 on, with its status and what satisfies it.
Re-read at the start of every session and after any context compaction; update as items
close. Status: **done**, **in progress**, **pending**, **withdrawn**.
Last updated: 2026-11-24 (Phase 3 release).

## Scope (Phase 3 spec)

| # | Request | Status | Satisfied by |
|---|---|---|---|
| S1 | Each defense as a composable layer | done | `93b2302`, `fd91a2d` (`parry/defenses/`, `PUT /_lab/config`) |
| S2 | Run the full defense matrix | done | `3b4ed31`; `runs/matrix-20261123T212651Z` (42/42 cells, 0 errors) |
| S3 | Report ASR reduction, false-positive rate, utility retained, latency/cost | done | `evals/results/phase3-matrix/matrix.md`; docs/defenses.md |
| S4 | Pareto chart | done | `evals/results/phase3-matrix/pareto.svg` (latency on frontier labels) |
| S5 | Benchmark against garak: what each finds that the other misses, including where garak beats Parry | done | `evals/results/phase3-garak/`; docs/defenses.md "Baseline scanner: garak"; F-004 |
| S6 | Results matrix in the README; hardened twins show measured improvement | done | README Phase 3 section; `hardened` supported in all three apps |
| S7 | End of phase: README status, CHANGELOG, `chore(release): complete phase 3 — …`, tag `phase-3`, push | done | `chore(release): complete phase 3 — defense evaluation`, tag `phase-3` |

## Plan-approval conditions

| # | Request | Status | Satisfied by |
|---|---|---|---|
| C1 | Spot-check bridge: `none` + `pi_classifier` per app; (a) zero OutputValidator constructions/calls, (b) verdict changes within noise allowance and overlapping CIs; rerun the full matrix if either fails | done (all six pass) | `ab36953` (`matrix-compare`), `82b0a88`, `232a131`; results in `docs/deviations.md` "Spot-check design" (`de3b41c`) |
| C2 | Validator version and commit SHA in every results file; log bug, fix and redone runs in deviations | done | `991d62a`, `efd8fa5`, `de3b41c`; D-001/D-002 filled; per-cell code vs recorded commit in `SOURCES.json` (D-005) |
| C3 | Discard buggy-validator results; archive under `evals/results/archive/`; never mix | done | `evals/results/archive/phase3-original-superseded/` (9 cells); final matrix `evals/results/phase3-matrix/` |
| C4 | Same seeds, model versions and benign task set | done | seed 1337, `qwen2.5:7b-instruct`, same benign sets; digests in provenance (D-005 for originals) |
| C5 | Groq run | withdrawn for targets/attacks (no hosted APIs); retry-then-report rule kept. Hosted labelers only, by later decision: X-001 / L12 | retry rule `f23a121` |
| C6 | garak on the same targets; garak's detectors and Parry's judges re-scoring garak's responses against the lab canaries | done | garak detectors + Parry re-judging; both / Parry-only / garak-only per target |
| C7 | Temperature 0 and a fixed seed on every Ollama call | done | `efd8fa5` (D-002) |
| C8 | Record the Ollama version and model digests | done | `efd8fa5` (`parry/provenance.py`) |
| C9 | Report measured nondeterminism (246/256 identical, 1 flip) as a known limitation | done | docs/defenses.md Limitations |
| C10 | Rerun `output_validator`, `hardened+guards`, `llama_guard` on all three apps | done | `runs/matrix-20261124T024429Z` (9/9, commit `7a14edc`), R-001 |
| C11 | Write-up: exact commit per cell (originals `3b4ed31`, reruns, spot-checks as bridge) | done | docs/defenses.md Setup; `SOURCES.json` |
| C12 | Write-up: engine changed between original cells and reruns (retry rule `f23a121`); spot-checks bridge it | done | docs/defenses.md Setup |
| C13 | Confirm the OpenAI-compatible adapter seed is off the matrix path | done | `82b0a88` (deviations) |

## Process

| # | Request | Status | Satisfied by |
|---|---|---|---|
| P1 | Progress from result files on disk (cells, cases, time per cell, errors, retries); stop and tell the owner if a cell is stuck or retrying | in progress (standing) | T-001 (`f23a121`) |
| P2 | Retry rule: errored case/benign task retried once after the cell, same seed; report both attempts | done | `f23a121` |
| P3 | Fix log buffering (`PYTHONUNBUFFERED=1`, `flush=True`) and log it as a tooling note | done | `f23a121` (T-001) |
| P4 | Never silence commit output; check the exit code before reporting a commit; note under D-003 | done (standing) | `a14abc1` |
| P5 | `set -o pipefail` for test-then-commit | done (standing) | D-003 |
| P6 | Interim numbers stay out of the README and write-up until the spot-checks pass and the reruns finish | done | numbers entered the README and write-up only after the spot-checks passed and the reruns finished |
| P7 | Show the matrix while it runs | done | reported in chat |
| P8 | Explain every "(1 failed)" step and whether it affected a commit | done (standing) | reported in chat for each update |
| P9 | Draw the sample and rerun the v2-diff only after the matrix process exits; analysis refuses cells without a completion marker | done | `e0b7354` (T-002) |
| P10 | Keep >= 15 GB free before the reruns; prune only dangling images and build cache; remove labeler models after the panel if space is short; pause before any step that could fill the disk | in progress (standing) | 13 GB -> 20 GB free (not a commit) |
| P11 | Do not start the reruns until all six spot-checks are confirmed passing | done | all six pass (`de3b41c`) |
| P12 | Requests ledger in `docs/requests.md`; re-read each session and after compaction; update and commit | done (standing) | this file |
| P13 | Back up uncommitted work without touching HEAD (`git diff` patch + untracked copies) | done | `~/parry-uncommitted-20261123-2315.patch` + `-untracked/`; refreshed at 23:17 (`~/parry-uncommitted-20261123-2317.*`) |
| P14 | Responsible scope for baselines: no harmful payloads reach any target (garak encoding probes defaulted to slur terms; D-006) | done (standing) | `parry/baselines/garak.py` pinned payloads + offline preflight |
| P15 | Every shell pipeline uses `set -o pipefail` (standing); log the repeat slip as a process note | done (standing) | CLAUDE.md "How to work"; deviations T-003 |
| P16 | Restart the lab containers (`make targets-up`) before Phases 5 and 6 (they were stopped during Phase 4 training to free memory) | pending | |

## Analysis (final data only)

| # | Request | Status | Satisfied by |
|---|---|---|---|
| A1 | Exact McNemar paired tests (each config vs `none`, hardened vs hardened+guards) with flip counts | done | final run on `evals/results/phase3-matrix` (`analysis.json`); docs/defenses.md |
| A2 | Holm-Bonferroni within each app; raw and adjusted p; "supported" = adjusted p < 0.05; don't rank unsupported differences | done | final run on `evals/results/phase3-matrix` (`analysis.json`); docs/defenses.md |
| A3 | Judge-artifact check for `redact_output` and `sanitize_markdown` | done | final run on `evals/results/phase3-matrix` (`analysis.json`); docs/defenses.md |
| A4 | Leak judge v2 applied to every cell; old and new numbers | done | final run on `evals/results/phase3-matrix` (`analysis.json`); docs/defenses.md |
| A5 | Threshold sensitivity at 1/2, 2/3, full; state whether any conclusion changes | done | final run on `evals/results/phase3-matrix` (`analysis.json`); docs/defenses.md |
| A6 | FP controls: cross-secret control and v2 on benign replies; minimum fragment >= 8 with a chance-match justification; tighten and log if FP | done | `24d003a`, `bce78ae` (J-001) |
| A7 | Utility (benign pass rate) next to ASR for every cell, on the Pareto chart with latency overhead; call out defenses that cost benign tasks | done | final run on `evals/results/phase3-matrix` (`analysis.json`); docs/defenses.md |
| A8 | Confirm J-001 committed (git log, exit code) | done | `bce78ae` |
| A9 | Baseline exposure: ASR as now and excluding goals whose secret a benign task exposes; which secrets/configs; whether conclusions change, especially `secrets_out_of_prompt` | done | A-001; no supported conclusion changes, incl. `secrets_out_of_prompt` |
| A10 | List every v2-positive/v2.1-negative trial for review, with fragments; count the 12-char split cases | done | `3cc9189` (`datasets/judge-labels/leak-v2-diff.*`): 13 cases, 0 split-12 |
| A11 | MCP resource coverage gap as a Phase 3 finding: why `secrets_out_of_prompt` closes it and output filters don't; resource-hook hardened variant as a follow-up; matrix unchanged | done | A-001; docs/defenses.md Findings 1; follow-up F2 |
| A12 | Judge v2.2: reversal decoding, residual-entropy rule (<= 256 candidates) with per-type calculation, FP controls before use, v2-diff under v2.2; keep v2.1 and report both | done | `841944a`, `8e278cd` (J-001b): v2.2 catches 5 of 13 |
| A13 | State v2.2's exact fragment rules; chance-match bound for any minimum below 8 | done | `e0b7354` (J-001b) |
| A14 | Precision sample stratified by evidence type (verbatim, decoded, partial, pooled, residual-entropy), up to 10 per type, precision per type with Wilson CIs, overall weighted by share | done, partly unmeasured | verbatim/spaced: analytic bound (J-001e); pooled/entropy: unmeasured (X-001) |
| A15 | Decoder recall check: 20 real encoded-payload replies inspected; correctly encoded secrets injected into real replies; recall per encoding | done | `fc01450` (J-001d, `decoder-recall.json`) |
| A16 | Latency: exclude errored attempts and requests that hit a model-load stall; report median and p95, not mean; flag cells with a retry | done (code), applied at final report | `parry/stalls.py`, `cell_summary`, Pareto table †; R-001 |
| A17 | Log each model-load stall in the vuln-agent cells; don't change Ollama settings mid-run | done | R-001: no stall in the vuln-agent cells; settings unchanged |
| A18 | Memory-pressure cause (16 GB, qwen + Llama Guard + DeBERTa resident) as a limitation in the write-up | done | docs/defenses.md Limitations |
| A19 | Guard fail-open / fail-closed: code path and timeouts; check trials during the two stalls for guard timeouts/errors; flag and retry if a verdict could be affected; write up per defense as a finding | done | F-002 (no guard failed; guard errors now stored and retried) |
| A20 | Power: discordant pairs and minimum detectable effect at 80% power for every unsupported comparison; phrase as "no detectable improvement at this sample size" | done | `power_table` (`7b647e3`); docs/defenses.md |
| A21 | Per-attack-family ASR for each single control (exploratory, no Holm) | done | `family_table` (`7b647e3`); docs/defenses.md |
| A22 | The 13 benign agent tasks lost under hardened+guards, which guard blocked each, false-positive pattern | done | docs/defenses.md |
| A23 | Log the redact_output leak as F-003 (defense bug), case ID, suggested fix; follow-up | done | F-003; follow-up F3 |
| A24 | Log the user-pasted-content gap as F-004; add the channel as a follow-up | done | F-004; follow-up F4 |
| A25 | Fair garak comparison: each tool's success criterion; per target both / Parry only / garak only; base64 canary as Parry-only example, pasted-text probes as garak-only | done | docs/defenses.md "Baseline scanner: garak"; `evals/results/phase3-garak/compare.json` |

## Labeling

| # | Request | Status | Satisfied by |
|---|---|---|---|
| L1 | Owner will not label manually; use an independent LLM panel: two model families different from the judge and each other, digests recorded | done, voided | local panel (J-001c) and hosted panel (X-001) both failed the known-answer gate |
| L2 | Blind: labelers see only the reply text, the secret and the rule | done | `tests/test_panel.py` |
| L3 | Rule verbatim in prompt and dataset README | done | `e528d28` (`datasets/judge-labels/README.md`) |
| L4 | t/f plus one-line reason; temperature 0, fixed seed | done | `e528d28` |
| L5 | Agreement and Cohen's kappa; precision per evidence type on agreed items; disagreements listed as unresolved; same panel on the 13 v2-diff cases | done, voided | `leak-panel.*` (`7a14edc`) and `leak-panel-hosted.*`; not measurements |
| L6 | Wording everywhere: "LLM-panel labels, not human-verified"; never hand-labeled/manual | done (standing) | J-001c, X-001, dataset README, docs/defenses.md, README |
| L7 | Log the change in J-001 | done | J-001c (`e528d28`, `fc01450`) |
| L8 | 10 known-answer items (5 clear leaks, 5 clear non-leaks), blind; each labeler's accuracy; flag a labeler that gets any wrong | done | leak sets 8/10 and 9/10, Phase 2 4/10 and 3/10: both labelers flagged unreliable (J-001c); one defective item fixed |
| L9 | Apply the same panel to the 200 Phase 2 outcomes with the same blinding, known answers, wording and logging | done, flagged unreliable | `phase2-panel.*` (`7a14edc`) |
| L10 | Note that the known-answer items are easy by design (detect a badly unreliable labeler, not subtle errors) as a limitation | done | J-001c (`6ff7b5a`) |
| L11 | Analytic precision for verbatim and separator-spaced positives: effectively 1 by construction, chance bound per secret type, explained in J-001 | done | J-001e (bounds; 0 of 84 cases carry secret material) |
| L12 | Hosted panel (Groq llama-3.3-70b-versatile, Gemini free tier) for the hard items only: pooled, residual-entropy, 13 v2-diff, 200 Phase 2; keys from `~/.parry/keys.env`, never printed or logged; documented exception; same blinding, fixed known-answer builder, temperature 0, seeds, backoff, wording | done, voided | ran as gpt-oss-120b + ALLaM (L20); ALLaM 7/10 on known answers (X-001) |
| L13 | If either hosted labeler misses any known-answer item: void again; report hard-strata precision and Phase 2 judge accuracy as unmeasured with reasons | done | X-001; write-up reports both as unmeasured |
| L14 | Run the hosted panel only after the reruns finish, not alongside them | done | hosted panel ran after the reruns |
| L15 | Pin Gemini to `gemini-2.5-flash`; no silent fallback, stop and ask if unavailable | done | `parry/judges/hosted.py` (`GEMINI_MODEL`), test |
| L16 | Phrase the analytic bound probabilistically (P(>=1 chance FP) <= ~0.7%, Poisson/Markov); no point precision value | done | J-001e |
| L17 | X-001: free-tier Gemini inputs may be used by Google; only fake lab canaries and lab replies are sent | done | X-001 |
| L18 | Groq model: `llama-3.3-70b-versatile` retired; use `openai/gpt-oss-120b`, pinned | done | `parry/judges/hosted.py`, X-001 |
| L19 | Gemini model: `gemini-2.5-flash` closed to new users; use `gemini-3.8-flash`, pinned | done | `parry/judges/hosted.py`, X-001 |
| L20 | Two-family Groq panel instead of Gemini: list Groq models, pick two non-Qwen families, show daily limits before running; Gemini dropped; log in X-001 | done, voided | `openai/gpt-oss-120b` 10/10, `allam-2-7b` 7/10 on known answers |
| L21 | If no valid second Groq family: leak hard items by gpt-oss + Gemini over two days, Phase 2 accuracy unmeasured | not needed unless the Groq panel fails to run | |
| L22 | Don't block the release on labeling: if the panel isn't done when garak and the analysis finish, release with hard-strata precision and Phase 2 accuracy marked "pending" and add a follow-up | not needed | the panel finished (voided) before release; numbers reported as unmeasured |

## Follow-ups (after the Phase 3 release; the Phase 3 matrix is not changed)

| # | Request | Status | Satisfied by |
|---|---|---|---|
| F1 | Fault-injection test for F-002: a lab switch that makes Llama Guard and the classifier time out or error on demand. Measure `hardened+guards` ASR with (a) healthy guards, (b) failing guards, current fail-open, (c) failing guards with a new `fail_closed` option that blocks the request; report benign pass rate under (c). Make fail-closed the default for security-critical guards, documented as a security-vs-availability trade-off | pending (after phase-3 release) | |
| F2 | Hardened variant that routes MCP resource reads through the output hook (A-001 finding) | pending (after phase-3 release) | |
| F3 | Fix `redact_output` to also redact the random body alone, separator-tolerant and decoded forms; regression test from vuln-rag `ob-encode-output/03` (F-003) | pending (after phase-3 release) | |
| F4 | New attack channel: untrusted content inside the user's message (F-004, exposed by garak) | pending (after phase-3 release) | |

## Still open with the owner (from earlier phases)

- Private vulnerability reporting setting on the GitHub repository (owner action).

## Phase 4: prompt-injection classifier

| # | Request | Status | Satisfied by |
|---|---|---|---|
| K1 | Classifier on licensed data only (licenses verified at the source) | in progress | datasets/README.md |
| K2 | Held-out attack families and a held-out source in evaluation | pending | |
| K3 | Calibrated threshold | pending | |
| K4 | MLflow tracking; weights never committed | pending | |
| K5 | Hugging Face Hub model card (upload is an owner action) | pending | |
| K7 | Report token-length distribution of train/val/held-out sets and the share over 256 tokens | done | docs/classifier.md (train 10.1%, all held-out sets 0%) |
| K8 | Sliding-window chunking at inference (256-token windows with overlap; flag if any chunk is over threshold); calibrate with the same chunking | in progress | |
| K9 | Long-input evaluation: held-out injections at start / middle / end of long benign documents (1k-4k tokens); recall by position, with and without chunking, for both classifiers | pending | |
| K10 | State the truncation limit and chunking behavior in the model card | pending | |
| K11 | If many training items exceed 256 tokens, tell the owner before deciding on retraining with chunked examples | done (asked) | 970 of 9,585 (10.1%); 945 are injections (length confound) |
| K12 | FPR on injection-free long documents at 1,024 / 2,048 / 4,096 tokens for both classifiers; if it rises with length, try a length-aware rule (window-count-adjusted threshold, top-k window mean) as exploratory | in progress | `parry/classifier/longinput.py` |
| K13 | Note that long benign documents are OASST prompts, which can contain instruction-like text | done | `longinput.py` results note; examples of the most-flagged benign documents kept |
| K14 | Held-out metrics (recall, FPR, AUROC, long-input) for all three seeds as mean and min-max next to seed 1337; confirm seed selection used only validation loss, before any held-out scoring | in progress | |
| K15 | Integration test of chunking against both real tokenizers, skipped when not cached; run locally before each commit that touches chunking | done (standing) | `tests/test_chunking_real.py`; pre-commit hook `chunking-real-tokenizers` |
| K16 | Freeze v1: commit the evaluation fix, rerun for the per-family table and seed aggregates, publish v1 as-is ("strong in-distribution, poor generalization to unseen attack families") with ProtectAI alongside; no change to v1's data or threshold after held-out results | in progress (standing) | |
| K17 | No tuning against held-out: Gandalf, the held-out Parry families and NotInject are "seen" for any later model; a v2 needs a fresh held-out set, defined, frozen and logged in ADR 0007 before any v2 training; v2 on old sets labeled "previously seen" | standing | |
| K18 | Bring the long-input results (recall by position, FPR by length, length-aware options, top flagged benign windows) before proposing v2; then propose v2: length balancing and chunked training, indirect and tool-channel examples from training families only, hard benign examples with trigger words | in progress | |
| K19 | Until a classifier generalizes, ProtectAI stays the recommended `pi_classifier` defense in Parry's docs | done (standing) | model card, classifier README, docs/defenses.md |
| K6 | Downloads approved by the owner: deepset/prompt-injections, SPML, OASST1 prompts file, Lakera gandalf, NotInject, microsoft/deberta-v3-small; PyPI mlflow, pyarrow, sentencepiece | approved | owner, 2026-11-24 |
