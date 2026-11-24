# Phase 3 requests ledger

Every instruction the owner gave during Phase 3, with its status and what satisfies it.
Re-read at the start of every session and after any context compaction; update as items
close. Status: **done**, **in progress**, **pending**, **withdrawn**.
Last updated: 2026-11-23.

## Scope (Phase 3 spec)

| # | Request | Status | Satisfied by |
|---|---|---|---|
| S1 | Each defense as a composable layer | done | `93b2302`, `fd91a2d` (`parry/defenses/`, `PUT /_lab/config`) |
| S2 | Run the full defense matrix | done | `3b4ed31`; `runs/matrix-20261123T212651Z` (42/42 cells, 0 errors) |
| S3 | Report ASR reduction, false-positive rate, utility retained, latency/cost | in progress | `parry/matrix.py` (`cell_summary`, `summarize_matrix`); final numbers after reruns |
| S4 | Pareto chart | in progress | `4fac81c` (`parry/reporting/pareto.py`); final chart after reruns |
| S5 | Benchmark against garak: what each finds that the other misses, including where garak beats Parry | pending | `3ab14d8`, `540d6c7` (code); run not done; report field names unverified |
| S6 | Results matrix in the README; hardened twins show measured improvement | pending | after reruns and analysis |
| S7 | End of phase: README status, CHANGELOG, `chore(release): complete phase 3 — …`, tag `phase-3`, push | pending | |

## Plan-approval conditions

| # | Request | Status | Satisfied by |
|---|---|---|---|
| C1 | Spot-check bridge: `none` + `pi_classifier` per app; (a) zero OutputValidator constructions/calls, (b) verdict changes within noise allowance and overlapping CIs; rerun the full matrix if either fails | done (all six pass) | `ab36953` (`matrix-compare`), `82b0a88`, `232a131`; results in `docs/deviations.md` "Spot-check design" (`de3b41c`) |
| C2 | Validator version and commit SHA in every results file; log bug, fix and redone runs in deviations | in progress | `991d62a`, `efd8fa5`, `de3b41c`; D-001 "Runs redone / Archived" to fill after reruns |
| C3 | Discard buggy-validator results; archive under `evals/results/archive/`; never mix | pending | after reruns |
| C4 | Same seeds, model versions and benign task set | in progress | `provenance.json` per matrix (`efd8fa5`, `de3b41c`) |
| C5 | Groq run | withdrawn for targets/attacks (no hosted APIs); retry-then-report rule kept. Hosted labelers only, by later decision: X-001 / L12 | retry rule `f23a121` |
| C6 | garak on the same targets; garak's detectors and Parry's judges re-scoring garak's responses against the lab canaries | pending | `540d6c7` (code) |
| C7 | Temperature 0 and a fixed seed on every Ollama call | done | `efd8fa5` (D-002) |
| C8 | Record the Ollama version and model digests | done | `efd8fa5` (`parry/provenance.py`) |
| C9 | Report measured nondeterminism (246/256 identical, 1 flip) as a known limitation | in progress | `docs/deviations.md` "Known non-determinism"; write-up pending |
| C10 | Rerun `output_validator`, `hardened+guards`, `llama_guard` on all three apps | done | `runs/matrix-20261124T024429Z` (9/9, commit `7a14edc`), R-001 |
| C11 | Write-up: exact commit per cell (originals `3b4ed31`, reruns, spot-checks as bridge) | pending | write-up |
| C12 | Write-up: engine changed between original cells and reruns (retry rule `f23a121`); spot-checks bridge it | pending | write-up; noted in deviations (`232a131`) |
| C13 | Confirm the OpenAI-compatible adapter seed is off the matrix path | done | `82b0a88` (deviations) |

## Process

| # | Request | Status | Satisfied by |
|---|---|---|---|
| P1 | Progress from result files on disk (cells, cases, time per cell, errors, retries); stop and tell the owner if a cell is stuck or retrying | in progress (standing) | T-001 (`f23a121`) |
| P2 | Retry rule: errored case/benign task retried once after the cell, same seed; report both attempts | done | `f23a121` |
| P3 | Fix log buffering (`PYTHONUNBUFFERED=1`, `flush=True`) and log it as a tooling note | done | `f23a121` (T-001) |
| P4 | Never silence commit output; check the exit code before reporting a commit; note under D-003 | done (standing) | `a14abc1` |
| P5 | `set -o pipefail` for test-then-commit | done (standing) | D-003 |
| P6 | Interim numbers stay out of the README and write-up until the spot-checks pass and the reruns finish | in progress (standing) | |
| P7 | Show the matrix while it runs | done | reported in chat |
| P8 | Explain every "(1 failed)" step and whether it affected a commit | done (standing) | reported in chat for each update |
| P9 | Draw the sample and rerun the v2-diff only after the matrix process exits; analysis refuses cells without a completion marker | done | `e0b7354` (T-002) |
| P10 | Keep >= 15 GB free before the reruns; prune only dangling images and build cache; remove labeler models after the panel if space is short; pause before any step that could fill the disk | in progress (standing) | 13 GB -> 20 GB free (not a commit) |
| P11 | Do not start the reruns until all six spot-checks are confirmed passing | done | all six pass (`de3b41c`) |
| P12 | Requests ledger in `docs/requests.md`; re-read each session and after compaction; update and commit | done (standing) | this file |
| P13 | Back up uncommitted work without touching HEAD (`git diff` patch + untracked copies) | done | `~/parry-uncommitted-20261123-2315.patch` + `-untracked/`; refreshed at 23:17 (`~/parry-uncommitted-20261123-2317.*`) |

## Analysis (final data only)

| # | Request | Status | Satisfied by |
|---|---|---|---|
| A1 | Exact McNemar paired tests (each config vs `none`, hardened vs hardened+guards) with flip counts | in progress | `0c744eb`; final run after reruns |
| A2 | Holm-Bonferroni within each app; raw and adjusted p; "supported" = adjusted p < 0.05; don't rank unsupported differences | in progress | `24d003a`; final run after reruns |
| A3 | Judge-artifact check for `redact_output` and `sanitize_markdown` | in progress | `0c744eb` (`artifact_check`); final run after reruns |
| A4 | Leak judge v2 applied to every cell; old and new numbers | in progress | `analyze` (`24d003a`, `841944a`); final run after reruns |
| A5 | Threshold sensitivity at 1/2, 2/3, full; state whether any conclusion changes | in progress | `24d003a`; final run after reruns |
| A6 | FP controls: cross-secret control and v2 on benign replies; minimum fragment >= 8 with a chance-match justification; tighten and log if FP | done | `24d003a`, `bce78ae` (J-001) |
| A7 | Utility (benign pass rate) next to ASR for every cell, on the Pareto chart with latency overhead; call out defenses that cost benign tasks | in progress | `4fac81c`; final after reruns |
| A8 | Confirm J-001 committed (git log, exit code) | done | `bce78ae` |
| A9 | Baseline exposure: ASR as now and excluding goals whose secret a benign task exposes; which secrets/configs; whether conclusions change, especially `secrets_out_of_prompt` | in progress | `05d5f80` (A-001); conclusion check after reruns |
| A10 | List every v2-positive/v2.1-negative trial for review, with fragments; count the 12-char split cases | done | `3cc9189` (`datasets/judge-labels/leak-v2-diff.*`): 13 cases, 0 split-12 |
| A11 | MCP resource coverage gap as a Phase 3 finding: why `secrets_out_of_prompt` closes it and output filters don't; resource-hook hardened variant as a follow-up; matrix unchanged | in progress | `8e278cd` (A-001); write-up pending; follow-up variant pending (not in matrix) |
| A12 | Judge v2.2: reversal decoding, residual-entropy rule (<= 256 candidates) with per-type calculation, FP controls before use, v2-diff under v2.2; keep v2.1 and report both | done | `841944a`, `8e278cd` (J-001b): v2.2 catches 5 of 13 |
| A13 | State v2.2's exact fragment rules; chance-match bound for any minimum below 8 | done | `e0b7354` (J-001b) |
| A14 | Precision sample stratified by evidence type (verbatim, decoded, partial, pooled, residual-entropy), up to 10 per type, precision per type with Wilson CIs, overall weighted by share | in progress | verbatim/spaced analytic (J-001e); pooled/entropy via hosted panel (L12) |
| A15 | Decoder recall check: 20 real encoded-payload replies inspected; correctly encoded secrets injected into real replies; recall per encoding | done | `fc01450` (J-001d, `decoder-recall.json`) |
| A16 | Latency: exclude errored attempts and requests that hit a model-load stall; report median and p95, not mean; flag cells with a retry | done (code), applied at final report | `parry/stalls.py`, `cell_summary`, Pareto table †; R-001 |
| A17 | Log each model-load stall in the vuln-agent cells; don't change Ollama settings mid-run | done | R-001: no stall in the vuln-agent cells; settings unchanged |
| A18 | Memory-pressure cause (16 GB, qwen + Llama Guard + DeBERTa resident) as a limitation in the write-up | in progress | deviations "Limitation: memory pressure"; write-up pending |
| A19 | Guard fail-open / fail-closed: code path and timeouts; check trials during the two stalls for guard timeouts/errors; flag and retry if a verdict could be affected; write up per defense as a finding | done | F-002 (no guard failed; guard errors now stored and retried) |

## Labeling

| # | Request | Status | Satisfied by |
|---|---|---|---|
| L1 | Owner will not label manually; use an independent LLM panel: two model families different from the judge and each other, digests recorded | in progress | `e528d28`, `fc01450`; `llama3.1:8b` + `mistral:7b` (owner chose; no hosted third) |
| L2 | Blind: labelers see only the reply text, the secret and the rule | done | `tests/test_panel.py` |
| L3 | Rule verbatim in prompt and dataset README | done | `e528d28` (`datasets/judge-labels/README.md`) |
| L4 | t/f plus one-line reason; temperature 0, fixed seed | done | `e528d28` |
| L5 | Agreement and Cohen's kappa; precision per evidence type on agreed items; disagreements listed as unresolved; same panel on the 13 v2-diff cases | done, flagged unreliable | `leak-panel.*` (`7a14edc`); not usable as measurements (L8) |
| L6 | Wording everywhere: "LLM-panel labels, not human-verified"; never hand-labeled/manual | in progress (standing) | J-001c, dataset README; README/write-up pending |
| L7 | Log the change in J-001 | done | J-001c (`e528d28`, `fc01450`) |
| L8 | 10 known-answer items (5 clear leaks, 5 clear non-leaks), blind; each labeler's accuracy; flag a labeler that gets any wrong | done | leak sets 8/10 and 9/10, Phase 2 4/10 and 3/10: both labelers flagged unreliable (J-001c); one defective item fixed |
| L9 | Apply the same panel to the 200 Phase 2 outcomes with the same blinding, known answers, wording and logging | done, flagged unreliable | `phase2-panel.*` (`7a14edc`) |
| L10 | Note that the known-answer items are easy by design (detect a badly unreliable labeler, not subtle errors) as a limitation | done | J-001c (`6ff7b5a`) |
| L11 | Analytic precision for verbatim and separator-spaced positives: effectively 1 by construction, chance bound per secret type, explained in J-001 | done | J-001e (bounds; 0 of 84 cases carry secret material) |
| L12 | Hosted panel (Groq llama-3.3-70b-versatile, Gemini free tier) for the hard items only: pooled, residual-entropy, 13 v2-diff, 200 Phase 2; keys from `~/.parry/keys.env`, never printed or logged; documented exception; same blinding, fixed known-answer builder, temperature 0, seeds, backoff, wording | in progress | `parry/judges/hosted.py`, X-001; run after the reruns |
| L13 | If either hosted labeler misses any known-answer item: void again; report hard-strata precision and Phase 2 judge accuracy as unmeasured with reasons | pending | gate in X-001 |
| L14 | Run the hosted panel only after the reruns finish, not alongside them | pending (standing) | |
| L15 | Pin Gemini to `gemini-2.5-flash`; no silent fallback, stop and ask if unavailable | done | `parry/judges/hosted.py` (`GEMINI_MODEL`), test |
| L16 | Phrase the analytic bound probabilistically (P(>=1 chance FP) <= ~0.7%, Poisson/Markov); no point precision value | done | J-001e |
| L17 | X-001: free-tier Gemini inputs may be used by Google; only fake lab canaries and lab replies are sent | done | X-001 |
| L18 | Groq model: `llama-3.3-70b-versatile` retired; use `openai/gpt-oss-120b`, pinned | done | `parry/judges/hosted.py`, X-001 |
| L19 | Gemini model: `gemini-2.5-flash` closed to new users; use `gemini-3.8-flash`, pinned | done | `parry/judges/hosted.py`, X-001 |

## Follow-ups (after the Phase 3 release; the Phase 3 matrix is not changed)

| # | Request | Status | Satisfied by |
|---|---|---|---|
| F1 | Fault-injection test for F-002: a lab switch that makes Llama Guard and the classifier time out or error on demand. Measure `hardened+guards` ASR with (a) healthy guards, (b) failing guards, current fail-open, (c) failing guards with a new `fail_closed` option that blocks the request; report benign pass rate under (c). Make fail-closed the default for security-critical guards, documented as a security-vs-availability trade-off | pending (after phase-3 release) | |
| F2 | Hardened variant that routes MCP resource reads through the output hook (A-001 finding) | pending (after phase-3 release) | |

## Still open with the owner (from earlier phases)

- Private vulnerability reporting setting on the GitHub repository (owner action).
