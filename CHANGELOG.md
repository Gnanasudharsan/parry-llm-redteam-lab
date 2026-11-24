# Changelog

All notable changes to this project are documented here. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow SemVer.

## [Unreleased]

## [phase-3] - 2026-11-24

### Added
- Defense layers (`parry/defenses`): Llama Guard 3 via Ollama, a DeBERTa prompt-injection
  classifier served by `parry guard serve`, a format-aware output validator; composable at
  input, untrusted-content and output hooks; versions and use traced per cell.
- Runtime reconfiguration of lab apps (`PUT /_lab/config`); defense matrix of 42
  configurations (`targets/matrix.yaml`, `parry matrix`), each with attacks and benign tasks.
- `parry matrix-report` (results table, Pareto chart with latency), `parry matrix-compare`
  (rerun vs original within measured noise), `parry analyze` (paired exact McNemar,
  Holm-Bonferroni, seven leak-judge rules, false-positive controls, baseline exposure,
  judge-artifact check).
- Leak judge v2.1 and v2.2 next to v1 (more decoders, partial leaks, pieces across turns,
  reversal of every decoded view, residual-entropy rule); decoder recall check.
- Retry rule for errored cases and benign tasks; guard failures recorded and retried;
  model-load stall detection for latency; request start times; provenance (commit pinned at
  process start, Ollama version and model digests).
- `parry baseline garak` with an offline payload preflight; garak responses re-judged with
  Parry's judges.
- LLM labeling panels (local and hosted) with blind known-answer items.
- Results in `evals/results/` (final matrix, spot-checks, archived superseded cells);
  docs/defenses.md, docs/deviations.md, docs/requests.md, ADR 0005.

### Fixed
- Output validator matched the word "staff" (D-001); Llama Guard calls had no seed (D-002).
- garak encoding probes defaulted to a slur-term payload set (D-006).

### Known gaps
- Judge accuracy and hard-strata leak-judge precision are unmeasured (no reliable labels).
- Follow-ups (docs/requests.md): guard fault-injection test with a fail-closed option;
  MCP resource reads through the output hook; `redact_output` misses the secret's random body
  on its own (F-003); no attack channel for untrusted content inside the user's message
  (F-004, exposed by garak).

## [phase-2] - 2026-11-23

### Added
- Attack engine: YAML templates expanded with seed-derived nonces; 9 families, 8 channels,
  84 cases; obfuscation transforms (base64, ROT13, leetspeak, word split).
- Channels: direct, multi-turn, RAG review documents, web pages (attacker and first-party
  hosts), agent emails and files, MCP notes, third-party tool descriptions, direct MCP calls.
- Judges: decoding leak judge (plain, spaced, reversed, base64, hex, ROT13), lab-evidence judges
  for tool calls and exfiltration, LLM judge for misinformation, success vs attempt, delivery
  confirmation for indirect channels.
- `parry scan`, `parry report` (Markdown, HTML, JSON), `parry attacks list`,
  `parry judge sample | label | eval`.
- Adapters: HTTP chat, OpenAI-compatible, MCP streamable HTTP, LangGraph in-process; lab client.
- MITRE ATLAS 5.6.0 techniques (verified against atlas-data v2026.10); coverage table.
- Lab agent: third-party tool install endpoint; hardened profile pins tool manifests by hash.
- Results: `docs/results/phase2/`; 200-item judge labeling sample.
- ADR 0004, docs/attacks.md.

### Changed
- Canary derivation moved to `parry.canary`; run metadata records commit and dirty state.

## [phase-1] - 2026-11-23

### Added
- Lab targets for a fictional retailer, each in a vulnerable and a hardened profile from one
  codebase: RAG customer assistant (FastAPI, numpy vector store), tool-using ops agent
  (LangGraph; mock bank, email, files, orders, web), workspace MCP server (MCP SDK 2.x,
  streamable HTTP).
- Eight named hardening controls toggleable one at a time (`HARDEN_<FLAG>`).
- HMAC-derived canaries and fake secrets per target; token-guarded lab admin API
  (state, events, reset, content planting).
- Mock web + exfiltration recorder answering for every lab hostname.
- Docker Compose lab: internal-only network, nginx gateway as the single ingress/egress
  (ports on 127.0.0.1, model API to host Ollama), read-only non-root containers.
- `make targets-up`, `targets-verify` (34 live checks), `benign`; benign task schema
  (`parry/tasks.py`) and runner gated by `--i-own-this-target`.
- Benign task sets: 47 RAG, 43 + 6 approval-gated agent, 42 MCP; baseline results in
  `docs/results/phase1-benign.json`.
- ADR 0003, docs/lab.md; CI builds the lab image.

### Changed
- Lab models capped at 512 output tokens after a repetition loop produced a 6-minute response.

## [phase-0] - 2026-11-23

### Added
- Project layout: `parry/{cli,adapters,attacks,channels,judges,defenses,reporting,mapping}`,
  `targets/`, `classifier/`, `datasets/`, `docs/`, `tests/`.
- `parry.yaml` schema (Pydantic v2) with secret-free key references.
- Target authorization gate: `--i-own-this-target` per target, public endpoints refused by default.
- `parry targets list` and `parry targets check` commands.
- 95% Wilson score intervals (`parry.metrics`).
- OWASP Top 10 for LLM Applications (2025) ID table.
- SECURITY.md, responsible-use guide, metrics definitions, ADRs 0001 and 0002.
- CI (ruff, mypy strict, pytest), pre-commit config, Makefile.
