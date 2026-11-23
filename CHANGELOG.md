# Changelog

All notable changes to this project are documented here. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow SemVer.

## [Unreleased]

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
