# Changelog

All notable changes to this project are documented here. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow SemVer.

## [Unreleased]

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
