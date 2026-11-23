# ADR 0002: Python 3.12, uv, Typer, Pydantic v2

- Status: accepted
- Date: 2026-11-23

## Decision

- **Python 3.12**, pinned (`requires-python >=3.12,<3.13`). It is supported by every planned
  dependency (Transformers, LiteLLM, LangGraph, MCP SDK), and one version keeps results
  reproducible.
- **uv** for environments and the lockfile (`uv.lock` is committed).
- **Typer** for the CLI: type-annotated commands, testable with `CliRunner`.
- **Pydantic v2** for every config and result model, with `extra="forbid"` so a misspelled
  field fails loudly instead of silently changing scope.
- **ruff** (lint + format), **mypy --strict**, **pytest**, **pre-commit**, GitHub Actions.

## Consequences

Contributors need uv. Dependencies are added per phase only when code uses them, so Phase 0
installs three runtime packages.
