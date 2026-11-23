from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from parry.config import ParryConfig, load_config

ROOT = Path(__file__).resolve().parents[1]


def test_example_config_loads() -> None:
    cfg = load_config(ROOT / "parry.example.yaml")
    assert {t.name for t in cfg.targets} == {"vuln-rag", "local-ollama", "vuln-mcp"}
    assert cfg.seed == 1337


def _one(**overrides: object) -> dict[str, object]:
    t: dict[str, object] = {
        "name": "t",
        "kind": "http",
        "url": "http://localhost:1/x",
        "owner_statement": "my own local lab app",
    }
    t.update(overrides)
    return {"targets": [t]}


@pytest.mark.parametrize(
    "overrides",
    [
        {"url": None},  # http needs a url
        {"kind": "litellm", "url": None},  # litellm needs a model
        {"kind": "langgraph", "url": None},  # needs entrypoint
        {"kind": "mcp_stdio", "url": None},  # needs command
        {"owner_statement": "mine"},  # too short to be a real statement
        {"name": "Bad Name"},
        {"api_key_env": "sk-live-abc123"},  # a key, not an env var name
        {"surprise": True},  # unknown fields are rejected
    ],
)
def test_invalid_targets_rejected(overrides: dict[str, object]) -> None:
    with pytest.raises(ValidationError):
        ParryConfig.model_validate(_one(**overrides))


def test_duplicate_names_rejected() -> None:
    raw = _one()
    raw["targets"] = raw["targets"] * 2  # type: ignore[operator]
    with pytest.raises(ValidationError, match="duplicate target names"):
        ParryConfig.model_validate(raw)


def test_empty_targets_rejected() -> None:
    with pytest.raises(ValidationError):
        ParryConfig.model_validate({"targets": []})
