"""Composable defense layers (see base.py). `make_stack` builds a stack from layer names."""

from __future__ import annotations

import os

from parry.defenses.base import Decision, DefenseStack, Hook, Layer
from parry.defenses.layers import LlamaGuard, OutputValidator, PromptInjectionClassifier

LAYER_NAMES = ("llama_guard", "pi_classifier", "output_validator")


def make_stack(names: list[str], env: dict[str, str] | None = None) -> DefenseStack:
    env = dict(os.environ) if env is None else env
    ollama = env.get("OLLAMA_BASE_URL", "http://localhost:11434")
    guard = env.get("GUARD_URL", "http://localhost:8300")
    layers: list[Layer] = []
    for n in names:
        if n == "llama_guard":
            layers.append(LlamaGuard(ollama, env.get("GUARD_LLAMA_MODEL", "llama-guard3:1b")))
        elif n == "pi_classifier":
            layers.append(PromptInjectionClassifier(guard, model="protectai"))
        elif n == "output_validator":
            layers.append(OutputValidator())
        else:
            raise ValueError(f"unknown defense layer {n!r}; known: {', '.join(LAYER_NAMES)}")
    return DefenseStack(layers)


__all__ = ["LAYER_NAMES", "Decision", "DefenseStack", "Hook", "Layer", "make_stack"]
