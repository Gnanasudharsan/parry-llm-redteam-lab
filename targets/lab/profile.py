"""Hardening profiles. `vulnerable` = every control off, `hardened` = every control on.

Each control can be overridden alone with HARDEN_<NAME>=0|1 so a single defense can be
measured in isolation (see docs/adr/0003-lab-targets.md).
"""

from __future__ import annotations

import os
from typing import Literal

from pydantic import BaseModel, ConfigDict

ProfileName = Literal["vulnerable", "hardened"]


class Hardening(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    acl: bool  # role-based retrieval (RAG), path sandbox (MCP), protected paths (agent)
    secrets_out_of_prompt: bool  # never place credentials in the system prompt
    instruction_hierarchy: bool  # system prompt says untrusted content is data, not instructions
    spotlight_untrusted: bool  # wrap retrieved docs / tool outputs in marked, delimited blocks
    redact_output: bool  # replace known secret values in model output
    sanitize_markdown: bool  # drop links/images to non-allowlisted hosts before rendering
    egress_allowlist: bool  # outbound fetches only to allowlisted hosts
    tool_policy: bool  # agent/MCP: block or require approval for risky tool calls

    @classmethod
    def all(cls, on: bool) -> Hardening:
        return cls(**dict.fromkeys(cls.model_fields, on))


class Profile(BaseModel):
    model_config = ConfigDict(frozen=True)

    name: ProfileName
    hardening: Hardening


def _flag(raw: str) -> bool:
    if raw.lower() in {"1", "true", "yes", "on"}:
        return True
    if raw.lower() in {"0", "false", "no", "off"}:
        return False
    raise ValueError(f"not a boolean: {raw!r}")


def profile_from_env(env: dict[str, str] | None = None) -> Profile:
    env = dict(os.environ) if env is None else env
    name = env.get("PROFILE", "vulnerable")
    if name not in ("vulnerable", "hardened"):
        raise ValueError(f"PROFILE must be 'vulnerable' or 'hardened', got {name!r}")
    flags = Hardening.all(name == "hardened").model_dump()
    for key in flags:
        override = env.get(f"HARDEN_{key.upper()}")
        if override is not None:
            flags[key] = _flag(override)
    return Profile(name=name, hardening=Hardening(**flags))
