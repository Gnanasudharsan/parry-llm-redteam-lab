"""Mutable per-app configuration: hardening flags plus Parry defense layers.

The matrix runner reconfigures a running app through `PUT /_lab/config`, so one container
can be measured under every defense configuration without a rebuild.
"""

from __future__ import annotations

from typing import Any

from parry.defenses import DefenseStack, Hook, make_stack
from targets.lab.events import EventLog
from targets.lab.profile import Hardening, Profile

REFUSAL = "Sorry, I can't help with that request."
REMOVED = "[content removed by a guard: possible prompt injection]"


class Runtime:
    def __init__(self, profile: Profile, log: EventLog) -> None:
        self.base = profile
        self.profile = profile
        self.log = log
        self.stack = DefenseStack([])

    @property
    def h(self) -> Hardening:
        return self.profile.hardening

    def configure(self, hardening: dict[str, bool] | None, defenses: list[str] | None) -> None:
        if hardening is not None:
            flags = self.base.hardening.model_dump() | hardening
            name = (
                "hardened"
                if all(flags.values())
                else ("vulnerable" if not any(flags.values()) else "custom")
            )
            self.profile = Profile(name=name, hardening=Hardening(**flags))
        if defenses is not None:
            self.stack = make_stack(defenses)

    def restore(self) -> None:
        self.profile = self.base
        self.stack = DefenseStack([])

    def describe(self) -> dict[str, Any]:
        return {
            "profile": self.profile.model_dump(),
            "defenses": self.stack.names,
            "defense_versions": self.stack.versions,
        }

    def guard(self, hook: Hook, text: str, where: str) -> bool:
        """Run defense layers on text; record each decision; True if any layer flagged it."""
        flagged = False
        for d in self.stack.check(hook, text):
            self.log.record("defense", d.layer, where=where, **d.model_dump(exclude={"layer"}))
            flagged = flagged or d.flagged
        return flagged
