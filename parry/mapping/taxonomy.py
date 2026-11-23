"""Taxonomy tables.

OWASP: Top 10 for LLM Applications, 2025 edition (genai.owasp.org).
ATLAS: intentionally empty in Phase 0. Technique IDs are added in Phase 2, each checked
against the current published ATLAS release, together with the attacks that use them.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping

from pydantic import BaseModel, ConfigDict


class TaxonomyEntry(BaseModel):
    model_config = ConfigDict(frozen=True)

    id: str
    name: str
    framework: str


def _owasp(num: int, name: str) -> TaxonomyEntry:
    return TaxonomyEntry(id=f"LLM{num:02d}:2025", name=name, framework="OWASP LLM Top 10 2025")


OWASP_LLM_2025: Mapping[str, TaxonomyEntry] = {
    e.id: e
    for e in (
        _owasp(1, "Prompt Injection"),
        _owasp(2, "Sensitive Information Disclosure"),
        _owasp(3, "Supply Chain"),
        _owasp(4, "Data and Model Poisoning"),
        _owasp(5, "Improper Output Handling"),
        _owasp(6, "Excessive Agency"),
        _owasp(7, "System Prompt Leakage"),
        _owasp(8, "Vector and Embedding Weaknesses"),
        _owasp(9, "Misinformation"),
        _owasp(10, "Unbounded Consumption"),
    )
}

ATLAS_TECHNIQUES: Mapping[str, TaxonomyEntry] = {}


def validate_ids(ids: Iterable[str]) -> list[TaxonomyEntry]:
    """Resolve taxonomy IDs, raising KeyError on any that are not in the tables."""
    known = {**OWASP_LLM_2025, **ATLAS_TECHNIQUES}
    out: list[TaxonomyEntry] = []
    for i in ids:
        if i not in known:
            raise KeyError(f"unknown taxonomy id: {i}")
        out.append(known[i])
    return out
