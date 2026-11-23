"""Taxonomy tables.

OWASP: Top 10 for LLM Applications, 2025 edition (genai.owasp.org).
ATLAS: technique IDs and names checked against MITRE ATLAS 5.6.0 (atlas-data release
v2026.10, https://github.com/mitre-atlas/atlas-data). Only the techniques Parry's attacks
exercise are listed; `tests/test_mapping.py` pins them.
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

ATLAS_VERSION = "5.6.0"


def _atlas(tid: str, name: str) -> TaxonomyEntry:
    return TaxonomyEntry(id=tid, name=name, framework=f"MITRE ATLAS {ATLAS_VERSION}")


ATLAS_TECHNIQUES: Mapping[str, TaxonomyEntry] = {
    e.id: e
    for e in (
        _atlas("AML.T0051", "LLM Prompt Injection"),
        _atlas("AML.T0051.000", "LLM Prompt Injection: Direct"),
        _atlas("AML.T0051.001", "LLM Prompt Injection: Indirect"),
        _atlas("AML.T0054", "LLM Jailbreak"),
        _atlas("AML.T0056", "Extract LLM System Prompt"),
        _atlas("AML.T0057", "LLM Data Leakage"),
        _atlas("AML.T0053", "AI Agent Tool Invocation"),
        _atlas("AML.T0068", "LLM Prompt Obfuscation"),
        _atlas("AML.T0070", "RAG Poisoning"),
        _atlas("AML.T0066", "Retrieval Content Crafting"),
        _atlas("AML.T0077", "LLM Response Rendering"),
        _atlas("AML.T0080", "AI Agent Context Poisoning"),
        _atlas("AML.T0086", "Exfiltration via AI Agent Tool Invocation"),
        _atlas("AML.T0099", "AI Agent Tool Data Poisoning"),
        _atlas("AML.T0101", "Data Destruction via AI Agent Tool Invocation"),
        _atlas("AML.T0110", "AI Agent Tool Poisoning"),
        _atlas("AML.T0055", "Unsecured Credentials"),
        _atlas("AML.T0037", "Data from Local System"),
    )
}


def validate_ids(ids: Iterable[str]) -> list[TaxonomyEntry]:
    """Resolve taxonomy IDs, raising KeyError on any that are not in the tables."""
    known = {**OWASP_LLM_2025, **ATLAS_TECHNIQUES}
    out: list[TaxonomyEntry] = []
    for i in ids:
        if i not in known:
            raise KeyError(f"unknown taxonomy id: {i}")
        out.append(known[i])
    return out
