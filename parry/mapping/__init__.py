"""Taxonomy mapping: OWASP Top 10 for LLM Applications and MITRE ATLAS.

Every attack plugin declares the IDs it exercises; `validate_ids` rejects unknown ones,
so the coverage table in docs is generated from code rather than written by hand.
"""

from parry.mapping.taxonomy import (
    ATLAS_TECHNIQUES,
    OWASP_LLM_2025,
    TaxonomyEntry,
    validate_ids,
)

__all__ = ["ATLAS_TECHNIQUES", "OWASP_LLM_2025", "TaxonomyEntry", "validate_ids"]
