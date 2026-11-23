from __future__ import annotations

import os
from pathlib import Path

import pytest
import yaml

from parry.mapping import ATLAS_TECHNIQUES, OWASP_LLM_2025, validate_ids


def test_tables() -> None:
    assert len(OWASP_LLM_2025) == 10
    assert ATLAS_TECHNIQUES["AML.T0056"].name == "Extract LLM System Prompt"
    with pytest.raises(KeyError):
        validate_ids(["AML.T9999"])


@pytest.mark.skipif(
    "ATLAS_YAML" not in os.environ, reason="set ATLAS_YAML to atlas-data dist/ATLAS.yaml"
)
def test_atlas_ids_match_release() -> None:
    data = yaml.safe_load(Path(os.environ["ATLAS_YAML"]).read_text())
    names = {t["id"]: t["name"] for m in data["matrices"] for t in m.get("techniques", [])}
    for tid, entry in ATLAS_TECHNIQUES.items():
        assert tid in names, tid
        assert names[tid] == entry.name.split(": ")[-1], tid
