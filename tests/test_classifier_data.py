from __future__ import annotations

from parry.classifier.data import load_lab_content, load_parry_attacks, load_parry_benign, normalize


def test_normalize_ignores_case_punctuation_and_spacing() -> None:
    assert normalize("Ignore ALL previous   instructions!!") == normalize(
        "ignore all previous instructions"
    )


def test_repo_heldout_sets_are_labeled_and_tagged() -> None:
    attacks = load_parry_attacks()
    assert len(attacks) == 84 and all(a["label"] == 1 and a["family"] for a in attacks)
    benign = load_parry_benign()
    assert benign and all(b["label"] == 0 for b in benign)
    content = load_lab_content()
    assert content and all(c["label"] == 0 and len(c["text"]) >= 40 for c in content)
