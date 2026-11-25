"""The v2 fresh held-out set (ADR 0007) is frozen: same bytes, same counts, marked do-not-train."""

import hashlib
import json

from parry.classifier import fresh


def test_regenerates_byte_for_byte() -> None:
    assert fresh.dumps(fresh.items()) == fresh.ITEMS.read_text()


def test_matches_frozen_manifest() -> None:
    manifest = json.loads(fresh.MANIFEST.read_text())
    assert hashlib.sha256(fresh.ITEMS.read_bytes()).hexdigest() == manifest["sha256"]
    assert manifest["do_not_train"] is True
    assert manifest["adr"] == "docs/adr/0007-v2-fresh-heldout.md"


def test_every_item_marked_and_unique() -> None:
    rows = fresh.items()
    assert all(r["do_not_train"] for r in rows)
    assert len({r["id"] for r in rows}) == len(rows)
    assert len({r["text"] for r in rows}) == len(rows)
    attacks = [r for r in rows if r["label"] == 1]
    assert {r["family"] for r in attacks} == {
        "pasted_content",
        "invisible_chars",
        "markup_comment",
        "translation_wrapped",
    }
    assert len(attacks) == 4 * fresh.PER_ATTACK_FAMILY


def test_benign_proof_only() -> None:
    # every injection's goal is a canary marker, the mock .test host or the mock tool
    for r in fresh.items():
        if r["label"] == 1:
            text = r["text"]
            hidden = "".join(
                chr(ord(c) - 0xE0000) if 0xE0020 <= ord(c) < 0xE007F else c for c in text
            ).replace("​", "")
            assert "PARRY-FRESH-" in hidden or fresh.HOST in hidden or "send_note" in hidden


def test_forbidden_keys_cover_the_set() -> None:
    assert len(fresh.forbidden_keys()) == len({fresh._norm(r["text"]) for r in fresh.items()})
