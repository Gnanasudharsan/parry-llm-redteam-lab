"""The model card's tables are exactly what the renderer makes from the committed results."""

from parry.classifier import card


def test_card_tables_match_results() -> None:
    text = card.CARD.read_text()
    a, b = text.index(card.BEGIN), text.index(card.END) + len(card.END)
    assert text[a:b] == card.render()


def test_card_states_v1_verdict_and_recommendation() -> None:
    text = card.CARD.read_text()
    assert "strong in-distribution, poor generalization to unseen attack families" in text
    assert "ProtectAI as its recommended and default `pi_classifier`" in text
    assert "256 tokens" in text and "overlap by 64 tokens" in text
