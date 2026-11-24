from __future__ import annotations

from typing import Any

from parry.classifier.chunking import windows


class _Tok:
    """Minimal tokenizer: one token per word, [CLS]=0 ... [SEP]=1 around each window."""

    def __call__(self, text: str, add_special_tokens: bool = True) -> dict[str, Any]:
        ids = [int(w) for w in text.split()]
        return {"input_ids": [0, *ids, 1] if add_special_tokens else ids}


def test_windows_cover_text_with_overlap() -> None:
    text = " ".join(str(i) for i in range(10, 40))  # 30 tokens
    w = windows(_Tok(), text, window=12, overlap=4)  # body 10, step 6
    assert all(len(x) <= 12 and x[0] == 0 and x[-1] == 1 for x in w)
    covered = {t for x in w for t in x[1:-1]}
    assert covered == set(range(10, 40))  # every token is in some window
    assert w[0][1:-1][-4:] == w[1][1:-1][:4]  # consecutive windows overlap by 4


def test_short_text_is_one_window() -> None:
    w = windows(_Tok(), "5 6 7", window=12, overlap=4)
    assert w == [[0, 5, 6, 7, 1]]


def test_exploratory_rules() -> None:
    from parry.classifier.longinput import _aggregate, exploratory

    assert _aggregate([0.9, 0.1, 0.5], "max") == 0.9
    assert _aggregate([0.9, 0.1, 0.5], "top2") == 0.7
    assert _aggregate([0.4], "top2") == 0.4
    # validation: 100 single-window benign items spread over [0, 0.99], one injection
    val_w = [[i / 100] for i in range(100)] + [[0.995]]
    val_y = [0] * 100 + [1]
    cases = [[0.985], [0.985] + [0.1] * 9]  # same top window; 1 vs 10 windows
    ex = exploratory(val_w, val_y, cases, 0.05)
    # 1 window: per-window FPR 5% -> threshold below 0.985 -> flagged
    # 10 windows: per-window FPR 0.5% -> threshold above 0.985 -> not flagged
    assert ex["window_adjusted"] == [True, False]
