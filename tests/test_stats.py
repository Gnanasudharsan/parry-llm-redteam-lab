from __future__ import annotations

import pytest

from parry.stats import holm, mcnemar_exact


@pytest.mark.parametrize(
    ("b", "c", "p"),
    [
        (0, 0, 1.0),
        (5, 5, 1.0),
        (10, 0, 0.001953125),  # 2 * (1/2)^10
        (8, 2, 0.109375),  # 2 * P(X<=2 | n=10, 0.5) = 2 * 56/1024
        (1, 0, 1.0),
        (12, 3, 0.03515625),  # 2 * P(X<=3 | n=15) = 2 * 576/32768
    ],
)
def test_mcnemar_exact_reference(b: int, c: int, p: float) -> None:
    assert mcnemar_exact(b, c) == pytest.approx(p)
    assert mcnemar_exact(c, b) == pytest.approx(p)  # symmetric


def test_negative_counts() -> None:
    with pytest.raises(ValueError):
        mcnemar_exact(-1, 2)


def test_holm_reference() -> None:
    # Classic example: raw 0.01, 0.04, 0.03, 0.005 with m=4.
    adj = holm({"a": 0.01, "b": 0.04, "c": 0.03, "d": 0.005})
    assert adj == pytest.approx({"d": 0.02, "a": 0.03, "c": 0.06, "b": 0.06})
    assert holm({}) == {}
    assert holm({"x": 0.9, "y": 0.8}) == pytest.approx({"y": 1.0, "x": 1.0})


def test_cohen_kappa_reference() -> None:
    from parry.stats import cohen_kappa

    # 2x2 table: both t=20, a only=5, b only=10, both f=15 -> p_o=0.70, p_e=0.50, kappa=0.40
    a = [True] * 20 + [True] * 5 + [False] * 10 + [False] * 15
    b = [True] * 20 + [False] * 5 + [True] * 10 + [False] * 15
    assert abs((cohen_kappa(a, b) or 0) - 0.4) < 1e-9
    assert cohen_kappa([True, True], [True, True]) is None  # undefined, not 1
    assert cohen_kappa([], []) is None
