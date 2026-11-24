from __future__ import annotations

import math

from parry.classifier.evaluate import auroc, ece, fit_temperature, nll, threshold_for_fpr


def test_auroc_reference_values() -> None:
    assert auroc([0.9, 0.8, 0.1, 0.2], [1, 1, 0, 0]) == 1.0
    assert auroc([0.1, 0.2, 0.9, 0.8], [1, 1, 0, 0]) == 0.0
    assert auroc([0.5, 0.5], [1, 0]) == 0.5  # tie counts half
    assert auroc([0.9], [1]) is None


def test_threshold_respects_target_fpr() -> None:
    benign = [i / 100 for i in range(100)]  # 0.00 .. 0.99
    probs, labels = [*benign, 0.995], [0] * 100 + [1]
    t = threshold_for_fpr(probs, labels, 0.01)  # 1 of 100 benign may be flagged
    flagged_benign = sum(p >= t for p in benign)
    assert flagged_benign == 1 and 0.98 < t <= 0.99 + 1e-9


def test_temperature_scaling_reduces_nll_of_overconfident_logits() -> None:
    # overconfident: logit gap 8 but only 70% correct
    logits = [[-4.0, 4.0]] * 7 + [[-4.0, 4.0]] * 3
    labels = [1] * 7 + [0] * 3
    t = fit_temperature(logits, labels)
    assert t > 1 and nll(logits, labels, t) < nll(logits, labels, 1.0)
    # optimum: p = 0.7 -> logit gap = ln(7/3) -> T = 8 / ln(7/3)
    assert math.isclose(t, 8 / math.log(7 / 3), rel_tol=1e-3)


def test_ece_zero_when_perfectly_calibrated_bins() -> None:
    assert ece([0.25, 0.25, 0.25, 0.25], [1, 0, 0, 0]) == 0.0
