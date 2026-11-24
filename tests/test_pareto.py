from __future__ import annotations

from typing import Any

from parry.reporting.pareto import frontier, to_markdown, to_svg


def _cell(asr: float, util: float) -> dict[str, Any]:
    def r(p: float) -> dict[str, Any]:
        return {
            "k": round(p * 40),
            "n": 40,
            "rate": p,
            "low": max(0, p - 0.1),
            "high": min(1, p + 0.1),
        }

    return {
        "asr": r(asr),
        "utility": r(util),
        "critical_asr": r(0),
        "false_positive": r(0),
        "utility_retained": util,
        "latency_median_s": 1.0,
        "latency_p95_s": 2.0,
        "guard_ms_median": 5.0,
        "guard_ms_p95": 9.0,
        "had_retry": util == 0.95,
        "guard_tokens_per_request": 0,
        "git_commit": "abc1234",
        "validator_version": "not used",
    }


MATRIX = {
    "targets": {
        "vuln-rag": {
            "none": _cell(0.5, 1.0),  # best utility -> frontier
            "hardened": _cell(0.1, 0.95),  # best ASR -> frontier
            "spotlight": _cell(0.45, 0.9),  # dominated by none
            "redact": _cell(0.3, 0.97),  # trade-off point -> frontier
        }
    }
}


def test_frontier() -> None:
    assert frontier(MATRIX["targets"]["vuln-rag"]) == {"none", "hardened", "redact"}


def test_render() -> None:
    svg = to_svg(MATRIX)
    assert svg.startswith("<svg") and svg.count("<circle") == 4 and ">hardened</text>" in svg
    assert "spotlight</text>" not in svg  # dominated points are not labeled, only titled
    md = to_markdown(MATRIX)
    assert "| hardened ★ † |" in md and "| spotlight |" in md and "| 1.0 / 2.0 | 5.0 / 9.0 |" in md
    assert "| abc1234 | not used |" in md
