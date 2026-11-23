"""Security vs utility (vs cost) from a defense matrix.

Writes a static SVG of small multiples (one panel per target): x = benign tasks passed,
y = attack success rate, whiskers = 95% Wilson interval on ASR. Configurations on the
Pareto frontier (no other configuration has both lower ASR and higher utility) are filled
accent dots with labels; dominated ones are hollow gray rings. Cost is in the table.
"""

from __future__ import annotations

import html
import math
from typing import Any

W_PANEL, H_PANEL = 330, 290
PAD_L, PAD_R, PAD_T, PAD_B = 44, 16, 34, 40


def frontier(cells: dict[str, Any]) -> set[str]:
    """Configurations not dominated on (lower ASR, higher utility)."""
    pts = {k: (c["asr"]["rate"], c["utility"]["rate"]) for k, c in cells.items()}
    out = set()
    for k, (a, u) in pts.items():
        dominated = any(
            (a2 <= a and u2 >= u) and (a2 < a or u2 > u) for k2, (a2, u2) in pts.items() if k2 != k
        )
        if not dominated:
            out.add(k)
    return out


def _fmt(r: dict[str, Any]) -> str:
    return f"{r['rate']:.0%} [{r['low']:.0%}, {r['high']:.0%}]"


def to_svg(matrix: dict[str, Any]) -> str:
    targets = list(matrix["targets"].items())
    all_cells = [c for _, cells in targets for c in cells.values()]
    x_min: float = max(0.0, math.floor(min(c["utility"]["rate"] for c in all_cells) * 10 - 1) / 10)
    y_max: float = min(1.0, math.ceil(max(c["asr"]["high"] for c in all_cells) * 10) / 10)
    width = W_PANEL * len(targets)
    height = H_PANEL + 26
    pw, ph = W_PANEL - PAD_L - PAD_R, H_PANEL - PAD_T - PAD_B

    def sx(u: float) -> float:
        return float(PAD_L + (u - x_min) / (1 - x_min) * pw)

    def sy(a: float) -> float:
        return float(PAD_T + (1 - a / y_max) * ph)

    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width} {height}" '
        f'width="{width}" height="{height}" role="img" aria-labelledby="t d">',
        "<title id='t'>Defense configurations: attack success vs benign utility</title>",
        "<desc id='d'>One panel per lab target. Lower and further right is better. Filled "
        "dots are Pareto-optimal configurations; hollow rings are dominated.</desc>",
        "<style>"
        ":root{--bg:#FFFFFF;--ink:#15191F;--muted:#525C6B;--grid:#DCE0E6;--accent:#1F4FD1;--ctx:#8A93A3}"
        "@media (prefers-color-scheme: dark){:root{--bg:#15191F;--ink:#E6E8EB;--muted:#9AA3AF;"
        "--grid:#2A3038;--accent:#6A8CF2;--ctx:#6B7484}}"
        "text{font-family:'Inter Tight',system-ui,sans-serif;fill:var(--ink)}"
        ".m{fill:var(--muted);font-size:11px}.lbl{font-size:11px}"
        ".g{stroke:var(--grid);stroke-width:1}.ax{stroke:var(--muted);stroke-width:1}"
        ".f{fill:var(--accent);stroke:var(--bg);stroke-width:2}"
        ".d{fill:none;stroke:var(--ctx);stroke-width:1.5}"
        ".wf{stroke:var(--accent);stroke-width:1.5;opacity:.45}.wd{stroke:var(--ctx);stroke-width:1;opacity:.5}"
        "</style>",
        f'<rect width="{width}" height="{height}" fill="var(--bg)"/>',
    ]
    for i, (name, cells) in enumerate(targets):
        ox = i * W_PANEL
        front = frontier(cells)
        parts.append(f'<g transform="translate({ox},0)">')
        parts.append(
            f'<text x="{PAD_L}" y="20" font-size="13" font-weight="600">{html.escape(name)}</text>'
        )
        for k in range(0, round(y_max * 10) + 1, 2 if y_max > 0.5 else 1):
            y = sy(k / 10)
            parts.append(
                f'<line class="g" x1="{PAD_L}" x2="{PAD_L + pw}" y1="{y:.1f}" y2="{y:.1f}"/>'
            )
            parts.append(
                f'<text class="m" x="{PAD_L - 6}" y="{y + 4:.1f}" text-anchor="end">{k * 10}%</text>'
            )
        for k in range(round(x_min * 10), 11):
            x = sx(k / 10)
            parts.append(
                f'<text class="m" x="{x:.1f}" y="{PAD_T + ph + 16}" text-anchor="middle">{k * 10}%</text>'
            )
        parts.append(
            f'<line class="ax" x1="{PAD_L}" x2="{PAD_L + pw}" y1="{PAD_T + ph}" y2="{PAD_T + ph}"/>'
        )
        parts.append(
            f'<text class="m" x="{PAD_L + pw / 2}" y="{PAD_T + ph + 32}" text-anchor="middle">'
            "benign tasks passed (higher is better)</text>"
        )
        if i == 0:
            parts.append(
                f'<text class="m" transform="translate(12,{PAD_T + ph / 2}) rotate(-90)" '
                'text-anchor="middle">attack success rate (lower is better)</text>'
            )
        order = sorted(cells.items(), key=lambda kv: (kv[0] in front, kv[1]["asr"]["rate"]))
        labeled: list[tuple[float, float]] = []
        for cfg, c in order:
            x, y = sx(c["utility"]["rate"]), sy(c["asr"]["rate"])
            lo, hi = sy(c["asr"]["low"]), sy(c["asr"]["high"])
            on = cfg in front
            tip = (
                f"{cfg}: ASR {_fmt(c['asr'])}, utility {_fmt(c['utility'])}, "
                f"median latency {c['latency_median_s']}s, guard {c['guard_ms_per_request']} ms/request"
            )
            parts.append(
                f'<line class="{"wf" if on else "wd"}" x1="{x:.1f}" x2="{x:.1f}" y1="{hi:.1f}" y2="{lo:.1f}"/>'
            )
            parts.append(
                f'<circle class="{"f" if on else "d"}" cx="{x:.1f}" cy="{y:.1f}" r="{5 if on else 4}">'
                f"<title>{html.escape(tip)}</title></circle>"
            )
            if on:
                ly = y + 4
                while any(abs(ly - py) < 12 and abs(x - px) < 90 for px, py in labeled):
                    ly += 12
                labeled.append((x, ly))
                anchor, lx = ("end", x - 9) if x > PAD_L + pw * 0.6 else ("start", x + 9)
                parts.append(
                    f'<text class="lbl" x="{lx:.1f}" y="{ly:.1f}" text-anchor="{anchor}">'
                    f"{html.escape(cfg)}</text>"
                )
        parts.append("</g>")
    parts.append("</svg>")
    return "\n".join(parts) + "\n"


def to_markdown(matrix: dict[str, Any]) -> str:
    lines: list[str] = []
    for name, cells in matrix["targets"].items():
        front = frontier(cells)
        lines += [
            f"#### {name}",
            "",
            "| configuration | ASR [95% CI] | critical ASR | benign passed | FP rate | utility retained "
            "| median latency (s) | guard ms / req | guard tokens / req |",
            "|---|---|---|---|---|---|---|---|---|",
        ]
        rows = sorted(
            cells.items(), key=lambda kv: (kv[1]["asr"]["rate"], -kv[1]["utility"]["rate"])
        )
        for cfg, c in rows:
            star = " ★" if cfg in front else ""
            ret = f"{c['utility_retained']:.2f}" if c.get("utility_retained") is not None else "-"
            lines.append(
                f"| {cfg}{star} | {c['asr']['k']}/{c['asr']['n']} {_fmt(c['asr'])} | "
                f"{c['critical_asr']['k']}/{c['critical_asr']['n']} | "
                f"{c['utility']['k']}/{c['utility']['n']} | {c['false_positive']['rate']:.0%} | {ret} | "
                f"{c['latency_median_s']} | {c['guard_ms_per_request']} | {c['guard_tokens_per_request']} |"
            )
        lines.append("")
    lines.append("★ = Pareto-optimal on (lower ASR, higher utility).")
    return "\n".join(lines) + "\n"
