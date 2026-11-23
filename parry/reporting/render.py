"""Render a run summary as Markdown or a small self-contained HTML page."""

from __future__ import annotations

import html
from typing import Any


def cell(r: dict[str, Any]) -> str:
    if not r["n"]:
        return "-"
    return f"{r['k']}/{r['n']} {r['rate']:.0%} [{r['low']:.0%}, {r['high']:.0%}]"


def _matrix(summary: dict[str, Any], dim: str, title: str, metric: str = "asr") -> list[str]:
    targets = list(summary["targets"])
    keys = sorted({k for t in summary["targets"].values() for k in t[dim]})
    lines = [
        f"### {title}",
        "",
        "| " + " | ".join([dim.removeprefix("by_"), *targets]) + " |",
        "|" + "---|" * (len(targets) + 1),
    ]
    for k in keys:
        row = [
            cell(summary["targets"][t][dim][k][metric]) if k in summary["targets"][t][dim] else "-"
            for t in targets
        ]
        lines.append(f"| {k} | " + " | ".join(row) + " |")
    return [*lines, ""]


def to_markdown(summary: dict[str, Any], meta: dict[str, Any]) -> str:
    out = [
        f"# Parry scan {meta.get('run_id', '')}",
        "",
        f"Seed {meta.get('seed')} · cases {meta.get('cases_hash')} · "
        f"commit {meta.get('git_commit')} · judge model {meta.get('judge_model')}",
        "",
        "Attack success rate (ASR) = successful trials / scored trials, with 95% Wilson intervals.",
        "Attempt rate also counts trials where the target was steered but a control stopped "
        "the effect.",
        "",
        "| target | profile | model | ASR | attempt rate | critical ASR |",
        "|---|---|---|---|---|---|",
    ]
    for name, t in summary["targets"].items():
        out.append(
            f"| {name} | {t['profile']} | {t['model']} | {cell(t['overall']['asr'])} | "
            f"{cell(t['overall']['attempt'])} | {cell(t['critical']['asr'])} |"
        )
    tot = summary["totals"]
    out += [
        "",
        f"Trials {tot['trials']}, scored {tot['scored']}, skipped {tot['skipped']}, "
        f"errors {tot['errors']}.",
        "",
    ]
    out += _matrix(summary, "by_family", "ASR by attack family")
    out += _matrix(summary, "by_channel", "ASR by delivery channel")
    out += _matrix(summary, "by_channel", "Planted content confirmed delivered", "delivered")
    out += _matrix(summary, "by_channel", "ASR over delivered trials only", "asr_delivered")
    out += _matrix(summary, "by_goal", "ASR by goal")
    if summary.get("coverage"):
        out += [
            "### Coverage (from attack metadata)",
            "",
            "| ID | name | cases | families |",
            "|---|---|---|---|",
        ]
        for tid, c in summary["coverage"].items():
            fams = ", ".join(c["families"]) or "not covered"
            out.append(f"| {tid} | {c['name']} | {c['cases']} | {fams} |")
    return "\n".join(out) + "\n"


def to_html(markdown: str, title: str) -> str:
    """Minimal HTML: tables and headings from the Markdown report, no external assets."""
    body: list[str] = []
    in_table = False
    for line in markdown.splitlines():
        if line.startswith("|"):
            cells = [html.escape(c.strip()) for c in line.strip("|").split("|")]
            if set("".join(cells)) <= set("-"):
                continue
            tag = "th" if not in_table else "td"
            if not in_table:
                body.append("<table>")
                in_table = True
            body.append("<tr>" + "".join(f"<{tag}>{c}</{tag}>" for c in cells) + "</tr>")
            continue
        if in_table:
            body.append("</table>")
            in_table = False
        if line.startswith("### "):
            body.append(f"<h2>{html.escape(line[4:])}</h2>")
        elif line.startswith("# "):
            body.append(f"<h1>{html.escape(line[2:])}</h1>")
        elif line.strip():
            body.append(f"<p>{html.escape(line)}</p>")
    if in_table:
        body.append("</table>")
    css = (
        "body{font:14px/1.5 system-ui,sans-serif;color:#15191F;background:#F7F8FA;"
        "margin:2rem auto;max-width:1100px;padding:0 16px}"
        "table{border-collapse:collapse;background:#fff;margin:1rem 0;"
        "font-variant-numeric:tabular-nums}"
        "td,th{border:1px solid #DCE0E6;padding:4px 8px;text-align:left}th{background:#F7F8FA}"
        "@media(prefers-color-scheme:dark){body{background:#0f1216;color:#e6e8eb}"
        "table{background:#171b21}td,th{border-color:#2a3038}th{background:#1d2229}}"
    )
    return (
        f"<!doctype html><html lang=en><head><meta charset=utf-8><meta name=viewport "
        f"content='width=device-width,initial-scale=1'><title>{html.escape(title)}</title>"
        f"<style>{css}</style></head><body>{''.join(body)}</body></html>"
    )
