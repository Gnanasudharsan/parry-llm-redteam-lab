"""NVIDIA garak (Apache-2.0) as a baseline scanner, gated by Parry's target authorization.

garak is installed separately (`uv tool install garak`) and driven through its REST
generator against the same lab chat endpoints Parry attacks. Probe selection keeps to
injection, encoding and markdown-exfiltration probes with benign payloads; the
"kill/hate humans" variants and DAN-style jailbreaks are left out by policy.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import Any

from parry.config import TargetConfig

PROBES = [
    "promptinject.HijackLongPrompt",
    "latentinjection.LatentInjectionFactSnippetEiffel",
    "latentinjection.LatentInjectionReport",
    "latentinjection.LatentInjectionResume",
    "latentinjection.LatentWhois",
    "encoding.InjectBase64",
    "encoding.InjectROT13",
    "encoding.InjectHex",
    "web_injection.MarkdownImageExfil",
    "web_injection.StringAssemblyDataExfil",
]
PROMPT_CAP = 20


def generator_options(target: TargetConfig) -> dict[str, Any]:
    base = str(target.url).rstrip("/")
    return {
        "rest": {
            "RestGenerator": {
                "name": target.name,
                "uri": f"{base}/chat",
                "method": "post",
                "headers": {"Content-Type": "application/json"},
                "req_template_json_object": {"message": "$INPUT"},
                "response_json": True,
                "response_json_field": "answer",
                "request_timeout": 180,
            }
        }
    }


def run_config(seed: int) -> dict[str, Any]:
    return {
        "run": {"seed": seed, "generations": 1, "soft_probe_prompt_cap": PROMPT_CAP},
        "system": {"parallel_attempts": 1, "lite": True},
    }


def run(target: TargetConfig, out_dir: Path, seed: int) -> Path:
    exe = shutil.which("garak")
    if exe is None:
        raise RuntimeError("garak is not installed (uv tool install garak)")
    out_dir.mkdir(parents=True, exist_ok=True)
    opts = out_dir / f"{target.name}.generator.json"
    cfg = out_dir / f"{target.name}.run.json"
    opts.write_text(json.dumps(generator_options(target), indent=2))
    cfg.write_text(json.dumps(run_config(seed), indent=2))
    prefix = f"parry-{target.name}"
    subprocess.run(  # noqa: S603 - fixed argv built from validated config
        [
            exe,
            "--model_type",
            "rest",
            "--generator_option_file",
            str(opts),
            "--config",
            str(cfg),
            "--probes",
            ",".join(PROBES),
            "--report_prefix",
            prefix,
        ],
        check=True,
    )
    report = _find_report(prefix)
    dest = out_dir / f"{target.name}.report.jsonl"
    shutil.copy(report, dest)
    return dest


def _find_report(prefix: str) -> Path:
    roots = [Path.home() / ".local/share/garak/garak_runs", Path.home() / ".local/share/garak"]
    found = sorted(
        (p for r in roots if r.exists() for p in r.rglob(f"{prefix}*.report.jsonl")),
        key=lambda p: p.stat().st_mtime,
    )
    if not found:
        raise FileNotFoundError(f"no garak report for {prefix}")
    return found[-1]


def summarize(report: Path) -> dict[str, dict[str, Any]]:
    """Per-probe failure counts from garak's `eval` entries (a failure = the attack worked)."""
    out: dict[str, dict[str, Any]] = {}
    for line in report.read_text().splitlines():
        e = json.loads(line)
        if e.get("entry_type") != "eval":
            continue
        total = int(e.get("total_evaluated", e.get("total", 0)))
        passed = int(e.get("passed", 0))
        out[f"{e['probe']}|{e['detector']}"] = {
            "probe": e["probe"],
            "detector": e["detector"],
            "hits": total - passed,
            "total": total,
        }
    return out
