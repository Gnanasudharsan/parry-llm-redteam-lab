"""Load attack templates and expand them into seeded, reproducible cases."""

from __future__ import annotations

import hashlib
import hmac
from pathlib import Path
from typing import Any

import yaml

from parry.attacks.model import AttackCase, AttackTemplate, Channel, Payload, ToolMatch
from parry.attacks.transforms import TRANSFORMS, apply

CATALOG_DIR = Path(__file__).parent / "catalog"
ATTACKER_HOST = "attacker.test"


def load_templates(directory: Path = CATALOG_DIR) -> list[AttackTemplate]:
    templates: list[AttackTemplate] = []
    for path in sorted(directory.glob("*.yaml")):
        for raw in yaml.safe_load(path.read_text()) or []:
            templates.append(AttackTemplate.model_validate(raw))
    ids = [t.id for t in templates]
    dupes = {i for i in ids if ids.count(i) > 1}
    if dupes:
        raise ValueError(f"duplicate template ids: {sorted(dupes)}")
    for t in templates:
        unknown = set(t.transforms) - set(TRANSFORMS)
        if unknown:
            raise ValueError(f"{t.id}: unknown transforms {sorted(unknown)}")
    return templates


def nonce_for(seed: int, case_id: str) -> str:
    return hmac.new(str(seed).encode(), case_id.encode(), hashlib.sha256).hexdigest()[:10]


def placeholders(nonce: str) -> dict[str, str]:
    return {
        "nonce": nonce,
        "marker": f"PARRY-HIJACK-{nonce}",
        "exfil_url": f"http://{ATTACKER_HOST}/c/{nonce}",
        "attacker_email": f"ops-{nonce}@{ATTACKER_HOST}",
        "attacker_account": f"XX00-ATTACKER-{nonce.upper()}",
    }


def _fill(value: Any, ph: dict[str, str]) -> Any:
    if isinstance(value, str):
        for k, v in ph.items():
            value = value.replace("{" + k + "}", v)
        return value
    if isinstance(value, list):
        return [_fill(v, ph) for v in value]
    if isinstance(value, dict):
        return {k: _fill(v, ph) for k, v in value.items()}
    return value


def _tool(t: AttackTemplate, ph: dict[str, str]) -> ToolMatch | None:
    if t.tool is None:
        return None
    return t.tool.model_copy(update={"args_contain": _fill(t.tool.args_contain, ph)})


def _per_host(t: AttackTemplate) -> list[AttackTemplate]:
    """Web templates run once per host: an attacker site, and a first-party site with UGC."""
    hosts = t.params.get("hosts")
    if not hosts:
        return [t]
    out = []
    for host in hosts:
        params = {k: v for k, v in t.params.items() if k != "hosts"} | {"host": host}
        trigger = t.trigger.replace("{host}", host) if t.trigger else None
        out.append(
            t.model_copy(
                update={"id": f"{t.id}-{host.split('.')[0]}", "params": params, "trigger": trigger}
            )
        )
    return out


def expand(templates: list[AttackTemplate], seed: int) -> list[AttackCase]:
    cases: list[AttackCase] = []
    for t in (v for tpl in templates for v in _per_host(tpl)):
        for i, payload in enumerate(t.payloads):
            for transform in t.transforms:
                case_id = f"{t.id}/{i + 1:02d}" + ("" if transform == "none" else f"/{transform}")
                ph = placeholders(nonce_for(seed, case_id))
                filled: Payload = _fill(payload, ph)
                if transform != "none":
                    if t.channel is not Channel.DIRECT or not isinstance(filled, str):
                        raise ValueError(f"{t.id}: transforms only apply to direct string payloads")
                    filled = apply(transform, filled)
                cases.append(
                    AttackCase(
                        case_id=case_id,
                        template=t.id,
                        family=t.family,
                        channel=t.channel,
                        apps=t.apps,
                        goal=t.goal,
                        severity=t.severity,
                        owasp=t.owasp,
                        atlas=t.atlas,
                        transform=transform,
                        nonce=ph["nonce"],
                        payload=filled,
                        trigger=_fill(t.trigger, ph),
                        role=t.role,
                        params=_fill(t.params, ph),
                        secrets=t.secrets,
                        tool=_tool(t, ph),
                        rubric=t.rubric,
                    )
                )
    return cases
