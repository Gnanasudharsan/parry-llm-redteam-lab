"""Client for the Parry lab admin API (targets/lab/admin.py) and the mock web recorder.

Only used for targets with `lab: true`. It lets the engine reset state between trials,
plant attacker content, and read back what happened, so judges never have to guess.
"""

from __future__ import annotations

import os
from typing import Any
from urllib.parse import urlsplit, urlunsplit

import httpx

from parry.canary import LabSecrets, secrets_for
from parry.config import ParryConfig, TargetConfig

DEFAULT_TOKEN = "parry-lab-admin"  # noqa: S105 - the lab's documented default


def base_url(target: TargetConfig) -> str:
    parts = urlsplit(str(target.url))
    return urlunsplit((parts.scheme, parts.netloc, "", "", "")).rstrip("/")


class LabClient:
    def __init__(self, cfg: ParryConfig, target: TargetConfig) -> None:
        if not target.lab:
            raise ValueError(f"target '{target.name}' is not a lab target")
        self.target = target
        self.base = base_url(target)
        self.mockweb = str(cfg.lab.mockweb_url).rstrip("/")
        self.headers = {"X-Lab-Token": os.environ.get(cfg.lab.admin_token_env, DEFAULT_TOKEN)}
        self.seed = os.environ.get(cfg.lab.seed_env)
        self.http = httpx.Client(timeout=30, headers=self.headers)

    def configure(
        self,
        hardening: dict[str, bool] | None = None,
        defenses: list[str] | None = None,
        restore: bool = True,
    ) -> dict[str, Any]:
        """Set the target's hardening flags and defense layers at runtime."""
        body = {"hardening": hardening, "defenses": defenses, "restore": restore}
        return dict(self.http.put(f"{self.base}/_lab/config", json=body).raise_for_status().json())

    def secrets(self) -> LabSecrets:
        """Recomputed locally from the seed; never read from the target."""
        return secrets_for(self.target.name, self.seed)

    def state(self) -> dict[str, Any]:
        return dict(self.http.get(f"{self.base}/_lab/state").raise_for_status().json())

    def reset(self) -> None:
        self.http.post(f"{self.base}/_lab/reset").raise_for_status()
        self.http.post(f"{self.mockweb}/_lab/reset").raise_for_status()

    def events(self, since: int = 0) -> list[dict[str, Any]]:
        r = self.http.get(f"{self.base}/_lab/events", params={"since": since})
        return list(r.raise_for_status().json())

    def hits(self, host: str | None = None) -> list[dict[str, Any]]:
        params = {"host": host} if host else {}
        return list(
            self.http.get(f"{self.mockweb}/_lab/hits", params=params).raise_for_status().json()
        )

    def put_page(self, host: str, path: str, html: str) -> None:
        body = {"host": host, "path": path, "html": html}
        self.http.put(f"{self.mockweb}/_lab/pages", json=body).raise_for_status()

    def plant_email(self, sender: str, subject: str, body: str) -> str:
        r = self.http.post(
            f"{self.base}/_lab/inbox", json={"sender": sender, "subject": subject, "body": body}
        )
        return str(r.raise_for_status().json()["id"])

    def plant_file(self, path: str, content: str) -> None:
        self.http.post(
            f"{self.base}/_lab/files", json={"path": path, "content": content}
        ).raise_for_status()

    def install_plugin(self, name: str, description: str) -> dict[str, Any]:
        r = self.http.post(
            f"{self.base}/_lab/plugins", json={"name": name, "description": description}
        )
        return dict(r.raise_for_status().json())

    def public_post(self, path: str, body: dict[str, Any]) -> httpx.Response:
        """A request any user of the app could make (e.g. posting a product review)."""
        return httpx.post(f"{self.base}{path}", json=body, timeout=60)
