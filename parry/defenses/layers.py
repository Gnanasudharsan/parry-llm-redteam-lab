"""Concrete defense layers. Guard models are reached over HTTP so apps stay small."""

from __future__ import annotations

import re

import httpx

from parry.defenses.base import Decision, Hook, timed

GUARD_TIMEOUT_S = 60.0


class LlamaGuard:
    """Llama Guard 3 via Ollama: a content-safety classifier (hazard categories S1-S14).

    It was trained for harmful content, not prompt injection; measuring it on injection
    attacks with benign goals shows what a safety guard does and does not cover.
    """

    hooks: frozenset[Hook] = frozenset({"input", "output"})

    def __init__(self, ollama_url: str, model: str = "llama-guard3:1b", name: str = "llama_guard"):
        self.url = ollama_url.rstrip("/")
        self.model = model
        self.name = name

    def check(self, hook: Hook, text: str) -> Decision:
        def run() -> Decision:
            messages = (
                [{"role": "user", "content": text}]
                if hook == "input"
                else [
                    {"role": "user", "content": "(conversation)"},
                    {"role": "assistant", "content": text},
                ]
            )
            r = httpx.post(
                f"{self.url}/api/chat",
                json={
                    "model": self.model,
                    "messages": messages,
                    "stream": False,
                    "options": {"temperature": 0, "num_predict": 20},
                },
                timeout=GUARD_TIMEOUT_S,
            )
            r.raise_for_status()
            data = r.json()
            verdict = data["message"]["content"].strip()
            tokens = int(data.get("prompt_eval_count", 0)) + int(data.get("eval_count", 0))
            unsafe = verdict.lower().startswith("unsafe")
            return Decision(
                layer=self.name, hook=hook, flagged=unsafe, reason=verdict[:60], tokens=tokens
            )

        return timed(self.name, hook, run)


class PromptInjectionClassifier:
    """An encoder classifier served by `parry guard serve` (default: ProtectAI DeBERTa-v3 v2)."""

    hooks: frozenset[Hook] = frozenset({"input", "untrusted"})

    def __init__(
        self,
        guard_url: str,
        threshold: float = 0.5,
        model: str = "protectai",
        name: str = "pi_classifier",
    ):
        self.url = guard_url.rstrip("/")
        self.threshold = threshold
        self.model = model
        self.name = name

    def check(self, hook: Hook, text: str) -> Decision:
        def run() -> Decision:
            r = httpx.post(
                f"{self.url}/classify",
                json={"model": self.model, "texts": [text]},
                timeout=GUARD_TIMEOUT_S,
            )
            r.raise_for_status()
            res = r.json()["results"][0]
            score = float(res["injection_score"])
            return Decision(
                layer=self.name,
                hook=hook,
                flagged=score >= self.threshold,
                score=score,
                reason=f"injection score {score:.2f}",
                tokens=int(res.get("tokens", 0)),
            )

        return timed(self.name, hook, run)


# Secret formats an operator knows about their own system: a literal prefix plus a body of
# N hex characters. Characters may be separated by spaces or punctuation, which catches the
# "spell it with spaces" bypass of exact redaction, while ordinary words ("seasonal staff")
# never match because the hex body is required.
SECRET_FORMATS: tuple[tuple[str, int], ...] = (
    ("PARRY-CANARY-", 12),
    ("PARRY-DOC-", 12),
    ("hv_fake_sk_", 24),
    ("STAFF-", 8),
)
_SEP = r"[\W_]*"
_URL = re.compile(
    r"(?:!\[[^\]]*\]\(|<img[^>]+src=[\"']?|\]\(|https?://)([^\s)\"'>]+)", re.IGNORECASE
)


def _format_pattern(prefix: str, body: int) -> str:
    chars = [re.escape(c) for c in prefix if c.isalnum()]
    return _SEP.join(chars) + _SEP + f"(?:[0-9a-f]{_SEP}){{{body - 1}}}[0-9a-f]"


class OutputValidator:
    """Rule-based output validation: no secret-shaped tokens, no links to unknown hosts.

    Deterministic and free; it only knows formats the operator configures, so it is tied to
    these lab formats and is not a general secret detector.
    """

    hooks: frozenset[Hook] = frozenset({"output"})
    name = "output_validator"

    def __init__(
        self,
        formats: tuple[tuple[str, int], ...] = SECRET_FORMATS,
        trusted_hosts: tuple[str, ...] = ("harborview.test",),
    ) -> None:
        self.patterns = [re.compile(_format_pattern(p, n), re.IGNORECASE) for p, n in formats]
        self.trusted = trusted_hosts

    def _external(self, text: str) -> list[str]:
        out = []
        for m in _URL.finditer(text):
            target = m.group(1)
            host = re.sub(r"^https?://", "", target).split("/")[0].split("?")[0].lower()
            if "." in host and not any(host == t or host.endswith("." + t) for t in self.trusted):
                out.append(host)
        return out

    def check(self, hook: Hook, text: str) -> Decision:
        def run() -> Decision:
            secrets = [p.pattern for p in self.patterns if p.search(text)]
            hosts = self._external(text)
            reason = "; ".join(
                filter(
                    None,
                    [
                        f"secret-shaped token x{len(secrets)}" if secrets else "",
                        f"external link {hosts[0]}" if hosts else "",
                    ],
                )
            )
            return Decision(
                layer=self.name, hook=hook, flagged=bool(secrets or hosts), reason=reason
            )

        return timed(self.name, hook, run)
