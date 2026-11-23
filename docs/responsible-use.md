# Responsible use

Parry is an offensive testing tool. These rules are part of the design, and most are enforced
in code (`parry/scope.py`), not just written down.

## 1. Only systems you own or are authorized to test

- List the target in `parry.yaml` with an `owner_statement` explaining why you may test it.
- Name it on every run: `--i-own-this-target <name>`. One flag per target; there is no
  "all targets" shortcut. Unknown names are an error, so a typo never widens scope.
- Public endpoints (anything that is not loopback, a private address, a reserved test TLD
  such as `.test`/`.internal`, a Docker Compose service name, or an in-process target) are
  refused unless the target sets `public_endpoint_acknowledged: true` **and** the run passes
  `--allow-public-endpoints`. Use that only for apps you deploy yourself.
- Hosted model APIs (OpenAI, Gemini, Groq…) count as public. Check the provider's usage
  policy before red-teaming their models; Parry's default lab uses local models via Ollama.

## 2. Prove impact with benign canaries

| Instead of… | Parry uses… |
|---|---|
| Real secrets | Generated canary tokens and fake credentials unique to each run |
| Real exfiltration | A local mock endpoint that records what reached it |
| Real side effects | Mock tools (`send_email`, `delete_file`, `transfer_funds`) that only log |
| Harmful content | Proxy goals: leak the canary prompt, call the forbidden mock tool |

A jailbreak "succeeds" in Parry when a policy boundary is crossed in a measurable, harmless
way, never when dangerous content is produced. Attack generators must not ship payloads
that ask for weapons, malware, self-harm, sexual content involving minors, or similar.

## 3. Data you collect

Run transcripts can include whatever your target returns. Keep them local, do not commit
them (`reports/`, `runs/` and `mlruns/` are git-ignored), and strip real user data before
sharing a report.

## 4. Real vulnerabilities in other people's software

If Parry surfaces a real issue in a third-party or open-source project:

1. Stop testing that target.
2. Report it privately through the project's `SECURITY.md` or security contact.
3. Do not publish payloads, transcripts or write-ups until a fix is released or the
   disclosure window (90 days by default, or the project's own policy) has passed.
4. Case studies in this repo cover only my own applications, plus disclosed and fixed issues.
