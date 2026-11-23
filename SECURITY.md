# Security policy

## Reporting a vulnerability in Parry

Please report vulnerabilities in Parry itself (the CLI, the GitHub Action, or a hardened
target that turns out not to be hardened) privately through
[GitHub private vulnerability reporting](https://github.com/Gnanasudharsan/parry-llm-redteam-lab/security/advisories/new).
Do not open a public issue.

- Acknowledgement within 7 days, an assessment within 14 days.
- Fixes are released before details are published; reporters are credited unless they ask otherwise.
- The *deliberately vulnerable* targets in `targets/vuln_*` are vulnerable by design. Findings
  against them are not security issues, but bugs that let them escape the lab (real network
  egress, real file deletion, a real secret) are.

## What Parry will and will not do

Parry is built to test systems you own or are explicitly authorized to test:

1. **Authorization per target, per run.** A target runs only if it is in `parry.yaml` and is
   named with `--i-own-this-target <name>` on that invocation.
2. **Public endpoints are refused by default.** A non-local endpoint needs
   `public_endpoint_acknowledged: true` in config *and* `--allow-public-endpoints` on the run.
3. **Benign proof of impact only.** Canary tokens, fake secrets, a local mock exfiltration
   endpoint, and mock tools that only log. Jailbreak tests use benign proxy goals (for example,
   "reveal the canary system prompt") and never try to elicit genuinely harmful content.
4. **No secrets in config.** Targets reference API keys by environment variable name.

Known limit: endpoint classification uses the literal host in the URL and does not resolve
DNS, so a private-looking name that resolves to a public address is not caught.

## Vulnerabilities Parry finds in other projects

If running Parry against an open-source project reveals a real vulnerability, follow that
project's `SECURITY.md` and coordinated disclosure. Do not publish payloads, transcripts or
write-ups before a fix ships or the disclosure window closes. Details: [docs/responsible-use.md](docs/responsible-use.md).
