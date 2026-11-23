# CLAUDE.md — Parry (parry-llm-redteam-lab)

Condensed project spec. Re-read at the start of every session and every phase.

## What Parry is
CLI + GitHub Action that runs repeatable attack suites against LLM apps (chatbots, RAG,
tool-using agents, MCP servers), measures attack success with confidence intervals, evaluates
guardrails, and reports results mapped to OWASP LLM Top 10 (2025) and MITRE ATLAS. Includes
deliberately vulnerable targets (DVWA for LLM apps), each with a hardened twin, and the
owner's own trained prompt-injection classifier. Owner: Gnanasudharsan Ashokumar.
Budget: $0 (open source, free tiers, local models). Dev machine: Apple Silicon Mac.

## Responsible scope (non-negotiable, enforced in `parry/scope.py`)
- Targets must be in `parry.yaml` AND named per run with `--i-own-this-target <name>`.
- Public endpoints refused unless `public_endpoint_acknowledged: true` AND `--allow-public-endpoints`.
- Benign proof only: canaries, fake secrets, local mock exfil endpoint, mock tools that only log.
- Jailbreaks use benign proxy goals; never elicit genuinely harmful content.
- Real vulns in others' projects → their SECURITY.md, coordinated disclosure, publish nothing early.

## Stack
Python 3.12 + uv · Typer · Pydantic v2 (`extra="forbid"`) · adapters: OpenAI-compatible, LiteLLM
(Gemini/Groq/Ollama), HTTP, LangGraph in-process, MCP (official Python SDK) · own plugin engine:
attack = generator + delivery channel + judge · channels: direct, retrieved docs, web pages, tool
outputs, MCP tool descriptions, multi-turn · baselines: garak, PyRIT, promptfoo (license permitting)
· judges: deterministic first, LLM judge only where needed, accuracy vs human labels · defenses:
local guard models (Ollama), spotlighting/data marking, instruction hierarchy, tool allowlists,
egress allowlists, output schema validation, own classifier · classifier: ModernBERT/DeBERTa-v3-small,
HF Transformers, MLflow, HF Hub + model card · targets: Docker Compose (FastAPI + LangGraph + small
vector store) · reports: HTML, JSON, SARIF · Langfuse self-hosted traces · docs site on GitHub Pages
· ruff, mypy strict, pytest, pre-commit, GitHub Actions. Verify current versions before adding deps.

## Layout
`parry/{cli,adapters,attacks,channels,judges,defenses,reporting,mapping}` · `parry/config.py`
(schema) · `parry/scope.py` (authorization gate) · `parry/metrics.py` (Wilson CIs) · `targets/`
· `classifier/` · `datasets/` · `docs/` (metrics.md, responsible-use.md, adr/) · `tests/`.

## Git rules
- Commit only as the existing git identity; never change `user.name`/`user.email`.
- NO AI attribution anywhere (no Co-Authored-By, "Generated with Claude Code", Claude-Session) in
  commits, PRs, tags, releases or code comments. Local `.git/hooks/commit-msg` strips them (not committed).
- Conventional commits, small logical commits. Apache-2.0.
- End of phase: update README status + CHANGELOG, commit `chore(release): complete phase N — <name>`,
  tag `phase-N`, push with tags, show URL.
- Never commit secrets or model weights. No force-push / history rewrite without approval.

## How to work
- Each phase: short plan → execute → acceptance checks → commit/tag/push → STOP with (a) built,
  (b) measured results, (c) USER ACTION REQUIRED, (d) next phase. Wait for "continue".
- Every README claim backed by a number produced by repo code. 95% Wilson CIs, fixed seeds.
- ADRs in `docs/adr/` for meaningful decisions. Code the owner can explain in an interview.
- Before commit: `make lint test`.

## Metrics (docs/metrics.md)
ASR per family/channel/target/defense with CIs · FPR on benign set · utility retained ·
latency/cost overhead · judge accuracy vs human labels · OWASP/ATLAS coverage.

## Phases
0 Foundation ✅ · 1 Vulnerable targets + hardened twins, canaries, mock exfil, 40+ benign tasks per
target · 2 Attack engine, families (direct/indirect injection, MCP tool poisoning, prompt extraction,
data leakage, excessive agency, multi-turn, encodings, output handling), judges + 200-label judge set,
`parry scan`/`parry report`, mapping · 3 Defense matrix, Pareto chart, baseline scanner comparison ·
4 Classifier (licensed data, held-out families, calibrated threshold, HF Hub model card) ·
5 GitHub Action (SARIF, PR comment, ASR threshold) + demo repo · 6 Case studies on owner's own apps
(Ramp, DecisionTrace) with explicit confirmation per target · 7 Docs site (tokens: ink #15191F,
slate #525C6B, paper #F7F8FA, surface #FFFFFF, line #DCE0E6, accent #1F4FD1; severity critical
#B42318, high #C2410C, medium #A15C07, low #5B6575, pass #13795B, always with icon + label; dark mode;
Inter Tight + JetBrains Mono; WCAG 2.2 AA; no gradients, no generic card grids, no ALL-CAPS eyebrows),
PyPI, blog post, v1.0.0 release.

## Notes
- OWASP IDs are the 2025 edition. ATLAS table is empty until Phase 2, when each ID is verified
  against the current ATLAS release.
- Owner's git email is stored with angle brackets in global config; git strips them in commits.
