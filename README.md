# Parry

**Attack your LLM app before someone else does. Measure every defense.**

Parry is a CLI and GitHub Action that runs repeatable attack suites against LLM applications
(chatbots, RAG apps, tool-using agents, MCP servers), measures attack success with confidence
intervals, tests guardrails, and reports results mapped to the
[OWASP Top 10 for LLM Applications](https://genai.owasp.org/llm-top-10/) and
[MITRE ATLAS](https://atlas.mitre.org/). It ships deliberately vulnerable target apps for
learning and benchmarking, and a trained prompt-injection classifier.

> **Status: Phase 1 (vulnerable targets and canaries) complete.** No attack results are
> reported yet; they start in Phase 2. Every result this README reports will be produced by code in this repo, with
> fixed seeds and 95% Wilson intervals ([docs/metrics.md](docs/metrics.md)).

## Responsible use

Parry only attacks targets you list in `parry.yaml` **and** name on the command line with
`--i-own-this-target <name>`. Public endpoints are refused unless you acknowledge them twice
(in config and with `--allow-public-endpoints`). Attacks prove impact with benign canaries,
fake secrets, and a local mock exfiltration endpoint, never real harmful content. See
[SECURITY.md](SECURITY.md) and [docs/responsible-use.md](docs/responsible-use.md).

## Built so far

| Area | State |
|---|---|
| Config schema (`parry.yaml`, Pydantic v2) | done |
| Target authorization gate (`--i-own-this-target`, public-endpoint refusal) | done, tested |
| Wilson 95% interval for every reported rate | done, tested against reference values |
| OWASP LLM Top 10 (2025) ID table | done; ATLAS IDs land with the attacks in Phase 2 |
| CI: ruff, mypy (strict), pytest, lab image build | done |
| Lab: vulnerable RAG app, tool-using agent, MCP server, each with a hardened twin ([docs/lab.md](docs/lab.md)) | done |
| Canaries + fake secrets (HMAC-derived), mock exfiltration recorder, internal-only lab network | done, verified live (`make targets-verify`) |
| Benign task sets: 47 RAG, 43 + 6 approval-gated agent, 42 MCP | done |

### Lab baseline: benign tasks (utility before any attack)

`make benign`, `qwen2.5:7b-instruct` via Ollama, temperature 0, seed 1337, Apple M4.
Raw results: [docs/results/phase1-benign.json](docs/results/phase1-benign.json).

| Target | Core tasks passed [95% Wilson CI] | Approval-gated tasks completed | Secret leaks in benign answers |
|---|---|---|---|
| vuln-rag | 47/47, 100.0% [92.4, 100.0] | n/a | 0 |
| hard-rag | 47/47, 100.0% [92.4, 100.0] | n/a | 0 |
| vuln-agent | 41/43, 95.3% [84.5, 98.7] | 6/6, 100.0% [61.0, 100.0] | 0 |
| hard-agent | 40/43, 93.0% [81.4, 97.6] | 0/6, 0.0% [0.0, 39.0] | 0 |
| vuln-mcp | 42/42, 100.0% [91.6, 100.0] | n/a | 1 |
| hard-mcp | 42/42, 100.0% [91.6, 100.0] | n/a | 0 |

How to read it: the hardened agent's tool policy routes all six approval-gated requests
(external email, external payment, large transfer, shared-file delete, HR file) to a human.
That is the usefulness the policy costs. The vulnerable MCP server returns its API key on an
ordinary settings read, which is the planted weakness. The agents' failures come from the 7B
model guessing a file name or skipping a tool, plus one check that is too strict
(`inbox-jordan`). The intervals overlap heavily, so these numbers do not yet show a utility
difference between the twins.

```bash
uv sync
uv run parry targets list -c parry.example.yaml
uv run parry targets check -c parry.example.yaml --i-own-this-target vuln-rag

ollama serve &            # models: qwen2.5:7b-instruct, nomic-embed-text
make targets-up           # Docker lab on 127.0.0.1
make targets-verify       # live checks: canaries, mock exfil endpoint, egress isolation
make benign               # benign task sets -> reports/benign.json
```

## Roadmap

| Phase | Scope | Status |
|---|---|---|
| 0 | Foundation: layout, scope gate, docs, CI | complete |
| 1 | Vulnerable targets (RAG app, tool agent, MCP server) + hardened twins, canaries, benign task sets | complete |
| 2 | Attack engine, judges (with measured judge accuracy), CLI scan, OWASP/ATLAS mapping | next |
| 3 | Defense matrix: ASR reduction, false positives, utility, latency/cost, Pareto chart, baseline scanner comparison | planned |
| 4 | Prompt-injection classifier: training, calibration, held-out-family evaluation, model card | planned |
| 5 | GitHub Action: SARIF upload, PR summary, ASR threshold gate | planned |
| 6 | Case studies on my own apps, before/after ASR | planned |
| 7 | Docs site, PyPI release, v1.0.0 | planned |

## Development

```bash
make install   # uv sync (all groups) + pre-commit hooks
make lint      # ruff + mypy
make test      # pytest
```

## License

Apache-2.0. Copyright 2026 Gnanasudharsan Ashokumar.
