# Parry

**Attack your LLM app before someone else does. Measure every defense.**

Parry is a CLI and GitHub Action that runs repeatable attack suites against LLM applications
(chatbots, RAG apps, tool-using agents, MCP servers), measures attack success with confidence
intervals, tests guardrails, and reports results mapped to the
[OWASP Top 10 for LLM Applications](https://genai.owasp.org/llm-top-10/) and
[MITRE ATLAS](https://atlas.mitre.org/). It ships deliberately vulnerable target apps for
learning and benchmarking, and a trained prompt-injection classifier.

> **Status: Phase 0 (foundation) complete.** No attack results are reported yet; they start
> in Phase 2. Every result this README reports will be produced by code in this repo, with
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
| CI: ruff, mypy (strict), pytest | done |

```bash
uv sync
uv run parry targets list -c parry.example.yaml
uv run parry targets check -c parry.example.yaml --i-own-this-target vuln-rag
```

## Roadmap

| Phase | Scope | Status |
|---|---|---|
| 0 | Foundation: layout, scope gate, docs, CI | complete |
| 1 | Vulnerable targets (RAG app, tool agent, MCP server) + hardened twins, canaries, benign task sets | next |
| 2 | Attack engine, judges (with measured judge accuracy), CLI scan, OWASP/ATLAS mapping | planned |
| 3 | Defense matrix: ASR reduction, false positives, utility, latency/cost, Pareto chart, baseline scanner comparison | planned |
| 4 | Prompt-injection classifier: training, calibration, held-out-family evaluation, model card | planned |
| 5 | GitHub Action: SARIF upload, PR summary, ASR threshold gate | planned |
| 6 | Case studies on my own apps, before/after ASR | planned |
| 7 | Docs site, PyPI release, v1.0.0 | planned |

## Development

```bash
make install   # uv sync + pre-commit hooks
make lint      # ruff + mypy
make test      # pytest
```

## License

Apache-2.0. Copyright 2026 Gnanasudharsan Ashokumar.
