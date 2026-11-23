.DEFAULT_GOAL := help
COMPOSE := docker compose -f targets/compose.yaml
CONFIG ?= parry.yaml

.PHONY: help install lint fmt test targets-up targets-down targets-verify benign scan eval

help: ## Show targets
	@grep -E '^[a-z-]+:.*## ' $(MAKEFILE_LIST) | awk -F':.*## ' '{printf "  %-14s %s\n", $$1, $$2}'

install: ## Install deps and git hooks
	uv sync --all-groups
	uv run pre-commit install

lint: ## ruff + format check + mypy
	uv run ruff check .
	uv run ruff format --check .
	uv run mypy

fmt: ## Auto-format
	uv run ruff check --fix .
	uv run ruff format .

test: ## Run tests
	uv run pytest

targets-up: ## Start lab targets (needs Ollama running on the host)
	@curl -sf http://localhost:11434/api/version >/dev/null || { echo "Ollama is not running: start it with 'ollama serve'"; exit 1; }
	$(COMPOSE) up -d --build --wait

targets-down: ## Stop lab targets
	$(COMPOSE) down

targets-verify: ## Live checks: health, canaries, mock exfil endpoint, egress isolation
	uv run python -m targets.verify

benign: ## Run benign task sets on all lab targets (OUT=reports/benign.json)
	uv run python -m targets.benign.run -c targets/parry.lab.yaml \
		$(foreach t,vuln-rag hard-rag vuln-agent hard-agent vuln-mcp hard-mcp,--i-own-this-target $(t)) \
		--out $(or $(OUT),reports/benign.json)

LAB_TARGETS := vuln-rag hard-rag vuln-agent hard-agent vuln-mcp hard-mcp

scan: ## Attack suite on the lab (override CONFIG and OWN for your own targets)
	uv run parry scan -c $(or $(CONFIG_SCAN),targets/parry.lab.yaml) \
		$(or $(OWN),$(foreach t,$(LAB_TARGETS),--i-own-this-target $(t)))

eval: ## Run the defense evaluation matrix (Phase 3)
	@echo "defense evaluation arrives in Phase 3"; exit 1
