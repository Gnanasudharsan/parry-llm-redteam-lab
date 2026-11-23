.DEFAULT_GOAL := help
COMPOSE := docker compose -f targets/compose.yaml
CONFIG ?= parry.yaml

.PHONY: help install lint fmt test targets-up targets-down scan eval

help: ## Show targets
	@grep -E '^[a-z-]+:.*## ' $(MAKEFILE_LIST) | awk -F':.*## ' '{printf "  %-14s %s\n", $$1, $$2}'

install: ## Install deps and git hooks
	uv sync
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

targets-up: ## Start lab targets (Phase 1)
	@test -f targets/compose.yaml || { echo "targets/compose.yaml arrives in Phase 1"; exit 1; }
	$(COMPOSE) up -d --build

targets-down: ## Stop lab targets
	@test -f targets/compose.yaml || { echo "targets/compose.yaml arrives in Phase 1"; exit 1; }
	$(COMPOSE) down

scan: ## Run a scan (Phase 2): make scan OWN="--i-own-this-target vuln-rag"
	@uv run parry scan --help >/dev/null 2>&1 || { echo "parry scan arrives in Phase 2"; exit 1; }
	uv run parry scan -c $(CONFIG) $(OWN)

eval: ## Run the defense evaluation matrix (Phase 3)
	@echo "defense evaluation arrives in Phase 3"; exit 1
