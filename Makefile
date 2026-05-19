COMPOSE_FILE=docker/node1/docker-compose.yml
ifeq ("$(wildcard .env)","")
ENV_FILE=.env.example
else
ENV_FILE=.env
endif
COMPOSE=docker compose -f $(COMPOSE_FILE) --env-file $(ENV_FILE)

# Cross-platform venv binary path
ifeq ($(OS),Windows_NT)
  VENV_BIN=.venv/Scripts
else
  VENV_BIN=.venv/bin
endif

.PHONY: help install lint format format-fix typecheck test test-critical \
        security-scan pre-commit-all clean \
        docker-check docker-up docker-ps docker-logs docker-down \
        docker-clean docker-restart docker-pull

help: ## Show this help message
	@grep -E '^[a-zA-Z_-]+:.*##' $(MAKEFILE_LIST) | \
	  awk 'BEGIN {FS = ":.*##"}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}' | sort

# ── Python / dev targets ──────────────────────────────────────────────────────

install: ## Create venv and install dev dependencies
	python -m venv .venv
	.venv/Scripts/pip install --upgrade pip || .venv/bin/pip install --upgrade pip
	.venv/Scripts/pip install -e ".[dev]" || .venv/bin/pip install -e ".[dev]"

lint: ## Run ruff linter
	$(VENV_BIN)/ruff check src/ tests/

format: ## Run ruff formatter (check only, no auto-fix)
	$(VENV_BIN)/ruff format --check src/ tests/

format-fix: ## Run ruff formatter with auto-fix
	$(VENV_BIN)/ruff format src/ tests/

typecheck: ## Run mypy strict type checking
	$(VENV_BIN)/mypy src/

test: ## Run full test suite with coverage
	@if find tests -name 'test_*.py' | grep -q .; then \
	  $(VENV_BIN)/pytest \
	    --cov=aegis.middleware.models \
	    --cov=aegis.middleware.risk_scorer \
	    --cov-report=xml \
	    --cov-fail-under=80; \
	else \
	  echo "No tests found — expected at this stage."; \
	fi

test-critical: ## Run only @pytest.mark.critical tests
	@$(VENV_BIN)/pytest -m critical --tb=short; \
	  code=$$?; \
	  if [ $$code -eq 5 ]; then echo "No critical tests found — expected at this stage."; exit 0; fi; \
	  exit $$code

security-scan: ## Run bandit + pip-audit
	$(VENV_BIN)/bandit -r src/ -ll
	$(VENV_BIN)/pip-audit

pre-commit-all: ## Run all pre-commit hooks on all files
	$(VENV_BIN)/pre-commit run --all-files

clean: ## Remove __pycache__, .mypy_cache, .ruff_cache, .pytest_cache
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	rm -rf .mypy_cache .ruff_cache .pytest_cache coverage.xml

# ── Docker / Node 1 targets ───────────────────────────────────────────────────

docker-check: ## Validate compose config
	$(COMPOSE) config

docker-up: ## Start Node 1 stack in detached mode
	$(COMPOSE) up -d --no-build --no-recreate

docker-ps: ## Show running services
	$(COMPOSE) ps

docker-logs: ## Follow logs for all services
	$(COMPOSE) logs -f --tail=200

docker-down: ## Stop stack
	$(COMPOSE) down

docker-clean: ## Stop stack and remove volumes
	$(COMPOSE) down -v --remove-orphans

docker-restart: ## Restart stack
	$(COMPOSE) stop
	$(COMPOSE) start

docker-pull: ## Pull latest images
	$(COMPOSE) pull
