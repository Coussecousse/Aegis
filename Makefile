COMPOSE_FILE=docker/node1/docker-compose.yml
ifeq ("$(wildcard .env)","")
ENV_FILE=.env.example
else
ENV_FILE=.env
endif
COMPOSE=docker compose -f $(COMPOSE_FILE) --env-file $(ENV_FILE)
COMPOSE_FULL=$(COMPOSE) --profile full

# Cross-platform venv binary path
ifeq ($(OS),Windows_NT)
  VENV_BIN=.venv/Scripts
else
  VENV_BIN=.venv/bin
endif

.PHONY: help install lint format format-fix typecheck test test-critical \
        benchmark-ci benchmark benchmark-quality benchmark-quality-score benchmark-load \
        security-scan pre-commit-all clean \
	docker-check docker-build docker-up docker-up-core docker-up-full docker-ps docker-logs \
	docker-down docker-clean docker-restart docker-pull docker-pull-full \
	docker-poc-up docker-poc-down \
	docker-juiceshop-up docker-juiceshop-down

help: ## Show this help message
	@grep -E '^[a-zA-Z_-]+:.*##' $(MAKEFILE_LIST) | \
	  awk 'BEGIN {FS = ":.*##"}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}' | sort

# ── Python / dev targets ──────────────────────────────────────────────────────

install: ## Create venv and install dev dependencies
	python -m venv .venv
	$(VENV_BIN)/pip install --upgrade pip
	$(VENV_BIN)/pip install -e ".[dev]"

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

benchmark-ci: ## Run Level-1 KPI benchmarks (deterministic, no Pi); writes docs/benchmarks/kpi-ci-latest.json
	$(VENV_BIN)/pytest -m benchmark --no-cov --tb=short

benchmark: ## Live KPI run (needs stack + Pi). SCENARIO=all INTENSITY=standard
	$(VENV_BIN)/python -m scripts.benchmark.run_attack_suite \
	  --scenario "$(or $(SCENARIO),all)" --intensity "$(or $(INTENSITY),standard)" \
	  | tee /tmp/aegis-bench-window.txt
	@since=$$(grep -o '"t0": "[^"]*"' /tmp/aegis-bench-window.txt | head -1 | cut -d'"' -f4); \
	until=$$(grep -o '"t1": "[^"]*"' /tmp/aegis-bench-window.txt | head -1 | cut -d'"' -f4); \
	$(VENV_BIN)/python -m scripts.benchmark.collect_kpis --since "$$since" --until "$$until"

benchmark-quality: ## Phase 1: fire corpus attacks for quality scoring (needs report_sink + SHUFFLE_WEBHOOK_URL set to it). SCENARIO=all
	$(VENV_BIN)/python -m scripts.benchmark.run_attack_suite --phase quality \
	  --scenario "$(or $(SCENARIO),all)" --intensity "$(or $(INTENSITY),smoke)" \
	  --manifest /tmp/aegis-quality-manifest.json
	@echo "Wait for the Pi to produce reports, then: make benchmark-quality-score"

benchmark-quality-score: ## Phase 1: grade captured reports vs the corpus
	$(VENV_BIN)/python -m scripts.benchmark.score_phase1 \
	  --manifest /tmp/aegis-quality-manifest.json --reports /tmp/aegis-reports.jsonl

benchmark-load: ## Phase 2: soak load + zero-loss + resource KPIs (needs stack + Pi)
	$(VENV_BIN)/python -m scripts.benchmark.run_attack_suite --phase load \
	  --scenario "$(or $(SCENARIO),all)" --intensity "$(or $(INTENSITY),soak)" \
	  | tee /tmp/aegis-bench-window.txt
	@since=$$(grep -o '"t0": "[^"]*"' /tmp/aegis-bench-window.txt | head -1 | cut -d'"' -f4); \
	until=$$(grep -o '"t1": "[^"]*"' /tmp/aegis-bench-window.txt | head -1 | cut -d'"' -f4); \
	echo "Waiting 60s for the pipeline to drain before measuring..."; sleep 60; \
	$(VENV_BIN)/python -m scripts.benchmark.collect_kpis --since "$$since" --until "$$until" --check-loss

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

docker-build: ## Build middleware and collector images
	$(COMPOSE) build middleware collector

docker-up: ## Start Node 1 core stack in detached mode (without Shuffle)
	$(COMPOSE) up -d --no-build --no-recreate

docker-up-core: ## Alias of docker-up (without Shuffle)
	$(COMPOSE) up -d --no-build --no-recreate

docker-up-full: ## Start full Node 1 stack including Shuffle SOAR
	$(COMPOSE_FULL) up -d --no-build --no-recreate

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

docker-pull: ## Pull latest images for core stack (without Shuffle)
	$(COMPOSE) pull

docker-pull-full: ## Pull latest images including Shuffle services
	$(COMPOSE_FULL) pull

docker-poc-up: ## Start POC OpenLDAP stack (requires main stack running first)
	docker compose -f docker/node1/docker-compose.poc.yml --env-file $(ENV_FILE) up -d

docker-poc-down: ## Stop POC OpenLDAP stack
	docker compose -f docker/node1/docker-compose.poc.yml --env-file $(ENV_FILE) down

docker-juiceshop-up: ## Start Juice Shop + nginx attack target (port 9080)
	docker compose -f docker/node1/docker-compose.juiceshop.yml up -d

docker-juiceshop-down: ## Stop Juice Shop stack
	docker compose -f docker/node1/docker-compose.juiceshop.yml down
