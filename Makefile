COMPOSE_FILE=docker/node1/docker-compose.yml
ifeq ("$(wildcard .env)","")
ENV_FILE=.env.example
else
ENV_FILE=.env
endif
COMPOSE=docker compose -f $(COMPOSE_FILE) --env-file $(ENV_FILE)

.PHONY: help docker-check docker-up docker-ps docker-logs docker-down docker-clean docker-restart docker-pull

help:
	@echo "AEGIS Docker commands"
	@echo "  make docker-check    Validate compose config"
	@echo "  make docker-up       Start Node 1 stack in detached mode"
	@echo "  make docker-ps       Show running services"
	@echo "  make docker-logs     Follow logs for all services"
	@echo "  make docker-down     Stop stack"
	@echo "  make docker-clean    Stop stack and remove volumes"
	@echo "  make docker-restart  Restart stack"
	@echo "  make docker-pull     Pull images"

docker-check:
	$(COMPOSE) config

docker-up:
	$(COMPOSE) up -d --no-build --no-recreate

docker-ps:
	$(COMPOSE) ps

docker-logs:
	$(COMPOSE) logs -f --tail=200

docker-down:
	$(COMPOSE) down

docker-clean:
	$(COMPOSE) down -v --remove-orphans

docker-restart:
	$(COMPOSE) stop
	$(COMPOSE) start

docker-pull:
	$(COMPOSE) pull
