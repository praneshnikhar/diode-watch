.PHONY: up down logs build test train seed ps n8n-import

up:
	docker compose up -d --build

down:
	docker compose down

logs:
	docker compose logs -f --tail=100

build:
	docker compose build

test:
	docker compose -f docker-compose.test.yml run --rm test

train:
	docker build -f ml/Dockerfile -t diode-ml . && \
	docker run --rm -v $$(pwd)/ml/artifacts:/app/artifacts diode-ml python -m ml.train_dga --out /app/artifacts

ps:
	docker compose ps

# Import the workflow JSONs from n8n/ and activate them headlessly. n8n must be
# stopped while importing so the CLI and the live process don't race on SQLite.
# Activation uses `publish:workflow` (n8n 2.x's versioned publish model): the
# workflow JSONs carry a fixed `webhookId` so the production webhook path is
# stable ("diode-alert" instead of the {workflowId}/{nodeName}/... form).
n8n-import:
	docker compose stop n8n
	docker compose run --rm --no-deps --entrypoint sh n8n -c "sh /opt/workflows/import-and-activate.sh"
	docker compose start n8n
