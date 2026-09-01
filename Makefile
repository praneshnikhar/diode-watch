.PHONY: up down logs build test train seed ps

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
