# Fichier Makefile pour EthicalPulse

# Variables
DOCKER_COMPOSE = docker-compose
DJANGO_MANAGE = docker-compose exec web python manage.py

# Construction
build:
	$(DOCKER_COMPOSE) build --no-cache

up:
	$(DOCKER_COMPOSE) up -d

down:
	$(DOCKER_COMPOSE) down

restart:
	$(DOCKER_COMPOSE) down && $(DOCKER_COMPOSE) up -d --build

# Django
migrate:
	$(DJANGO_MANAGE) migrate

createsuperuser:
	$(DJANGO_MANAGE) createsuperuser

collectstatic:
	$(DJANGO_MANAGE) collectstatic --noinput

shell:
	$(DJANGO_MANAGE) shell

makemigrations:
	$(DJANGO_MANAGE) makemigrations

# Tests
test:
	$(DJANGO_MANAGE) test

# Celery
celery:
	$(DOCKER_COMPOSE) exec web celery -A Ethicalpulse worker --loglevel=info

# Linting / formatage
lint:
	flake8 .

format:
	black .

check:
	black --check . && flake8 .

# Logs
logs:
	$(DOCKER_COMPOSE) logs -f

# Nettoyage
clean:
	find . -type f -name "*.pyc" -delete
	find . -type d -name "__pycache__" -exec rm -r {} +
	rm -rf staticfiles

# Aide
help:
	@echo "\n🛠️ Commandes disponibles :"
	@grep -E '^[a-zA-Z_-]+:.*?##' Makefile | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'

