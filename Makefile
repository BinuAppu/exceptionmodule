.PHONY: install dev api web test lint migrate seed worker backup-check

install:
	python3 -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 12) else "Python 3.12+ is required")'
	python3 -m venv .venv
	.venv/bin/python -m pip install --upgrade pip
	.venv/bin/python -m pip install -r backend/requirements-dev.txt
	cd frontend && npm ci

api:
	.venv/bin/uvicorn app.main:app --reload --app-dir backend --host 0.0.0.0 --port 8000

web:
	cd frontend && npm run dev

dev:
	@echo "Run 'make api' and 'make web' in separate terminals."

test:
	.venv/bin/pytest

lint:
	.venv/bin/ruff check backend
	.venv/bin/mypy backend/app

migrate:
	PYTHONPATH=backend .venv/bin/alembic -c backend/alembic.ini upgrade head

seed:
	PYTHONPATH=backend .venv/bin/python -m app.db.seed

worker:
	PYTHONPATH=backend .venv/bin/python -m app.workers.run

backup-check:
	PYTHONPATH=backend .venv/bin/python -m app.services.backups verify --latest
