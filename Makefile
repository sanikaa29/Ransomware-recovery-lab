VENV := .venv
PY   := $(VENV)/bin/python
LAB  := $(VENV)/bin/lab

.PHONY: setup up demo test test-integration lint reset

# Create the venv, install pinned deps, and generate random local credentials.
setup:
	python3 -m venv $(VENV)
	$(PY) -m pip install --upgrade pip
	$(PY) -m pip install -e ".[dev]"
	$(PY) -m lab.setup_env

up:
	$(LAB) up

demo:
	$(LAB) demo

test:
	$(VENV)/bin/pytest

# Needs `make up`. Re-seeds shopdb with a small data set and runs a real attack and restore.
test-integration:
	$(VENV)/bin/pytest -m integration

lint:
	$(VENV)/bin/ruff check .
	$(VENV)/bin/ruff format --check .

# Wipes ALL lab data, including the vault. This is the only way to clear
# COMPLIANCE-locked backups before retention expires (by design, nothing
# inside S3 can). Keeps .env and .lab/s3.json so `make up` still works.
reset:
	docker compose down -v --remove-orphans
	find .lab -mindepth 1 ! -name s3.json -delete 2>/dev/null || true
