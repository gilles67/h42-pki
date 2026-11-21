# Development and build tasks. Works from Git Bash on Windows (GNU make) and on Linux/macOS.

IMAGE ?= gilles67/h42-pki
GIT_REV := $(shell git rev-parse --short HEAD)

.PHONY: install fmt lint typecheck test check run docker-build docker-push

install:
	uv sync --all-groups

fmt:
	uv run ruff check --fix .
	uv run ruff format .

lint:
	uv run ruff check .
	uv run ruff format --check .

typecheck:
	uv run mypy src

test:
	uv run pytest

check: lint typecheck test

run:
	uv run h42pki serve --reload

docker-build:
	docker build -t $(IMAGE):latest -t $(IMAGE):$(GIT_REV) .

docker-push: docker-build
	docker push $(IMAGE):latest
	docker push $(IMAGE):$(GIT_REV)
