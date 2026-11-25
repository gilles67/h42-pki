# Development and build tasks. Works from Git Bash on Windows (GNU make) and on Linux/macOS.

IMAGE ?= gilles67/h42-pki
# Container engine (ADR-0016): make image ENGINE=docker
ENGINE ?= podman
# The OCI format, default of Podman, drops HEALTHCHECK.
BUILD_OPTIONS := $(if $(filter podman,$(notdir $(ENGINE))),--format docker)
GIT_REV := $(shell git rev-parse --short HEAD)

.PHONY: install fmt lint typecheck test check run image image-push docker-build docker-push

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

image:
	$(ENGINE) build $(BUILD_OPTIONS) -t $(IMAGE):latest -t $(IMAGE):$(GIT_REV) .

image-push: image
	$(ENGINE) push $(IMAGE):latest
	$(ENGINE) push $(IMAGE):$(GIT_REV)

# Former names, kept for the transition.
docker-build: image
docker-push: image-push
