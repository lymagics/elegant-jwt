.PHONY: help unit black flake8 ruff

help:
	@echo "Available commands:"
	@echo "  make unit    - run unit tests with coverage"
	@echo "  make black   - format code with black"
	@echo "  make flake8  - check style with flake8"
	@echo "  make ruff    - lint code with ruff"

unit:
	uv run pytest tests --cov=elegant_jwt --cov-report=term-missing --cov-fail-under=90

black:
	uv run black src tests

flake8:
	uv run flake8 src tests

ruff:
	uv run ruff check src tests
