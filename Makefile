# Makefile for passwault project

.PHONY: test lint format check clean portable

# Run tests wiht pytest
test:
	uv run pytest -s

# Run flake8 for linting
lint:
	uv run flake8 passwault tests

# Format code using ruff
format:
	ruff format passwault tests

# Check formatting without making changes
check:
	ruff format --check passwault tests

# Build the portable USB bundle (e.g. make portable DEST=/mnt/e)
portable:
	scripts/build_portable.sh $(DEST)

# Remove __pycache__ and .pyc files
clean:
	find . -type d -name "__pycache__" -exec rm -r {} + \
	&& find . -type d -name ".pytest_cache" -exec rm -r {} + \
	&& find . -type f -name "*.py[co]" -delete
