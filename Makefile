# Makefile for passwault project

.PHONY: test lint format check clean

# Run tests wiht pytest
test:
	PYTHONPATH=. poetry run pytest -s

# Run flake8 for linting
lint:
	poetry run flake8 src tests

# Format code using black
format:
	poetry run black src tests

# Check formatting without making changes
check:
	poetry run black --check src tests

# Remove __pycache__ and .pyc files
clean:
	find . -type d -name "__pycache__" -exec rm -r {} + \
	&& find . -type d -name ".pytest_cache" -exec rm -r {} + \
	&& find . -type f -name "*.py[co]" -delete