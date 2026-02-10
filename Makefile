# Makefile for passwault project

.PHONY: test lint format check clean build-portable

# Run tests wiht pytest
test:
	uv run pytest -s

# Run flake8 for linting
lint:
	uv run flake8 passwault tests

# Format code using black
format:
	uv run black passwault tests

# Check formatting without making changes
check:
	uv run black --check passwault tests

# Build portable executable with PyInstaller
build-portable:
	uv run pyinstaller passwault.spec --clean
	cp portable/run.sh dist/passwault/
	cp portable/run.bat dist/passwault/
	@echo "\nPortable build ready in dist/passwault/"
	@echo "Copy the dist/passwault/ folder to your USB drive."

# Remove __pycache__ and .pyc files
clean:
	find . -type d -name "__pycache__" -exec rm -r {} + \
	&& find . -type d -name ".pytest_cache" -exec rm -r {} + \
	&& find . -type f -name "*.py[co]" -delete