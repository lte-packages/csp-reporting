# Development Tasks
.PHONY: help install install-dev lint format test clean pre-commit build coverage

# Define variables
PACKAGE_NAME = csp_reporting
PYTHON = .venv/bin/python
PYTEST_ENV = PYTHONPATH=.

help:  ## Show this help message
	@echo 'Usage: make [target]'
	@echo ''
	@echo 'Targets:'
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  %-20s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

.venv:  ## Create a virtual environment
	python -m venv .venv
	$(PYTHON) -m pip install --upgrade pip

install: .venv  ## Install production dependencies
	$(PYTHON) -m pip install -e .

install-dev: .venv  ## Install development dependencies
	$(PYTHON) -m pip install -e ".[dev]"
	$(PYTHON) -m pre_commit install

lint:  ## Lint project with ruff
	$(PYTHON) -m ruff check .

format:  ## Format code with ruff
	$(PYTHON) -m ruff format .
	$(PYTHON) -m ruff check --fix .

run_command:  ## Run a custom management command
	$(PYTHON) ./demo_site/manage.py $(cmd) $(args)

run:  ## Run the development server
	$(PYTHON) ./demo_site/manage.py runserver 127.0.0.1:8000

test:  ## Run tests with pytest
	$(PYTEST_ENV) $(PYTHON) -m pytest tests/ -v

coverage:  ## Run tests with coverage report
	$(PYTEST_ENV) $(PYTHON) -m coverage run --source=csp_reporting -m pytest tests/
	$(PYTHON) -m coverage report
	$(PYTHON) -m coverage html
	@echo "Coverage report: htmlcov/index.html"

build:  ## Build the package for distribution
	$(PYTHON) -m build

clean:  ## Clean up build artifacts
	rm -rf build/
	rm -rf dist/
	rm -rf *.egg-info/
	rm -rf htmlcov/
	rm -rf .coverage
	find . -type d -name __pycache__ -delete
	find . -type f -name "*.pyc" -delete

clean-all: clean  ## Clean everything including virtual environment
	rm -rf .venv/

pre-commit: ## Run pre-commit hooks on changed files
	$(PYTHON) -m pre_commit run

pre-commit-all: ## Run pre-commit hooks on all files
	$(PYTHON) -m pre_commit run --all-files

build: ## Build the package
	@$(PYTHON) -m pip install --quiet build

tag:  ## Create a git tag using the version from pyproject.toml
	@VERSION=$$(grep '^version = ' pyproject.toml | sed 's/version = "\(.*\)"/\1/'); \
	echo "Creating git tag: $$VERSION"; \
	git tag -a "$$VERSION" -m "Release $$VERSION" && echo "Tag $$VERSION created successfully" || echo "Failed to create tag (may already exist)"

tag-push:  ## Create a git tag and push it to remote
	@VERSION=$$(grep '^version = ' pyproject.toml | sed 's/version = "\(.*\)"/\1/'); \
	echo "Creating and pushing git tag: $$VERSION"; \
	git tag -a "$$VERSION" -m "Release $$VERSION" && git push origin "$$VERSION" && echo "Tag $$VERSION created and pushed successfully" || echo "Failed to create/push tag"

# release:  ## Build and upload to PyPI (requires proper credentials)
# 	$(PYTHON) -m build
# 	$(PYTHON) -m twine upload dist/*
