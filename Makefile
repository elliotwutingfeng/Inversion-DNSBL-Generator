markdown_lint:
	markdownlint --disable MD013 MD033 MD041 --fix . --ignore CODE_OF_CONDUCT.md

ruff_check:
	uv run ruff check
	uv run ruff format --check

ruff_format:
	uv run ruff check --fix
	uv run ruff format

install:
	uv sync --locked --all-extras --dev
	uv run pre-commit install

build:
	uv build --no-sources

update:
	uv lock --upgrade
	uv sync --all-groups
