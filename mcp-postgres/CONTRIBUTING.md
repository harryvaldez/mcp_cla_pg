# Contributing

## Branch Strategy

- `main` — Production-ready code
- Feature branches — `feature/<description>` or `fix/<description>`

## PR Process

1. Fork or branch from `main`
2. Implement changes with tests
3. Run `ruff check .` and `pytest -q`
4. Update documentation if behavior changes
5. Open a pull request with a clear description

## Testing Requirements

- Unit tests for all new functionality
- Integration tests for endpoint changes
- `pytest -q` must pass before merge

## Linting

- `ruff check .` must pass before merge
- Max line length: 100 characters
- Target Python version: 3.11

## Code Style

- Use type hints for all function signatures
- Use FastMCP 3 idiomatic patterns (see AGENTS.md)
- Follow existing patterns in the codebase
- Keep functions focused and single-purpose
- Use descriptive variable names

## Commit Message Conventions

Use imperative mood:
- `Add db_pg96_ping tool`
- `Fix SSL mode handling for EDBAS 9.6`
- `Update rate limiter burst configuration`
