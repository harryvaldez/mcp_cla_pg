# Contributing

## Commit Hygiene

Use this repository rule of thumb:

- Commit files required to build, test, deploy, and maintain the project.
- Do not commit files that are generated, local-only, secret, or reproducible from commands.

## What To Commit

- Application source files (for example Python, JavaScript, and configuration files).
- Test source files and small deterministic fixtures used by tests.
- Dependency manifests and lock files used for reproducible installs.
- Infrastructure and deployment definitions (Docker, compose, and cloud IaC).
- Documentation that explains architecture, setup, and workflows.

## What Not To Commit

- Test run outputs and reports (for example `test_results.json`, JUnit XML, coverage HTML).
- Local environments and caches (`.venv`, `fresh_env`, `__pycache__`, `.pytest_cache`).
- Logs, temporary files, and generated analysis artifacts.
- Secrets or credentials in any form.
- Large evidence artifacts that can be regenerated.

## Test Results Policy

Default policy:

- Keep test results in CI artifacts, not in git history.

Exception policy:

- If compliance requires evidence snapshots, commit only curated, versioned evidence approved by maintainers.
- Avoid committing every routine test run output.

## Before Opening A Pull Request

1. Run tests locally for changed areas.
2. Ensure no generated artifacts are staged.
3. Verify no secrets are present in staged changes.
4. Keep commits focused and reviewable.

## Suggested Staging Check

Use this before committing:

```bash
git status
git diff --cached --name-only
```

If generated outputs appear, unstage them and add/update `.gitignore` patterns.
