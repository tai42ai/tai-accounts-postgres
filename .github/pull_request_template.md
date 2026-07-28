## What

<!-- What does this PR change? -->

## Why

<!-- Why is the change needed? Link related issues. -->

## Checklist

- [ ] Tests pass (`uv run --no-sync pytest --cov --cov-report=term-missing`)
- [ ] Lint is clean (`uv run --no-sync ruff check .`)
- [ ] Studio types check (`pnpm typecheck`)
- [ ] Studio formatting is clean (`pnpm run format:check`)
- [ ] Studio tests pass (`pnpm test`)
- [ ] Studio bundle rebuilt and committed (`pnpm run build`)
