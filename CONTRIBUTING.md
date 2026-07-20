# Contributing to tai-accounts-postgres

`tai-accounts-postgres` is the Postgres-backed **accounts provider** for the TAI
ecosystem: user accounts, password login, sessions, and invites, plus a Studio
users-admin plugin UI. The hard rule (the plugin rule): **it depends on
`tai-contract` + `tai-kit` only and never imports the skeleton.** The provider
registers itself as `"accounts-postgres"` in the contract's module-level accounts
registry at import (which also lands it in the identity registry, since it answers
its own session tokens) — there is no import edge to the skeleton in either
direction.

## Ground rules

- **No skeleton import — ever.** The package is contract-facing; the ban is
  enforced by ruff (`flake8-tidy-imports`), so a stray import fails lint:
  ```bash
  grep -rn "tai_skeleton" src/   # must be empty
  ```
- **Loud errors.** No swallowed exceptions, silent fallbacks, or silent
  truncation. A token-validation or store backend error fails closed by
  **raising**; a missing schema is caught loudly by `healthcheck()` at startup
  with the fix command; the rate limiter fails closed when Redis is down.
- **Typed package** (`py.typed`). Pyright runs clean.

## Layout

- `src/tai_accounts_postgres/provider.py` — the `PostgresAccountsProvider`
  (session-token validation, login methods, bootstrap) and its registration.
- `src/tai_accounts_postgres/routes_login.py` — the public `/api/login/*` routes.
- `src/tai_accounts_postgres/routes_users.py` — the authed `/api/auth/users*` routes.
- `src/tai_accounts_postgres/stores.py` — the thin Postgres seam (one class per table).
- `src/tai_accounts_postgres/hashing.py`, `rate_limit.py` — argon2id + login throttling.
- `src/tai_accounts_postgres/sql/accounts.init.sql` — the plugin's own DDL.
- `tests/` — behavior against in-memory store and redis fakes.

## Dev

The Python half:

```bash
uv sync --extra dev
uv run ruff check .
uv run ruff format --check .
uv run pyright
uv run pytest
```

The repo root is also a pnpm project — a single-package one holding the Studio
plugin UI, whose sources live under `studio-src/`. Run its gates from the repo
root:

```bash
pnpm install
pnpm typecheck
pnpm run format:check
pnpm test
pnpm run build          # rebuilds the committed bundle under src/tai_accounts_postgres/studio/
```

`pnpm run build` output is committed: CI rebuilds the bundle and fails if that
changes `src/tai_accounts_postgres/studio/`, so run the build and commit its
result alongside any UI change. Node 22+ and the pnpm version pinned in
`package.json`'s `packageManager` field are assumed already installed; this repo
never provisions pnpm via corepack, Homebrew, or a global npm install.

For local cross-repo work, `make dev` editable-installs the sibling `tai-*`
checkouts this package builds on into the venv. While `[tool.uv.sources]` pins
those siblings to local paths, `uv sync` already installs them editable and
`make dev` changes nothing; once the lock resolves them from the registry,
`uv sync` / `uv run` installs the published builds instead, so re-run
`make dev` afterward to restore the editable links.

Before any commit, run a secret scan over `src/` and `tests/` (e.g.
`detect-secrets scan`).

## License

By contributing you agree your contributions are licensed under Apache-2.0.
