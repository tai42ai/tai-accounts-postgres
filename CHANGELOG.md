# Changelog

All notable changes to `tai42-accounts-postgres` are documented here; the format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Until 1.0.0 the API is not stable: **minor (0.x) releases may contain breaking
changes.**

## [Unreleased]

First release (0.1.0) in preparation — nothing published yet.

- Postgres-backed accounts provider (`accounts-postgres`): user accounts,
  password login, sessions, and invites over the plugin's own DDL.
- Public `/api/login/*` routes (password, first-owner bootstrap, invite accept)
  and authed `/api/auth/users*` administration routes.
- argon2id password hashing with rehash-on-login, hashed sessions/invites at
  rest, uniform login-failure responses, and failures-only login rate limiting.
- Secure-by-default first-owner bootstrap gate (auto-generated one-time token
  shared across processes via Redis).
- Studio users-admin plugin UI.
