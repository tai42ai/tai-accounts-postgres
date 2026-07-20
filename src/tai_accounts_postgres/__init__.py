"""tai-accounts-postgres: the Postgres-backed accounts provider plugin.

Importing this package registers the ``"accounts-postgres"`` provider in the
contract's module-level accounts registry (which also lands it in the identity
registry under the same name, since it answers its own session tokens) — see
:mod:`tai_accounts_postgres.provider`. The public ``/api/login/*`` and authed
``/api/auth/users*`` routes are loaded separately through the deployment
manifest's ``routers_modules``.
"""

from __future__ import annotations

from tai_accounts_postgres.provider import PostgresAccountsProvider

__all__ = [
    "PostgresAccountsProvider",
]
