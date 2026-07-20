"""``PostgresAccountsProvider`` — session-token validation, login methods, bootstrap.

An accounts provider (the contract's ``AccountsProvider`` ABC, itself an
``IdentityProvider``): the session tokens it mints pass back through the inherited
``validate_token``, so installing it adds no second enforcement pathway. Its
storage is the plugin's own Postgres schema; login throttling and the shared
bootstrap token live in the injected Redis.

Registered ONCE at import via ``register_accounts_provider("accounts-postgres",
...)`` — which also lands the factory in the identity registry under the same
name, since an accounts provider IS the token answerer for its own sessions.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import TYPE_CHECKING

from tai_contract.access_control.identity import AuthIdentity, ReadinessTarget
from tai_contract.accounts import (
    AccountsProvider,
    FormField,
    FormMethod,
    LoginMethod,
    register_accounts_provider,
)
from tai_kit.clients import client_ctx
from tai_kit.clients.impl.postgres import PostgresClient
from tai_kit.clients.impl.redis import RedisClient

from tai_accounts_postgres import service
from tai_accounts_postgres.db import declared_tables
from tai_accounts_postgres.settings import accounts_settings

if TYPE_CHECKING:
    from tai_contract.accounts import AccountsProviderSettings

logger = logging.getLogger(__name__)

# ``last_seen_at`` is written only when it is more than this stale, so a busy
# session does not cost a PG UPDATE per request. The idle window dwarfs this
# coarseness, so sliding-expiry semantics are unaffected. A module constant, not
# config.
_TOUCH_THROTTLE_SECONDS = 60

_OPEN_WINDOW_WARNING = (
    "first-owner bootstrap is OPEN — anyone who can reach /api/login/bootstrap can seize the admin "
    "owner; unset TAI_ACCOUNTS_BOOTSTRAP_OPEN to gate it"
)
_SCHEMA_MISSING = (
    "tai-accounts-postgres schema missing: run 'python -m tai_accounts_postgres.db apply' "
    "against the configured database"
)


class PostgresAccountsProvider(AccountsProvider):
    """Validate sessions, declare login methods, and own the bootstrap gate."""

    def __init__(self, settings: AccountsProviderSettings) -> None:
        self.settings = settings
        # Populate the module holder so bare-decorated route handlers can reach
        # ``settings.admin`` / ``settings.redis``. Every instantiation refreshes it.
        service.set_provider_settings(settings)

    async def validate_token(self, token: str) -> AuthIdentity | None:
        # Fast-reject anything that is not one of our session tokens WITHOUT a DB
        # hit, so multi-provider resolution moves on to the api-key provider.
        if not token.startswith(service.SESSION_TOKEN_PREFIX):
            return None

        token_hash = service.token_hash(token)
        store = service.sessions_store()
        try:
            row = await store.resolve(token_hash)
        except Exception as exc:
            # A backend error fails closed by RAISING (logged at source), never by
            # returning None (which would read as a simply-invalid credential).
            logger.error("accounts: session resolve failed: %s", exc)
            raise

        if row is None:
            return None

        now = datetime.now(UTC)
        user_id = row["user_id"]

        if row["disabled"]:
            # Leave the row (an admin may re-enable the account); the disabled join
            # kills the live session on its next request regardless.
            logger.info("accounts: refused session for disabled user %s", user_id)
            return None
        if now >= row["absolute_expires_at"]:
            logger.info("accounts: session for %s past absolute expiry; deleting", user_id)
            await store.delete(token_hash)
            return None
        idle = (now - row["last_seen_at"]).total_seconds()
        if idle >= accounts_settings().session_idle_seconds:
            logger.info("accounts: session for %s idle-expired; deleting", user_id)
            await store.delete(token_hash)
            return None

        if idle > _TOUCH_THROTTLE_SECONDS:
            await store.touch(token_hash, now)

        return AuthIdentity(
            user_id=user_id,
            claims={"email": row["email"], "role": row["role"], "kind": "session"},
        )

    def login_methods(self) -> list[LoginMethod]:
        # Static, config-derived metadata — no store read. The bootstrap form
        # declares a bootstrap_token field UNLESS the gate is explicitly opened, so
        # the default (gated) posture is reachable straight through the generic
        # renderer with no renderer changes.
        settings = accounts_settings()

        bootstrap_fields = [
            FormField(name="email", label="Email", autocomplete="email"),
            FormField(name="password", label="Password", secret=True, autocomplete="new-password"),
        ]
        if not settings.bootstrap_open:
            bootstrap_fields.append(FormField(name="bootstrap_token", label="Bootstrap token", secret=True))

        return [
            FormMethod(
                id="password",
                title="Sign in",
                purpose="login",
                fields=[
                    FormField(name="email", label="Email", autocomplete="email"),
                    FormField(name="password", label="Password", secret=True, autocomplete="current-password"),
                ],
                submit_path="/api/login/password",
            ),
            FormMethod(
                id="bootstrap",
                title="Create the first owner",
                purpose="bootstrap",
                fields=bootstrap_fields,
                submit_path="/api/login/bootstrap",
            ),
            FormMethod(
                id="invite",
                title="Set your password",
                purpose="invite",
                fields=[
                    FormField(name="password", label="Password", secret=True, autocomplete="new-password"),
                    FormField(
                        name="password_confirm",
                        label="Confirm password",
                        secret=True,
                        autocomplete="new-password",
                    ),
                ],
                submit_path="/api/login/invite/accept",
            ),
        ]

    async def needs_bootstrap(self) -> bool:
        # A LIVE count on every call, so the owner screen disappears the moment the
        # owner exists.
        return await service.users_store().count() == 0

    async def revoke_session(self, token: str) -> bool:
        if not token.startswith(service.SESSION_TOKEN_PREFIX):
            # Not ours — the skeleton's logout dispatcher moves on. Backend errors
            # still propagate (fail closed) from the store below.
            return False
        return await service.sessions_store().delete(service.token_hash(token))

    async def healthcheck(self) -> None:
        # Runs once at boot under the AC-enabled probe. Three things: the schema
        # guard (raises with the apply command if the tables are absent), a trivial
        # session query, and the once-per-deployment bootstrap-token fix.
        await self._assert_schema()

        settings = accounts_settings()
        if settings.bootstrap_open:
            # The only ungated config: warn loudly every boot while no owner exists.
            if await self.needs_bootstrap():
                logger.warning(_OPEN_WINDOW_WARNING)
        else:
            # Gated (default or operator-token): fix the shared auto-token once.
            await service.ensure_bootstrap_token(self.settings.redis)

    async def _assert_schema(self) -> None:
        expected = declared_tables()
        async with (
            client_ctx(PostgresClient, accounts_settings().pg) as pool,
            pool.connection() as conn,
            conn.cursor() as cur,
        ):
            await cur.execute(
                "SELECT table_name FROM information_schema.tables "
                "WHERE table_schema = 'public' AND table_name = ANY(%s)",
                (expected,),
            )
            present = {row[0] for row in await cur.fetchall()}
            if any(table not in present for table in expected):
                raise RuntimeError(_SCHEMA_MISSING)
            # A trivial read against the sessions table — connectivity beyond the
            # catalog lookup, failing loudly if the table is unreadable.
            await cur.execute("SELECT 1 FROM accounts_sessions LIMIT 0")

    def readiness_targets(self) -> tuple[ReadinessTarget, ReadinessTarget]:
        # Both backing stores, named "accounts": the plugin's own Postgres and the
        # injected Redis. Core pings each generically, deduped against every other
        # subsystem sharing the connection.
        return (
            ReadinessTarget("accounts", PostgresClient, accounts_settings().pg),
            ReadinessTarget("accounts", RedisClient, self.settings.redis),
        )


# Module-level registration: one call lands the factory in BOTH the accounts
# registry (methods aggregation) and the identity registry (session-token
# resolution) under the same name — an accounts provider IS the identity answerer
# for its own sessions, so a single registration keeps sessions mintable AND
# validatable. No ``tai_app`` handle is involved; the plugin registers at its own
# import so ``lifecycle_modules: ["tai_accounts_postgres"]`` triggers it.
register_accounts_provider("accounts-postgres", PostgresAccountsProvider)
