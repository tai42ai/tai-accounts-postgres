"""Plugin configuration — the ``TAI_ACCOUNTS_*`` env namespace.

Two settings groups, both from the plugin's OWN env namespace (the plugin never
reads skeleton config): ``AccountsPgSettings`` (``TAI_ACCOUNTS_PG_*``) is the
Postgres connection the user/session/invite store opens; ``AccountsSettings``
(``TAI_ACCOUNTS_*``) carries the session/invite lifetimes, the login-throttle
knobs, the argon2 concurrency bound, and the first-owner bootstrap gate.

The Redis the rate limiter and the shared bootstrap token use is NOT configured
here — it is reached through the injected ``settings.redis`` the provider factory
receives, exactly as the identity provider reaches its own Redis.
"""

from __future__ import annotations

import logging
import os

from pydantic import Field, SecretStr
from pydantic_settings import SettingsConfigDict
from tai_kit.clients import PostgresConnectionSettings
from tai_kit.settings import TaiBaseSettings, settings_cache

logger = logging.getLogger(__name__)

# The argon2-verify concurrency default is a small multiple of the CPU count —
# enough parallel hashes to use the box without letting an unauthenticated flood
# amplify into unbounded memory/CPU. It CANNOT be a class-attribute literal (it
# depends on the host), so it is a default_factory.
_HASH_CONCURRENCY_CPU_MULTIPLE = 2


def _default_hash_concurrency() -> int:
    """A small multiple of the CPU count, with a loud floor when the count is unknown.

    ``os.cpu_count()`` can return ``None`` (undeterminable). Rather than let
    ``None * multiple`` raise a bare ``TypeError`` deep in settings load, fall to
    a fixed floor and log the degrade so it is visible.
    """
    cpu = os.cpu_count()
    if cpu is not None:
        return _HASH_CONCURRENCY_CPU_MULTIPLE * cpu
    logger.warning(
        "os.cpu_count() returned None; defaulting login_hash_concurrency to the floor of %d",
        _HASH_CONCURRENCY_CPU_MULTIPLE,
    )
    return _HASH_CONCURRENCY_CPU_MULTIPLE


class AccountsPgSettings(PostgresConnectionSettings):
    """``TAI_ACCOUNTS_PG_*`` Postgres connection for the plugin's own tables.

    The ``accounts_users`` / ``accounts_sessions`` / ``accounts_invites`` tables
    are plugin-owned schema objects that live in the platform database, so
    ``pg_db`` defaults to ``"tai"`` like the platform's own stores. No baked-in
    credential — supply the password via ``TAI_ACCOUNTS_PG_PASSWORD``.
    """

    model_config = SettingsConfigDict(env_prefix="TAI_ACCOUNTS_PG_")

    pg_db: str = "tai"


class AccountsSettings(TaiBaseSettings):
    """``TAI_ACCOUNTS_*`` behavior config for the accounts plugin."""

    model_config = SettingsConfigDict(env_prefix="TAI_ACCOUNTS_")

    # Session lifetimes. Idle expiry is the sliding window (a session dies once it
    # goes unused this long); absolute expiry is the hard cap from mint.
    session_idle_seconds: int = 86400
    session_absolute_seconds: int = 2592000

    # An unconsumed invite is valid this long from mint.
    invite_ttl_seconds: int = 259200

    # Login rate limiting (failures-only). Per-account: after this many
    # consecutive FAILURES the next failed attempt is locked with exponential
    # backoff, capped at the cap; a success resets the counter. Per-IP: a
    # fixed-window failure count catching distributed stuffing across many emails.
    login_backoff_threshold: int = 5
    login_backoff_cap_seconds: int = 900
    login_ip_max_attempts: int = 30
    login_ip_window_seconds: int = 900

    # argon2 verify is a synchronous CPU/memory-bound call run off the event loop.
    # This semaphore caps in-flight verifies so an unauthenticated login flood
    # cannot amplify into event-loop starvation or memory exhaustion; a request
    # that cannot acquire a slot within the wait sheds with a loud 503.
    login_hash_concurrency: int = Field(default_factory=_default_hash_concurrency)
    login_hash_wait_seconds: float = 2.0

    # First-owner bootstrap gate. Secure-by-default: with neither field set the
    # gate is ON and the effective token is auto-generated once at startup and
    # shared across processes via Redis. ``bootstrap_token`` is the explicit
    # operator-supplied token; ``bootstrap_open`` is the ONLY ungated config (a
    # local/dev opt-out) and is never the default.
    bootstrap_token: SecretStr | None = None
    bootstrap_open: bool = False

    # Per-deployment Redis namespace segment prefixed onto every plugin Redis key
    # (rate-limit counters and the bootstrap-token key) so a Redis shared across
    # deployments cannot cross-read. Effective default EQUALS the plugin's own
    # ``pg_db`` (which itself defaults ``"tai"``) — derived in model_post_init
    # because a pydantic class-attribute default cannot reference another field.
    # NEVER a hardcoded literal: two deployments overriding ``pg_db`` to distinct
    # values but leaving this unset must not both key on ``"tai"``. Deployments
    # sharing BOTH one Redis and one ``pg_db`` must set distinct values here.
    redis_key_prefix: str | None = None

    pg: AccountsPgSettings = Field(default_factory=AccountsPgSettings)

    def model_post_init(self, __context: object) -> None:
        # Derive the Redis namespace from the plugin's ``pg_db`` when the operator
        # left it unset — never a hardcoded literal (see the field comment).
        if self.redis_key_prefix is None:
            self.redis_key_prefix = self.pg.pg_db

    @property
    def key_prefix(self) -> str:
        """The resolved Redis namespace segment (never ``None`` post-init)."""
        # model_post_init guarantees redis_key_prefix is set; assert for the type
        # checker and to fail loudly should that invariant ever be broken.
        if self.redis_key_prefix is None:  # pragma: no cover - invariant guard
            raise RuntimeError("redis_key_prefix was not derived in model_post_init")
        return self.redis_key_prefix


@settings_cache
def accounts_settings() -> AccountsSettings:
    """Return the process-wide :class:`AccountsSettings`, cached after first load."""
    return AccountsSettings()
