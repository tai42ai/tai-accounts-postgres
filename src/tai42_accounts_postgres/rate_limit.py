"""Login rate limiting — failures-only, Redis-backed, fail-closed.

A correct-credential login is NEVER blocked, even mid-window: the route attempts
the credential first and only a FAILED attempt records against the counters, so
an attacker who knows a victim's email cannot lock the victim out (the victim's
correct password always succeeds and clears the account counter). Two dimensions:

- per-account: a consecutive-failure counter; once it reaches the backoff
  threshold, each further failed attempt is locked with exponential backoff
  (capped). A successful login clears it.
- per-IP: a fixed-window count of failed attempts across ALL emails from one
  source — the second dimension catching distributed credential stuffing.

Every key carries the per-deployment ``redis_key_prefix`` namespace so a Redis
shared across deployments cannot cross-read counters. Redis being unreachable is
NOT swallowed: the error propagates and the login fails closed (a throttle that
silently disappears under backend failure is a silent-degrade path).

Client IP is the request's direct peer — no ``X-Forwarded-For`` parsing. Behind a
shared proxy the per-IP dimension throttles at the ingress peer, so proxied
deployments must throttle at their ingress (documented in the README).
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, cast

from tai42_kit.clients import RedisConnectionSettings, client_ctx
from tai42_kit.clients.impl.redis import RedisClient

if TYPE_CHECKING:
    from tai42_accounts_postgres.settings import AccountsSettings


class RateLimitedError(Exception):
    """Login throttled. ``retry_after`` is whole seconds until the next attempt."""

    def __init__(self, retry_after: int) -> None:
        super().__init__(f"login throttled; retry after {retry_after}s")
        self.retry_after = retry_after


class RateLimiter:
    """Failures-only login throttle over the injected Redis."""

    def __init__(self, redis_settings: Any, settings: AccountsSettings) -> None:
        self._redis_settings = redis_settings
        self._settings = settings

    def _redis(self) -> RedisConnectionSettings:
        # tai42-contract types the injected ``redis`` as ``Any`` (it cannot name kit's
        # RedisConnectionSettings), and kit's ``client_ctx`` takes a NOMINAL settings
        # param, so cast the structural value at the single bridge point.
        return cast("RedisConnectionSettings", self._redis_settings)

    def _account_key(self, email: str) -> str:
        return f"{self._settings.key_prefix}:acc:login:fail:{email}"

    def _ip_key(self, ip: str) -> str:
        return f"{self._settings.key_prefix}:acc:login:ip:{ip}"

    async def record_failure(self, email: str | None, ip: str) -> None:
        """Count a failed attempt and raise :class:`RateLimitedError` if over-limit.

        The per-IP dimension always applies; the per-account dimension applies only
        when ``email`` is given (password login). The token-gated routes (bootstrap,
        invite accept) have no account and pass ``email=None``, throttling per IP.

        A Redis failure propagates (fail closed).
        """
        threshold = self._settings.login_backoff_threshold
        cap = self._settings.login_backoff_cap_seconds
        ip_max = self._settings.login_ip_max_attempts
        ip_window = self._settings.login_ip_window_seconds

        ip_key = self._ip_key(ip)

        async with client_ctx(RedisClient, self._redis()) as r:
            retry_after = 0

            if email is not None:
                account_key = self._account_key(email)
                account_failures = await r.incr(account_key)
                # The account counter decays after the max backoff of inactivity so
                # a long-dormant account is not permanently escalated; a success
                # clears it.
                await r.expire(account_key, cap)
                if account_failures > threshold:
                    # The threshold is a free allowance: the first lock lands on the
                    # attempt AFTER it is crossed, so the exponent starts at zero
                    # (a 1 s first lock) and doubles each further failure, capped.
                    retry_after = min(2 ** (account_failures - threshold - 1), cap)

            ip_failures = await r.incr(ip_key)
            if ip_failures == 1:
                # First failure in a fresh window opens the fixed window.
                await r.expire(ip_key, ip_window)
            if ip_failures > ip_max:
                ip_ttl = await r.ttl(ip_key)
                # A positive TTL is the remaining window; fall back to the full
                # window if Redis reports no expiry (key without TTL).
                ip_retry = ip_ttl if ip_ttl and ip_ttl > 0 else ip_window
                retry_after = max(retry_after, ip_retry)

        if retry_after > 0:
            raise RateLimitedError(retry_after)

    async def clear(self, email: str) -> None:
        """Reset the per-account failure counter after a successful login.

        A Redis failure propagates (fail closed).
        """
        async with client_ctx(RedisClient, self._redis()) as r:
            await r.delete(self._account_key(email))
