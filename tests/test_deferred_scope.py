"""What these unit tests prove vs what the e2e leg owns — stated honestly.

Proven here against the store/redis fakes: the provider's validate_token matrix
(prefix fast-reject, unknown, disabled, idle/absolute expiry with row deletion,
the happy path + throttled touch, claims shape, store-error-raises); needs_bootstrap
count semantics; revoke_session; the full login route matrix (uniform 401 bodies,
unknown-email dummy verify, rehash-on-login, failures-only throttling where a
correct password succeeds even over-limit and only a failed attempt trips the 429,
success clears the counter, the frozen token/user_id shape); bootstrap (zero->owner
+ apply_role + session, nonzero->409, the Q13 gate default/open/operator paths,
apply_role failure compensation); invite accept (happy, confirm mismatch, expired/
unknown miss, regenerate replaces); the users routes (create login_path once + apply
role failure compensation, role change via the injected services, disable
credentials-die-first, last-admin guards, delete ordering, self password change
keeping the presented session); the single registration landing in BOTH registries;
and the standalone ``db apply`` CLI (idempotent).

NOT unit-provable, owned by the ecosystem e2e leg: real SQL correctness — the
UNIQUE constraints, ``pg_advisory_xact_lock`` under true concurrency, the atomic
invite UPDATE, and the sessions⋈users JOIN — exercised against a live Postgres
whose schema is applied via ``load_ddl()``; and the full request → middleware →
provider integration. The end-to-end Studio-plugin LOAD (the users-admin page
mounted from ``studio_plugins`` and reachable) is owned by the e2e stack IF it
enables ``studio_plugins: ["tai42_accounts_postgres"]``; this repo proves the UI
through its own studio build + component tests. Absent that entry it stays a
documented gap.
"""

from __future__ import annotations

from tai42_accounts_postgres import stores
from tai42_accounts_postgres.db import load_ddl


def test_store_sql_names_match_the_ddl():
    """A cheap drift tripwire between the store SQL and the DDL — NOT a substitute
    for the e2e leg's live-SQL proof. Every table/column the stores read or write
    must appear in the packaged DDL."""
    ddl = load_ddl()
    for table in ("accounts_users", "accounts_sessions", "accounts_invites"):
        assert table in ddl
    for column in (
        "user_id",
        "email",
        "password_hash",
        "role",
        "disabled",
        "token_hash",
        "absolute_expires_at",
        "last_seen_at",
        "expires_at",
        "consumed_at",
    ):
        assert column in ddl
    # The constraint names the store splits on must be exactly the ones declared.
    assert stores._EMAIL_UNIQUE in ddl
    assert stores._USER_ID_UNIQUE in ddl
