"""Authed user-administration routes — under the reserved ``/api/auth`` prefix.

The ``/api/auth`` prefix is never public and scope-gated; admin-only reach comes
from the seeded jq conditions that fence non-admins out of the control plane, so
these handlers do not re-check admin — except ``PUT /api/auth/users/me/password``,
the one self-service route (carved out of the fence for every user). Handlers take
no settings argument: they reach the injected ``settings.admin`` services through
``service.provider_settings()``.

Logout is NOT here — the skeleton owns the single ``POST /api/auth/logout``
dispatcher; this plugin's contribution is the provider's ``revoke_session``.

Success bodies are ``{"data": ...}``; failures are ``{"error": "<message>"}``.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime, timedelta
from typing import Any

from pydantic import BaseModel, ValidationError
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from tai_contract.access_control import get_current_user_id
from tai_contract.app import tai_app

from tai_accounts_postgres import service
from tai_accounts_postgres.hashing import HashCapacityError, hash_password_async, verify_password
from tai_accounts_postgres.service import ADMIN_ROLE, SESSION_TOKEN_PREFIX
from tai_accounts_postgres.settings import accounts_settings
from tai_accounts_postgres.stores import EmailTakenError

logger = logging.getLogger(__name__)


class UserRecord(BaseModel):
    """One row of the user list — never a hash, never a token."""

    user_id: str
    email: str
    role: str
    disabled: bool
    created_at: str
    pending_invite: bool


class UsersListResponse(BaseModel):
    users: list[UserRecord]


class InviteResponse(BaseModel):
    """A minted/regenerated invite — the raw token and its origin-relative link,
    shown once."""

    user_id: str
    invite_token: str
    login_path: str


class CreateUserBody(BaseModel):
    email: str
    role: str


class UpdateUserBody(BaseModel):
    role: str | None = None
    disabled: bool | None = None


class ChangePasswordBody(BaseModel):
    current_password: str
    new_password: str


def _error(message: str, status_code: int) -> JSONResponse:
    return JSONResponse({"error": message}, status_code=status_code)


def _now() -> datetime:
    return datetime.now(UTC)


async def _parse[BodyT: BaseModel](
    request: Request, model_cls: type[BodyT]
) -> tuple[BodyT | None, JSONResponse | None]:
    try:
        body = await request.json()
    except ValueError:
        return None, _error("invalid JSON body", 400)
    try:
        return model_cls.model_validate(body), None
    except ValidationError:
        return None, _error("invalid request body", 422)


def _serialize_user(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "user_id": row["user_id"],
        "email": row["email"],
        "role": row["role"],
        "disabled": row["disabled"],
        "created_at": row["created_at"].isoformat(),
        "pending_invite": row["pending_invite"],
    }


def _presented_session_hash(request: Request) -> str | None:
    """The hash of the caller's own session token, so a self password change can
    spare the presented session. Reads the bearer / X-Api-Key credential the host
    authenticated with; ``None`` when it is not one of our session tokens."""
    token: str | None = None
    auth = request.headers.get("Authorization")
    if auth:
        scheme, _, rest = auth.partition(" ")
        if not rest:
            token = scheme
        elif scheme.lower() == "bearer":
            token = rest.strip() or None
    if token is None:
        token = request.headers.get("X-Api-Key")
    if token and token.startswith(SESSION_TOKEN_PREFIX):
        return service.token_hash(token)
    return None


@tai_app.http.custom_route(
    "/api/auth/users",
    methods=["GET"],
    summary="List user accounts",
    tags=["users"],
    response_model=UsersListResponse,
)
async def list_users(request: Request) -> Response:
    """Every account as ``{user_id, email, role, disabled, created_at,
    pending_invite}``. Never a password hash, never a token."""
    rows = await service.users_store().list()
    return JSONResponse({"data": {"users": [_serialize_user(row) for row in rows]}})


@tai_app.http.custom_route(
    "/api/auth/users",
    methods=["POST"],
    summary="Create a user and mint an invite",
    tags=["users"],
    request_model=CreateUserBody,
    response_model=InviteResponse,
)
async def create_user(request: Request) -> Response:
    """Create an account with a NULL password and a one-time invite.

    Order: insert the user, apply its role through the injected services, then mint
    the invite. If ``apply_role`` fails after the row was written, the compensating
    cleanup deletes the row (and any invite) so creation is re-runnable — never a
    policy-less zombie user.
    """
    body, error = await _parse(request, CreateUserBody)
    if error is not None:
        return error
    assert body is not None

    email = service.normalize_email(body.email)
    store = service.users_store()
    try:
        created_id = await store.create(service.new_user_id(), email, body.role, password_hash=None)
    except EmailTakenError:
        return _error("email already registered", 409)

    async def _cleanup() -> None:
        await service.invites_store().delete_for_user(created_id)
        await service.users_store().delete(created_id)

    await service.apply_role_compensated(created_id, body.role, cleanup=_cleanup)

    raw_invite = service.new_invite_token()
    expires_at = _now() + timedelta(seconds=accounts_settings().invite_ttl_seconds)
    await service.invites_store().create(service.token_hash(raw_invite), created_id, expires_at)
    return JSONResponse(
        {
            "data": {
                "user_id": created_id,
                "invite_token": raw_invite,
                "login_path": service.invite_login_path(raw_invite),
            }
        }
    )


@tai_app.http.custom_route(
    "/api/auth/users/me/password",
    methods=["PUT"],
    summary="Change your own password",
    tags=["users"],
    request_model=ChangePasswordBody,
    response_model=None,
)
async def change_own_password(request: Request) -> Response:
    """Self password change: verify the current password, set the new one, and
    revoke every OTHER session (the presented one survives), so a rotation after a
    suspected leak leaves only the caller's live session."""
    caller = get_current_user_id()
    if caller is None:
        return _error("unauthenticated", 401)

    body, error = await _parse(request, ChangePasswordBody)
    if error is not None:
        return error
    assert body is not None

    if len(body.new_password) < service.PASSWORD_MIN_LENGTH:
        return _error(f"Password must be at least {service.PASSWORD_MIN_LENGTH} characters", 422)

    user = await service.users_store().get_by_user_id(caller)
    if user is None or user["password_hash"] is None:
        return _error("no password set for this account", 400)

    try:
        matched = await verify_password(user["password_hash"], body.current_password)
    except HashCapacityError:
        return _error("Server busy, please retry shortly", 503)
    if not matched:
        return _error("current password is incorrect", 403)

    new_hash = await hash_password_async(body.new_password)
    await service.users_store().set_password_hash(caller, new_hash)
    await service.sessions_store().delete_for_user(caller, keep_token_hash=_presented_session_hash(request))
    return JSONResponse({"data": {"changed": True}})


@tai_app.http.custom_route(
    "/api/auth/users/{user_id}",
    methods=["PUT"],
    summary="Update a user's role or disabled state",
    tags=["users"],
    request_model=UpdateUserBody,
    response_model=None,
)
async def update_user(request: Request) -> Response:
    """Change a user's role and/or disabled state.

    The last enabled admin cannot be demoted or disabled (409). A role change or a
    disable runs inside ONE advisory-locked transaction (``admin_guard_txn``) where
    the target's role/disabled are RE-READ from committed state under the lock — the
    guarded-vs-unguarded decision and the orphan check use that authoritative
    re-read, never the pre-lock snapshot a concurrent re-enable/demote could have
    made stale. Two concurrent removals of the last two admins cannot both pass, and
    the 3-way (demote-A / disable-B / re-enable-A) interleave cannot orphan the
    admins because A's demote re-evaluates its role/disabled under the lock.

    Disable uses credentials-die-first ordering (fail closed): the injected disable
    marker lands, then session revocation and the row write happen on the guard's
    own connection (one transaction, no nested pool checkout under the lock), so a
    mid-flow failure leaves credentials already dead rather than a row that reads
    disabled while sessions stay live. Re-enable reverses the order (marker last)
    and needs no guard — enabling can never orphan the admins.
    """
    user_id = request.path_params["user_id"]
    body, error = await _parse(request, UpdateUserBody)
    if error is not None:
        return error
    assert body is not None

    store = service.users_store()
    target = await store.get_by_user_id(user_id)
    if target is None:
        return _error("user not found", 404)
    admin = service.provider_settings().admin

    role_requested = body.role is not None and body.role != target["role"]
    disable_requested = body.disabled is not None and body.disabled != target["disabled"]

    # A role change or a disable could remove the last enabled admin, so both run
    # under the lock and decide on the committed re-read. A re-enable only ever ADDS
    # an enabled admin, so it never orphans — but a re-enable COMBINED with a role
    # change still enters the guarded branch (on ``role_requested``) and is applied
    # there in BOTH directions, so a ``{role, disabled: false}`` request neither
    # drops the demote nor silently leaves the user locked out.
    if role_requested or (disable_requested and body.disabled):
        reenable_after_commit = False
        async with store.admin_guard_txn() as guard:
            locked = await guard.read_target(user_id)
            if locked is None:
                return _error("user not found", 404)
            current_role = locked["role"]

            if body.role is not None and body.role != current_role:
                demote = current_role == ADMIN_ROLE and body.role != ADMIN_ROLE
                if demote and not locked["disabled"] and await guard.count_other_enabled_admins(user_id) == 0:
                    return _error("cannot demote the last enabled admin", 409)
                await admin.apply_role(user_id, body.role)
                await guard.set_role(user_id, body.role)
                current_role = body.role

            if body.disabled and not locked["disabled"]:
                # DISABLE direction. Guarded only while the target is (still, under the
                # lock) an admin; a just-applied demote above makes this an ordinary
                # disable. Credentials die first (marker + sessions), then the row.
                if current_role == ADMIN_ROLE and await guard.count_other_enabled_admins(user_id) == 0:
                    return _error("cannot disable the last enabled admin", 409)
                await admin.set_user_disabled(user_id, True)
                await guard.delete_sessions_for_user(user_id)
                await guard.set_disabled(user_id, True)
            elif disable_requested and body.disabled is False and locked["disabled"]:
                # RE-ENABLE direction (combined with a role change). Row first —
                # committed on block exit — then the marker after commit, the mirror
                # of disable; re-enabling adds an admin, so it needs no orphan check.
                await guard.set_disabled(user_id, False)
                reenable_after_commit = True

        if reenable_after_commit:
            await admin.set_user_disabled(user_id, False)
    elif disable_requested:
        # Pure re-enable: row first, marker last (the mirror of disable).
        await store.set_disabled(user_id, False)
        await admin.set_user_disabled(user_id, False)

    return JSONResponse({"data": {"user_id": user_id}})


@tai_app.http.custom_route(
    "/api/auth/users/{user_id}",
    methods=["DELETE"],
    summary="Delete a user",
    tags=["users"],
    response_model=None,
)
async def delete_user(request: Request) -> Response:
    """Delete a user. The last enabled admin cannot be deleted (409); the guard
    RE-READS the target's role/disabled under the advisory lock and deletes the row
    inside ONE transaction, so the guarded-vs-unguarded decision uses committed state
    (never the pre-lock snapshot) and concurrent last-admin removals cannot both
    pass. Order: remove the policy (which also revokes owned keys), then this
    plugin's sessions, invites, and user row — all on the guard's own connection, so
    no second pool connection is taken while the lock is held. A mid-way failure
    leaves a re-deletable user, never an orphaned live credential."""
    user_id = request.path_params["user_id"]
    store = service.users_store()
    target = await store.get_by_user_id(user_id)
    if target is None:
        return _error("user not found", 404)
    admin = service.provider_settings().admin

    async with store.admin_guard_txn() as guard:
        locked = await guard.read_target(user_id)
        if (
            locked is not None
            and locked["role"] == ADMIN_ROLE
            and not locked["disabled"]
            and await guard.count_other_enabled_admins(user_id) == 0
        ):
            return _error("cannot delete the last enabled admin", 409)
        await admin.remove_policy(user_id)
        await guard.delete_sessions_for_user(user_id)
        await guard.delete_invites_for_user(user_id)
        await guard.delete(user_id)

    return JSONResponse({"data": {"deleted": True, "user_id": user_id}})


@tai_app.http.custom_route(
    "/api/auth/users/{user_id}/invite",
    methods=["POST"],
    summary="Regenerate a user's invite",
    tags=["users"],
    response_model=InviteResponse,
)
async def regenerate_invite(request: Request) -> Response:
    """Replace the live invite for a user who has not set a password yet (409 once
    a password is set — a set password rotates through the self-service route)."""
    user_id = request.path_params["user_id"]
    target = await service.users_store().get_by_user_id(user_id)
    if target is None:
        return _error("user not found", 404)
    if target["password_hash"] is not None:
        return _error("user already has a password", 409)

    raw_invite = service.new_invite_token()
    expires_at = _now() + timedelta(seconds=accounts_settings().invite_ttl_seconds)
    await service.invites_store().create(service.token_hash(raw_invite), user_id, expires_at)
    return JSONResponse(
        {
            "data": {
                "user_id": user_id,
                "invite_token": raw_invite,
                "login_path": service.invite_login_path(raw_invite),
            }
        }
    )
