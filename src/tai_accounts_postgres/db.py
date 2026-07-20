"""Packaged DDL loader and the plugin's own schema apply step.

This plugin owns the ``accounts_users`` / ``accounts_sessions`` / ``accounts_invites``
tables and applies their schema out-of-band through this module's entry point — it
rides no external migration tool::

    python -m tai_accounts_postgres.db apply    # create the three tables (idempotent)
    python -m tai_accounts_postgres.db tables    # list the tables the DDL declares

Both connect through ``AccountsPgSettings`` (the ``TAI_ACCOUNTS_PG_*`` namespace)
and run the packaged, trusted DDL through the kit ``PostgresClient`` pool.
"""

from __future__ import annotations

import argparse
import asyncio
import re
from pathlib import Path
from typing import LiteralString, cast

from tai_kit.clients import client_ctx
from tai_kit.clients.impl.postgres import PostgresClient

from tai_accounts_postgres.settings import AccountsPgSettings

_RESOURCES_DIR = Path(__file__).resolve().parent / "sql"

# Table names the DDL declares — parsed from the DDL itself so a listing never
# drifts from what ``apply`` creates.
_CREATE_TABLE_RE = re.compile(r"CREATE TABLE(?:\s+IF NOT EXISTS)?\s+(\w+)", re.IGNORECASE)


def load_ddl() -> str:
    """Return the plugin's full DDL (the ``accounts.init.sql`` resource)."""
    return (_RESOURCES_DIR / "accounts.init.sql").read_text(encoding="utf-8")


def declared_tables() -> list[str]:
    """The tables the packaged DDL creates, sorted."""
    return sorted(set(_CREATE_TABLE_RE.findall(load_ddl())))


def _target(settings: AccountsPgSettings) -> str:
    """A credential-free description of the connection target for messages."""
    return f"{settings.pg_host}:{settings.pg_port}/{settings.pg_db}"


async def _apply_schema(settings: AccountsPgSettings) -> None:
    ddl = load_ddl()
    # The DDL is a single multi-statement script with no parameters, so it runs in
    # one execute; the transaction makes the whole thing commit or roll back together.
    async with (
        client_ctx(PostgresClient, settings, fresh=True) as pool,
        pool.connection() as conn,
        conn.transaction(),
    ):
        # ``load_ddl`` returns the trusted, packaged schema (never user input), so
        # it is a valid literal query; the cast satisfies psycopg's LiteralString
        # guard, which exists to catch injected dynamic SQL.
        await conn.execute(cast("LiteralString", ddl))


def _apply_command() -> None:
    settings = AccountsPgSettings()
    asyncio.run(_apply_schema(settings))
    print(f"Applied accounts schema to {_target(settings)}.")


def _tables_command() -> None:
    for table in declared_tables():
        print(table)


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(
        prog="python -m tai_accounts_postgres.db",
        description="Apply and inspect the tai-accounts-postgres schema.",
    )
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("apply", help="Apply the packaged DDL to Postgres (idempotent).")
    sub.add_parser("tables", help="List the tables the DDL declares.")
    args = parser.parse_args(argv)

    if args.command == "apply":
        _apply_command()
    elif args.command == "tables":
        _tables_command()


if __name__ == "__main__":  # pragma: no cover - module CLI entry
    main()
