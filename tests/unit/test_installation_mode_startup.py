from datetime import datetime, timezone
from typing import cast
from unittest.mock import AsyncMock

import pytest
from fastapi import FastAPI
from sqlalchemy.ext.asyncio import AsyncConnection, create_async_engine

from lnbits import app as app_module
from lnbits.core import helpers
from lnbits.core.models.users import User
from lnbits.db import SQLITE, Connection
from lnbits.settings import PublicSettings, settings


@pytest.mark.anyio
async def test_mode_mismatch_stops_startup_before_runtime_services(monkeypatch):
    events: list[str] = []
    monkeypatch.setattr(settings, "lnbits_running", True)

    async def reject_mismatch():
        events.append("migration-boundary")
        raise RuntimeError("INSTALLATION_MODE_MISMATCH: test")

    monkeypatch.setattr(app_module, "migrate_databases", reject_mismatch)
    monkeypatch.setattr(
        app_module,
        "check_and_register_extensions",
        AsyncMock(side_effect=lambda *_: events.append("extensions")),
    )
    monkeypatch.setattr(app_module, "check_admin_settings", AsyncMock())
    monkeypatch.setattr(app_module, "check_webpush_settings", AsyncMock())
    monkeypatch.setattr(
        app_module, "set_funding_source", lambda: events.append("funding-source")
    )
    monkeypatch.setattr(
        app_module,
        "check_funding_source",
        AsyncMock(side_effect=lambda: events.append("funding")),
    )
    monkeypatch.setattr(
        app_module, "init_core_routers", lambda *_: events.append("routes")
    )
    monkeypatch.setattr(
        app_module, "register_async_tasks", lambda: events.append("tasks")
    )

    with pytest.raises(RuntimeError, match="INSTALLATION_MODE_MISMATCH"):
        await app_module.startup(FastAPI())

    assert events == ["migration-boundary"]


@pytest.mark.anyio
@pytest.mark.parametrize("mode", ["custodial", "arkade_noncustodial"])
async def test_migrate_databases_fresh_sqlite_records_and_reuses_mode(
    monkeypatch, mode
):
    class ConnectionContext:
        def __init__(self, connection):
            self.connection = connection

        async def __aenter__(self):
            return self.connection

        async def __aexit__(self, *_):
            return None

    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.connect() as raw_connection:
        connection = Connection(
            cast(AsyncConnection, raw_connection), SQLITE, "test", None
        )
        monkeypatch.setattr(
            helpers.core_db, "connect", lambda: ConnectionContext(connection)
        )
        run_migration = AsyncMock()
        monkeypatch.setattr(helpers, "run_migration", run_migration)
        monkeypatch.setattr(helpers, "load_disabled_extension_list", AsyncMock())
        monkeypatch.setattr(
            helpers, "get_installed_extensions", AsyncMock(return_value=[])
        )
        monkeypatch.setattr(settings, "lnbits_installation_mode", mode)
        monkeypatch.setattr(settings, "lnbits_effective_installation_mode", None)

        await helpers.migrate_databases()
        row = await connection.fetchone("SELECT id, mode FROM installation_mode")
        assert row == {"id": 1, "mode": mode}
        assert settings.lnbits_effective_installation_mode == mode

        await helpers.migrate_databases()
        assert settings.lnbits_effective_installation_mode == mode
        assert run_migration.await_count == 2

    await engine.dispose()


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("configured", "persisted"),
    [
        ("custodial", "arkade_noncustodial"),
        ("arkade_noncustodial", "custodial"),
    ],
)
async def test_migrate_databases_rejects_mismatch_before_core_migration(
    monkeypatch, configured, persisted
):
    class ConnectionContext:
        async def __aenter__(self):
            return object()

        async def __aexit__(self, *_):
            return None

    monkeypatch.setattr(helpers.core_db, "connect", ConnectionContext)
    monkeypatch.setattr(helpers, "_table_exists", AsyncMock(return_value=True))
    monkeypatch.setattr(helpers, "get_db_versions", AsyncMock(return_value=[]))
    monkeypatch.setattr(
        helpers,
        "initialize_installation_mode",
        AsyncMock(return_value=persisted),
    )
    run_migration = AsyncMock()
    monkeypatch.setattr(helpers, "run_migration", run_migration)
    monkeypatch.setattr(settings, "lnbits_installation_mode", configured)
    monkeypatch.setattr(settings, "lnbits_effective_installation_mode", "custodial")

    with pytest.raises(RuntimeError, match="INSTALLATION_MODE_MISMATCH"):
        await helpers.migrate_databases()

    run_migration.assert_not_awaited()
    assert settings.lnbits_effective_installation_mode is None


def test_installation_mode_is_authenticated_user_data_only():
    now = datetime.now(timezone.utc)
    user = User(
        id="0" * 31 + "1",
        created_at=now,
        updated_at=now,
        installation_mode="arkade_noncustodial",
    )

    assert user.dict()["installation_mode"] == "arkade_noncustodial"
    assert "installation_mode" not in PublicSettings.from_settings(settings).dict()
