from datetime import datetime, timezone
from types import SimpleNamespace
from typing import cast
from unittest.mock import AsyncMock

import pytest
from coincurve import PrivateKey
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
        if mode == "arkade_noncustodial":
            monkeypatch.setattr(settings, "lnbits_arkade_network", "regtest")
            monkeypatch.setattr(
                settings, "lnbits_arkade_server_url", "http://localhost:7070"
            )
            monkeypatch.setattr(
                settings,
                "lnbits_arkade_server_pubkey",
                PrivateKey.from_int(1).public_key_xonly.format().hex(),
            )

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


@pytest.mark.anyio
async def test_migrate_databases_rejects_invalid_arkade_config_before_migration(
    monkeypatch,
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
        AsyncMock(return_value="arkade_noncustodial"),
    )
    run_migration = AsyncMock()
    monkeypatch.setattr(helpers, "run_migration", run_migration)
    monkeypatch.setattr(settings, "lnbits_installation_mode", "arkade_noncustodial")
    monkeypatch.setattr(settings, "lnbits_effective_installation_mode", "custodial")
    monkeypatch.setattr(settings, "lnbits_arkade_network", None)
    monkeypatch.setattr(settings, "lnbits_arkade_server_url", None)
    monkeypatch.setattr(settings, "lnbits_arkade_server_pubkey", None)

    with pytest.raises(RuntimeError, match="ARKADE_CONFIG_INVALID"):
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


@pytest.mark.parametrize(
    "mode,expected", [("custodial", 1800), ("arkade_noncustodial", 5)]
)
def test_arkade_reconciliation_uses_events_with_fallback(monkeypatch, mode, expected):
    calls = []
    monkeypatch.setattr(settings, "lnbits_effective_installation_mode", mode)
    monkeypatch.setattr(
        settings, "lnbits_funding_source_pending_interval_seconds", 1800
    )
    monkeypatch.setattr(app_module.task_manager, "init", lambda: None)
    monkeypatch.setattr(
        app_module.task_manager, "register_invoice_listener", lambda *a: None
    )
    monkeypatch.setattr(
        app_module.task_manager,
        "create_permanent_task",
        lambda func, **kw: calls.append((func, kw)),
    )
    app_module.register_async_tasks()
    for func in [app_module.dispatch_arkade_lightning_terminal_events]:
        assert next(kw["interval"] for f, kw in calls if f == func) == expected
    registered = {f for f, _ in calls}
    if mode == "arkade_noncustodial":
        assert app_module.check_pending_payments not in registered
        assert {
            app_module.listen_arkade_transactions,
            app_module.reconcile_arkade_events,
        } <= registered
    else:
        assert (
            next(
                kw["interval"]
                for f, kw in calls
                if f == app_module.check_pending_payments
            )
            == 1800
        )
        assert app_module.listen_arkade_transactions not in registered
        assert app_module.reconcile_arkade_events not in registered
    custodial_tasks = {
        app_module.check_balance_delta_changed,
        app_module.check_server_balance_against_node,
        app_module.notify_server_status,
        app_module.fundingsource_invoice_producer,
    }
    assert custodial_tasks.intersection(f for f, _ in calls) == (
        custodial_tasks if mode == "custodial" else set()
    )


@pytest.mark.parametrize(
    "mode,warning", [("custodial", True), ("arkade_noncustodial", False)]
)
def test_voidwallet_banner_only_for_custodial_mode(monkeypatch, mode, warning):
    monkeypatch.setattr(settings, "lnbits_effective_installation_mode", mode)
    monkeypatch.setattr(settings, "lnbits_backend_wallet_class", "VoidWallet")
    assert PublicSettings.from_settings(settings).show_voidwallet is warning


@pytest.mark.anyio
async def test_noncustodial_startup_does_not_check_custodial_source(monkeypatch):
    monkeypatch.setattr(
        settings, "lnbits_effective_installation_mode", "arkade_noncustodial"
    )

    def forbidden():
        raise AssertionError("custodial funding source must not be contacted")

    monkeypatch.setattr(app_module, "get_funding_source", forbidden)
    await app_module.check_funding_source()


@pytest.mark.anyio
@pytest.mark.parametrize("mode", ["custodial", "arkade_noncustodial"])
async def test_startup_funding_source_is_mode_specific(monkeypatch, mode):
    monkeypatch.setattr(settings, "lnbits_effective_installation_mode", mode)
    monkeypatch.setattr(settings, "lnbits_running", True)
    monkeypatch.setattr(settings, "lnbits_backend_wallet_class", "FakeWallet")
    for name in [
        "migrate_databases",
        "check_admin_settings",
        "check_webpush_settings",
        "check_and_register_extensions",
        "check_funding_source",
    ]:
        monkeypatch.setattr(app_module, name, AsyncMock())
    for name in [
        "log_server_info",
        "init_core_routers",
        "create_llms_txt_route",
        "register_async_tasks",
        "enqueue_admin_notification",
    ]:
        monkeypatch.setattr(app_module, name, lambda *args, **kwargs: None)
    monkeypatch.setattr(
        app_module,
        "core_app_extra",
        SimpleNamespace(register_new_ratelimiter=lambda: None),
    )
    calls = []
    monkeypatch.setattr(
        app_module, "set_funding_source", lambda *args: calls.append(args)
    )
    await app_module.startup(FastAPI())
    assert calls == [("VoidWallet",) if mode == "arkade_noncustodial" else ()]
    assert settings.lnbits_backend_wallet_class == "FakeWallet"
