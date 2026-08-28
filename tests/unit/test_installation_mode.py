from typing import cast

import pytest
from sqlalchemy.ext.asyncio import AsyncConnection, create_async_engine

from lnbits.core.helpers import (
    INSTALLATION_MODE_CORRUPT,
    check_installation_mode,
    initialize_installation_mode,
)
from lnbits.db import SQLITE, Connection


@pytest.fixture
async def connection():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.connect() as raw_connection:
        yield Connection(cast(AsyncConnection, raw_connection), SQLITE, "test", None)
    await engine.dispose()


@pytest.mark.anyio
@pytest.mark.parametrize("mode", ["custodial", "arkade_noncustodial"])
async def test_fresh_installation_records_and_keeps_mode(connection, mode):
    persisted = await initialize_installation_mode(
        connection, configured=mode, core_version=0
    )
    restarted = await initialize_installation_mode(
        connection, configured=mode, core_version=51
    )

    assert persisted == mode
    assert restarted == mode


@pytest.mark.anyio
@pytest.mark.parametrize("configured", ["custodial", "arkade_noncustodial"])
async def test_legacy_installation_records_custodial(connection, configured):
    await connection.execute("CREATE TABLE accounts (id TEXT PRIMARY KEY)")
    persisted = await initialize_installation_mode(
        connection, configured=configured, core_version=50
    )

    assert persisted == "custodial"


@pytest.mark.parametrize(
    ("configured", "persisted"),
    [
        ("custodial", "arkade_noncustodial"),
        ("arkade_noncustodial", "custodial"),
    ],
)
def test_installation_mode_mismatch_has_remediation(configured, persisted):
    with pytest.raises(RuntimeError) as exc:
        check_installation_mode(configured, persisted)

    message = str(exc.value)
    assert "INSTALLATION_MODE_MISMATCH" in message
    assert f"configured mode '{configured}'" in message
    assert f"database mode '{persisted}'" in message
    assert f"LNBITS_INSTALLATION_MODE={persisted}" in message
    assert "new empty database" in message


@pytest.mark.anyio
async def test_migrated_database_rejects_missing_marker(connection):
    with pytest.raises(RuntimeError, match=INSTALLATION_MODE_CORRUPT):
        await initialize_installation_mode(
            connection, configured="custodial", core_version=51
        )


@pytest.mark.anyio
async def test_m000_only_database_is_still_fresh(connection):
    await connection.execute(
        "CREATE TABLE dbversions (db TEXT PRIMARY KEY, version INT)"
    )

    assert (
        await initialize_installation_mode(
            connection, configured="arkade_noncustodial", core_version=0
        )
        == "arkade_noncustodial"
    )


@pytest.mark.anyio
async def test_unrelated_table_does_not_make_installation_legacy(connection):
    await connection.execute("CREATE TABLE unrelated (id TEXT PRIMARY KEY)")

    assert (
        await initialize_installation_mode(
            connection, configured="arkade_noncustodial", core_version=0
        )
        == "arkade_noncustodial"
    )


@pytest.mark.anyio
async def test_corrupt_marker_schema_fails_closed(connection):
    await connection.execute("CREATE TABLE installation_mode (wrong TEXT)")

    with pytest.raises(RuntimeError, match=INSTALLATION_MODE_CORRUPT):
        await initialize_installation_mode(
            connection, configured="custodial", core_version=51
        )
