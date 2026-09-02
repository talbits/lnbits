from typing import cast

import pytest
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncConnection, create_async_engine

import lnbits.db as db_module
from lnbits.core import migrations
from lnbits.core.crud.payments import (
    create_payment,
    get_payment_by_native_id,
    update_payment,
)
from lnbits.core.models import CreatePayment
from lnbits.db import SQLITE, Connection


@pytest.fixture
async def legacy_connection(monkeypatch):
    monkeypatch.setattr(db_module, "DB_TYPE", SQLITE)
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.connect() as raw:
        connection = Connection(cast(AsyncConnection, raw), SQLITE, "test", None)
        await connection.execute(
            "CREATE TABLE wallets (id TEXT PRIMARY KEY, deleted BOOLEAN)"
        )
        await connection.execute("""
            CREATE TABLE apipayments (
                checking_id TEXT NOT NULL,
                amount INT NOT NULL,
                fee INTEGER NOT NULL DEFAULT 0,
                wallet_id TEXT NOT NULL,
                memo TEXT,
                time TIMESTAMP NOT NULL DEFAULT (strftime('%s', 'now')),
                payment_hash TEXT,
                preimage TEXT,
                bolt11 TEXT,
                extra TEXT,
                webhook TEXT,
                webhook_status TEXT,
                expiry TIMESTAMP,
                status TEXT DEFAULT 'pending',
                tag TEXT,
                extension TEXT,
                created_at TIMESTAMP,
                updated_at TIMESTAMP,
                fiat_provider TEXT,
                labels TEXT,
                external_id TEXT,
                UNIQUE (wallet_id, checking_id)
            )
        """)
        await connection.execute("""
            CREATE VIEW balances AS
            SELECT wallet_id, SUM(amount - ABS(fee)) AS balance
            FROM apipayments GROUP BY wallet_id
        """)
        await connection.execute(
            "INSERT INTO apipayments (checking_id, amount, wallet_id, "
            "payment_hash, bolt11) VALUES "
            "('legacy-checking', 1000, 'wallet-1', 'legacy-hash', 'legacy-bolt11')"
        )
        yield connection
    await engine.dispose()


@pytest.mark.anyio
async def test_payment_identity_migration_preserves_legacy_and_rejects_mixed(
    legacy_connection: Connection,
):
    await migrations.m054_add_payment_protocol_identity(legacy_connection)
    row = await legacy_connection.fetchone(
        "SELECT protocol, native_id, checking_id, payment_hash, bolt11, arkade_address "
        "FROM apipayments WHERE checking_id = 'legacy-checking'"
    )
    assert row == {
        "protocol": "lightning",
        "native_id": "legacy-checking",
        "checking_id": "legacy-checking",
        "payment_hash": "legacy-hash",
        "bolt11": "legacy-bolt11",
        "arkade_address": None,
    }

    await legacy_connection.execute(
        "INSERT INTO apipayments "
        "(checking_id, amount, wallet_id, protocol, native_id) "
        "VALUES (NULL, 1000, 'wallet-2', 'arkade', 'native-1')"
    )
    with pytest.raises(IntegrityError):
        await legacy_connection.execute(
            "INSERT INTO apipayments "
            "(checking_id, amount, wallet_id, payment_hash, protocol, native_id) "
            "VALUES (NULL, 1000, 'wallet-3', 'mixed-hash', 'arkade', 'native-2')"
        )


@pytest.mark.anyio
async def test_payment_identity_crud_defaults_and_pending_arkade(
    legacy_connection: Connection,
):
    await migrations.m054_add_payment_protocol_identity(legacy_connection)
    lightning = await create_payment(
        checking_id="crud-checking",
        data=CreatePayment(
            wallet_id="wallet-1",
            payment_hash="crud-hash",
            bolt11="crud-bolt11",
            amount_msat=2_000,
            memo="lightning",
        ),
        conn=legacy_connection,
    )
    assert lightning.protocol == "lightning"
    assert lightning.native_id == "crud-checking"

    arkade = await create_payment(
        checking_id=None,
        data=CreatePayment(
            wallet_id="wallet-1",
            amount_msat=2_000,
            memo="pending arkade",
            protocol="arkade",
            native_id="crud-native-1",
        ),
        conn=legacy_connection,
    )
    assert arkade.checking_id is None
    assert arkade.payment_hash is None
    assert arkade.bolt11 is None
    assert arkade.arkade_address is None
    stored = await get_payment_by_native_id("crud-native-1", conn=legacy_connection)
    assert stored is not None
    assert stored.native_id == arkade.native_id

    arkade.memo = "updated"
    await update_payment(arkade, conn=legacy_connection)
    stored = await get_payment_by_native_id("crud-native-1", conn=legacy_connection)
    assert stored is not None
    assert stored.memo == "updated"

    arkade.native_id = "changed"
    with pytest.raises(ValueError, match="native_id is immutable"):
        await update_payment(arkade, conn=legacy_connection)


def test_payment_identity_rejects_mixed_arkade_lightning_fields():
    with pytest.raises(ValueError, match="cannot have Lightning identifiers"):
        CreatePayment(
            wallet_id="wallet-1",
            amount_msat=1_000,
            memo="invalid",
            protocol="arkade",
            native_id="arkade-native-2",
            payment_hash="lightning-hash",
        )


@pytest.mark.anyio
async def test_payment_identity_migration_rolls_back_on_failure(
    legacy_connection: Connection, monkeypatch
):
    connection_type = type(legacy_connection.conn)
    original_execute = connection_type.execute

    async def fail_after_table_swap(raw_connection, query, values=None):
        if "ALTER TABLE apipayments_new RENAME TO apipayments" in str(query):
            raise RuntimeError("injected migration failure")
        return await original_execute(raw_connection, query, values)

    monkeypatch.setattr(connection_type, "execute", fail_after_table_swap)
    with pytest.raises(RuntimeError, match="injected migration failure"):
        await migrations.m054_add_payment_protocol_identity(legacy_connection)

    row = await legacy_connection.fetchone(
        "SELECT checking_id, payment_hash, bolt11 "
        "FROM apipayments WHERE checking_id = 'legacy-checking'"
    )
    assert row == {
        "checking_id": "legacy-checking",
        "payment_hash": "legacy-hash",
        "bolt11": "legacy-bolt11",
    }
    view_row = await legacy_connection.fetchone("SELECT * FROM balances")
    assert view_row is not None
