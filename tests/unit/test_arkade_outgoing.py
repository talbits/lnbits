from datetime import datetime, timedelta, timezone
from typing import cast

import pytest
from pydantic import ValidationError
from sqlalchemy.exc import OperationalError
from sqlalchemy.ext.asyncio import AsyncConnection, create_async_engine

import lnbits.db as db_module
from lnbits.core import migrations
from lnbits.core.crud.arkade_outgoing import (
    claim_arkade_outgoing_inputs,
    create_arkade_outgoing_intent,
    dispute_arkade_outgoing_intent,
    get_arkade_outgoing_intent,
    get_arkade_outgoing_intent_inputs,
    release_arkade_outgoing_intent,
    settle_arkade_outgoing_intent,
    submit_arkade_outgoing_intent,
)
from lnbits.core.crud.payments import get_payment_by_native_id
from lnbits.core.models.arkade import (
    ArkadeOutgoingIntent,
    ArkadeOutgoingIntentInput,
)
from lnbits.core.services import arkade
from lnbits.db import SQLITE, Connection
from lnbits.settings import settings


@pytest.fixture
async def connection(monkeypatch):
    monkeypatch.setattr(db_module, "DB_TYPE", SQLITE)
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.connect() as raw:
        connection = Connection(cast(AsyncConnection, raw), SQLITE, "test", None)
        await connection.execute("CREATE TABLE accounts (id TEXT PRIMARY KEY)")
        await connection.execute(
            'CREATE TABLE wallets (id TEXT PRIMARY KEY, "user" TEXT NOT NULL, '
            "name TEXT NOT NULL, adminkey TEXT NOT NULL, inkey TEXT NOT NULL, "
            "wallet_type TEXT NOT NULL DEFAULT 'lightning', shared_wallet_id TEXT, "
            "deleted BOOLEAN DEFAULT false, created_at TIMESTAMP, "
            "updated_at TIMESTAMP, "
            "currency TEXT, lightning_address TEXT, extra TEXT, stored_paylinks TEXT)"
        )
        await connection.execute(
            "INSERT INTO accounts (id) VALUES (:account_id), (:other_account_id)",
            {"account_id": ACCOUNT_ID, "other_account_id": "aa" * 16},
        )
        await connection.execute(
            'INSERT INTO wallets (id, "user", name, adminkey, inkey, '
            "extra, stored_paylinks) "
            "VALUES (:wallet_id, :account_id, 'main', 'admin', 'inkey', '{}', '{}')",
            {"wallet_id": WALLET_ID, "account_id": ACCOUNT_ID},
        )
        await connection.execute(
            'INSERT INTO wallets (id, "user", name, adminkey, inkey, '
            "extra, stored_paylinks) "
            "VALUES (:wallet_id, :account_id, 'other', 'admin2', 'inkey2', '{}', '{}')",
            {"wallet_id": OTHER_WALLET_ID, "account_id": "aa" * 16},
        )
        await connection.execute(
            'INSERT INTO wallets (id, "user", name, adminkey, inkey, '
            "extra, stored_paylinks) "
            "VALUES (:wallet_id, :account_id, 'second', 'admin3', 'inkey3', "
            "'{}', '{}')",
            {"wallet_id": SECOND_WALLET_ID, "account_id": ACCOUNT_ID},
        )
        await connection.execute(
            'INSERT INTO wallets (id, "user", name, wallet_type, shared_wallet_id, '
            "adminkey, inkey, extra, stored_paylinks) VALUES ("
            ":wallet_id, :account_id, 'limited', 'lightning-shared', :source_wallet, "
            "'admin4', 'inkey4', :extra, '{}')",
            {
                "wallet_id": NO_SEND_WALLET_ID,
                "account_id": ACCOUNT_ID,
                "source_wallet": WALLET_ID,
                "extra": (
                    '{"shared_with":[{"username":"share",'
                    f'"shared_with_wallet_id":"{NO_SEND_WALLET_ID}",'
                    '"permissions":[],"status":"approved"}]}'
                ),
            },
        )
        await connection.execute(
            "CREATE TABLE apipayments ("
            "checking_id TEXT, amount INT NOT NULL, fee INT NOT NULL DEFAULT 0, "
            "wallet_id TEXT NOT NULL, memo TEXT, time TIMESTAMP NOT NULL, "
            "payment_hash TEXT, preimage TEXT, bolt11 TEXT, extra TEXT, webhook TEXT, "
            "webhook_status TEXT, expiry TIMESTAMP, status TEXT DEFAULT 'pending', "
            "tag TEXT, extension TEXT, created_at TIMESTAMP, updated_at TIMESTAMP, "
            "fiat_provider TEXT, labels TEXT, external_id TEXT, "
            "protocol TEXT NOT NULL, "
            "native_id TEXT UNIQUE, arkade_address TEXT)"
        )
        await connection.execute(
            "CREATE VIEW balances AS SELECT wallet_id, SUM(amount - ABS(fee)) balance "
            "FROM apipayments WHERE (status = 'success' AND amount > 0) "
            "OR (status IN ('success', 'pending') AND amount < 0) GROUP BY wallet_id"
        )
        await connection.execute(
            "CREATE TABLE arkade_account_bindings ("
            "account_id TEXT PRIMARY KEY, state TEXT NOT NULL, enrollment_id TEXT, "
            "idempotency_key TEXT, challenge_nonce TEXT, "
            "challenge_expires_at TIMESTAMP, "
            "network TEXT, server_url TEXT, server_pubkey TEXT, "
            "identity_xonly_pubkey TEXT, "
            "backup_acknowledged_at TIMESTAMP, created_at TIMESTAMP, "
            "updated_at TIMESTAMP, "
            "ready_at TIMESTAMP)"
        )
        await connection.execute(
            "INSERT INTO arkade_account_bindings (account_id, state, enrollment_id, "
            "network, server_url, server_pubkey, identity_xonly_pubkey, "
            "backup_acknowledged_at, ready_at) "
            "VALUES (:account_id, 'ready', :enrollment_id, "
            "'regtest', 'http://indexer', :server_pubkey, :identity, 1, 1)",
            {
                "account_id": ACCOUNT_ID,
                "enrollment_id": "33" * 16,
                "server_pubkey": "44" * 32,
                "identity": "55" * 32,
            },
        )
        await migrations.m055_create_arkade_outgoing_tables(connection)
        yield connection
    await engine.dispose()


ACCOUNT_ID = "00" * 16
WALLET_ID = "11" * 16
OTHER_WALLET_ID = "66" * 16
SECOND_WALLET_ID = "88" * 16
NO_SEND_WALLET_ID = "aa" * 16
INTENT_ID = "22" * 16


def _intent(*, expires_at: datetime | None = None, amount_msat: int = 10_000):
    return ArkadeOutgoingIntent(
        intent_id=INTENT_ID,
        account_id=ACCOUNT_ID,
        wallet_id=WALLET_ID,
        amount_msat=amount_msat,
        max_fee_msat=0,
        destination="tark1destination",
        expires_at=expires_at
        or (datetime.now(timezone.utc) + timedelta(hours=1)).replace(microsecond=0),
    )


async def _credit(connection, wallet_id: str, amount_msat: int):
    await connection.execute(
        "INSERT INTO apipayments (amount, wallet_id, memo, time, status, protocol) "
        "VALUES (:amount, :wallet_id, 'credit', 1, 'success', 'lightning')",
        {"amount": amount_msat, "wallet_id": wallet_id},
    )


async def _backing(_account_id):
    return [
        arkade.ArkadeIndexerVtxo(
            txid="99" * 32,
            vout=0,
            amount_sat=100,
            script="aa",
        )
    ]


async def _low_backing(_account_id):
    return [
        arkade.ArkadeIndexerVtxo(
            txid="98" * 32,
            vout=0,
            amount_sat=10,
            script="aa",
        )
    ]


async def _exact_backing(_account_id):
    return [
        arkade.ArkadeIndexerVtxo(
            txid="97" * 32,
            vout=0,
            amount_sat=40,
            script="aa",
        )
    ]


@pytest.mark.anyio
async def test_reservation_debits_and_replays_atomically(connection, monkeypatch):
    monkeypatch.setattr(
        settings, "lnbits_effective_installation_mode", "arkade_noncustodial"
    )
    monkeypatch.setattr(arkade, "fetch_arkade_indexer_vtxos", _backing)
    await _credit(connection, WALLET_ID, 20_000)
    intent = _intent()

    reserved, payment = await arkade.reserve_arkade_outgoing_intent(
        ACCOUNT_ID, intent, conn=connection
    )
    assert reserved.intent_id == intent.intent_id
    assert reserved.amount_msat == intent.amount_msat
    assert payment.status == "pending"
    assert payment.amount == -10_000
    balance = await connection.fetchone(
        "SELECT balance FROM balances WHERE wallet_id = :wallet_id",
        {"wallet_id": WALLET_ID},
    )
    assert balance["balance"] == 10_000

    replay, replay_payment = await arkade.reserve_arkade_outgoing_intent(
        ACCOUNT_ID, intent, conn=connection
    )
    assert replay == reserved
    assert replay_payment == payment

    async def unavailable(_account_id):
        raise AssertionError("replay fetched public state")

    monkeypatch.setattr(arkade, "fetch_arkade_indexer_vtxos", unavailable)
    await arkade.reserve_arkade_outgoing_intent(ACCOUNT_ID, intent, conn=connection)


@pytest.mark.anyio
async def test_reservation_rejects_logical_and_backing_shortfalls(
    connection, monkeypatch
):
    monkeypatch.setattr(
        settings, "lnbits_effective_installation_mode", "arkade_noncustodial"
    )
    monkeypatch.setattr(arkade, "fetch_arkade_indexer_vtxos", _backing)
    await _credit(connection, WALLET_ID, 5_000)
    with pytest.raises(arkade.ArkadeOutgoingError, match="INSUFFICIENT_FUNDS"):
        await arkade.reserve_arkade_outgoing_intent(
            ACCOUNT_ID, _intent(amount_msat=10_000), conn=connection
        )

    await _credit(connection, WALLET_ID, 20_000)
    monkeypatch.setattr(arkade, "fetch_arkade_indexer_vtxos", _low_backing)
    with pytest.raises(arkade.ArkadeOutgoingError, match="BACKING_DEFICIT"):
        await arkade.reserve_arkade_outgoing_intent(
            ACCOUNT_ID,
            _intent(amount_msat=10_000).copy(update={"intent_id": "66" * 16}),
            conn=connection,
        )


@pytest.mark.anyio
async def test_reservation_rolls_back_pair_and_release_refunds(connection, monkeypatch):
    monkeypatch.setattr(
        settings, "lnbits_effective_installation_mode", "arkade_noncustodial"
    )
    monkeypatch.setattr(arkade, "fetch_arkade_indexer_vtxos", _backing)
    await _credit(connection, WALLET_ID, 20_000)
    intent = _intent()
    original_create_payment = arkade.create_payment

    async def fail_create_payment(*args, **kwargs):
        raise ValueError("boom")

    monkeypatch.setattr(arkade, "create_payment", fail_create_payment)
    with pytest.raises(ValueError, match="boom"):
        await arkade.reserve_arkade_outgoing_intent(ACCOUNT_ID, intent, conn=connection)
    assert not await get_arkade_outgoing_intent(INTENT_ID, conn=connection)
    assert not await get_payment_by_native_id(INTENT_ID, conn=connection)
    monkeypatch.setattr(arkade, "create_payment", original_create_payment)

    _, payment = await arkade.reserve_arkade_outgoing_intent(
        ACCOUNT_ID, intent, conn=connection
    )
    with pytest.raises(arkade.ArkadeOutgoingError, match="NOT_FOUND"):
        await arkade.release_arkade_outgoing_payment(
            "aa" * 16, INTENT_ID, conn=connection
        )
    still_reserved = await get_arkade_outgoing_intent(INTENT_ID, conn=connection)
    still_pending = await get_payment_by_native_id(INTENT_ID, conn=connection)
    assert still_reserved and still_reserved.status == "reserved"
    assert still_pending and still_pending.status == "pending"
    assert await arkade.release_arkade_outgoing_payment(
        ACCOUNT_ID, INTENT_ID, conn=connection
    )
    released_payment = await get_payment_by_native_id(INTENT_ID, conn=connection)
    assert released_payment and released_payment.status == "failed"
    balance = await connection.fetchone(
        "SELECT balance FROM balances WHERE wallet_id = :wallet_id",
        {"wallet_id": WALLET_ID},
    )
    assert balance["balance"] == 20_000
    assert payment.status == "pending"
    assert not await arkade.release_arkade_outgoing_payment(
        ACCOUNT_ID, INTENT_ID, conn=connection
    )
    replayed, replayed_payment = await arkade.reserve_arkade_outgoing_intent(
        ACCOUNT_ID, intent, conn=connection
    )
    assert replayed.status == "released"
    assert replayed_payment.status == "failed"
    await connection.execute(
        "UPDATE apipayments SET status = 'pending' WHERE native_id = :intent_id",
        {"intent_id": INTENT_ID},
    )
    with pytest.raises(arkade.ArkadeOutgoingError, match="CORRUPT"):
        await arkade.reserve_arkade_outgoing_intent(ACCOUNT_ID, intent, conn=connection)


@pytest.mark.anyio
async def test_reservation_validates_idempotency_and_wallet_account(
    connection, monkeypatch
):
    monkeypatch.setattr(
        settings, "lnbits_effective_installation_mode", "arkade_noncustodial"
    )
    monkeypatch.setattr(arkade, "fetch_arkade_indexer_vtxos", _backing)
    await _credit(connection, WALLET_ID, 20_000)
    await arkade.reserve_arkade_outgoing_intent(ACCOUNT_ID, _intent(), conn=connection)
    with pytest.raises(arkade.ArkadeOutgoingError, match="IDEMPOTENCY_CONFLICT"):
        await arkade.reserve_arkade_outgoing_intent(
            ACCOUNT_ID, _intent(amount_msat=11_000), conn=connection
        )
    with pytest.raises(arkade.ArkadeOutgoingError, match="WALLET_NOT_OWNED"):
        await arkade.reserve_arkade_outgoing_intent(
            ACCOUNT_ID,
            _intent().copy(
                update={"intent_id": "77" * 16, "wallet_id": OTHER_WALLET_ID}
            ),
            conn=connection,
        )


@pytest.mark.anyio
async def test_reservation_counts_account_obligations_once(connection, monkeypatch):
    monkeypatch.setattr(
        settings, "lnbits_effective_installation_mode", "arkade_noncustodial"
    )
    monkeypatch.setattr(arkade, "fetch_arkade_indexer_vtxos", _exact_backing)
    await _credit(connection, WALLET_ID, 20_000)
    await _credit(connection, SECOND_WALLET_ID, 20_000)
    await arkade.reserve_arkade_outgoing_intent(ACCOUNT_ID, _intent(), conn=connection)
    await arkade.reserve_arkade_outgoing_intent(
        ACCOUNT_ID,
        _intent().copy(update={"intent_id": "77" * 16, "wallet_id": SECOND_WALLET_ID}),
        conn=connection,
    )
    monkeypatch.setattr(arkade, "fetch_arkade_indexer_vtxos", _low_backing)
    with pytest.raises(arkade.ArkadeOutgoingError, match="BACKING_DEFICIT"):
        await arkade.reserve_arkade_outgoing_intent(
            ACCOUNT_ID,
            _intent().copy(
                update={
                    "intent_id": "66" * 16,
                }
            ),
            conn=connection,
        )


@pytest.mark.anyio
async def test_reservation_rejects_partial_pair(connection, monkeypatch):
    monkeypatch.setattr(
        settings, "lnbits_effective_installation_mode", "arkade_noncustodial"
    )
    monkeypatch.setattr(arkade, "fetch_arkade_indexer_vtxos", _backing)
    await _credit(connection, WALLET_ID, 20_000)
    intent = _intent()
    await arkade.reserve_arkade_outgoing_intent(ACCOUNT_ID, intent, conn=connection)
    await connection.execute(
        "DELETE FROM apipayments WHERE native_id = :intent_id",
        {"intent_id": INTENT_ID},
    )
    with pytest.raises(arkade.ArkadeOutgoingError, match="CORRUPT"):
        await arkade.reserve_arkade_outgoing_intent(ACCOUNT_ID, intent, conn=connection)


@pytest.mark.anyio
async def test_reservation_rejects_conflicting_backing_duplicates(
    connection, monkeypatch
):
    monkeypatch.setattr(
        settings, "lnbits_effective_installation_mode", "arkade_noncustodial"
    )

    async def conflicting(_account_id):
        return [
            arkade.ArkadeIndexerVtxo(
                txid="96" * 32, vout=0, amount_sat=10, script="aa"
            ),
            arkade.ArkadeIndexerVtxo(
                txid="96" * 32, vout=0, amount_sat=20, script="aa"
            ),
        ]

    monkeypatch.setattr(arkade, "fetch_arkade_indexer_vtxos", conflicting)
    await _credit(connection, WALLET_ID, 20_000)
    with pytest.raises(arkade.ArkadeOutgoingError, match="INVALID_RESPONSE"):
        await arkade.reserve_arkade_outgoing_intent(
            ACCOUNT_ID, _intent(), conn=connection
        )


@pytest.mark.anyio
async def test_reservation_rejects_wallet_without_send_permission(
    connection, monkeypatch
):
    monkeypatch.setattr(
        settings, "lnbits_effective_installation_mode", "arkade_noncustodial"
    )
    monkeypatch.setattr(arkade, "fetch_arkade_indexer_vtxos", _backing)
    intent = _intent().copy(
        update={"intent_id": "bb" * 16, "wallet_id": NO_SEND_WALLET_ID}
    )
    with pytest.raises(arkade.ArkadeOutgoingError, match="NOT_ALLOWED"):
        await arkade.reserve_arkade_outgoing_intent(ACCOUNT_ID, intent, conn=connection)


def test_database_busy_codes_are_sanitized():
    class Original:
        sqlstate = "40P01"

    busy = OperationalError("deadlock", {}, Original())
    unrelated = OperationalError("failure", {}, type("Original", (), {})())
    assert arkade._is_database_busy(busy)
    assert not arkade._is_database_busy(unrelated)


def test_native_outgoing_intent_rejects_nonzero_fees():
    with pytest.raises(ValidationError):
        ArkadeOutgoingIntent(**{**_intent().dict(), "max_fee_msat": 1})
    with pytest.raises(ValidationError):
        ArkadeOutgoingIntent(**{**_intent().dict(), "actual_fee_msat": 1})
    with pytest.raises(ValidationError):
        _intent(amount_msat=10_001)
    now = datetime.now(timezone.utc)
    with pytest.raises(ValidationError):
        ArkadeOutgoingIntent(
            **{**_intent().dict(), "reserved_at": now, "expires_at": now}
        )


@pytest.mark.anyio
async def test_create_is_idempotent_and_immutable(connection):
    with pytest.raises(RuntimeError, match="REQUIRES_TRANSACTION"):
        await create_arkade_outgoing_intent(_intent(), conn=connection)

    async with connection.transaction():
        intent = await create_arkade_outgoing_intent(_intent(), conn=connection)
        assert await create_arkade_outgoing_intent(_intent(), conn=connection) == intent
        with pytest.raises(ValueError, match="IDEMPOTENCY_CONFLICT"):
            await create_arkade_outgoing_intent(
                _intent(amount_msat=20_000), conn=connection
            )
        with pytest.raises(ValueError, match="IDEMPOTENCY_CONFLICT"):
            await create_arkade_outgoing_intent(
                _intent(expires_at=intent.expires_at + timedelta(hours=1)),
                conn=connection,
            )
        with pytest.raises(ValueError, match="INITIAL_STATE_INVALID"):
            await create_arkade_outgoing_intent(
                _intent().copy(update={"intent_id": "33" * 16, "status": "settled"}),
                conn=connection,
            )
        with pytest.raises(ValueError, match="WALLET_ACCOUNT_MISMATCH"):
            await create_arkade_outgoing_intent(
                _intent().copy(
                    update={"intent_id": "44" * 16, "account_id": "aa" * 16}
                ),
                conn=connection,
            )


@pytest.mark.anyio
async def test_forward_only_transitions(connection):
    input_row = ArkadeOutgoingIntentInput(
        intent_id=INTENT_ID, txid="55" * 32, vout=0, amount_sat=10
    )
    async with connection.transaction():
        await create_arkade_outgoing_intent(_intent(), conn=connection)
        with pytest.raises(ValueError, match="INPUTS_REQUIRED"):
            await submit_arkade_outgoing_intent(INTENT_ID, "33" * 32, connection)
        await claim_arkade_outgoing_inputs(
            [input_row.copy(update={"amount_sat": 9})], conn=connection
        )
        with pytest.raises(ValueError, match="INPUTS_INSUFFICIENT"):
            await submit_arkade_outgoing_intent(INTENT_ID, "33" * 32, connection)
        await claim_arkade_outgoing_inputs(
            [input_row.copy(update={"txid": "56" * 32, "amount_sat": 1})],
            conn=connection,
        )
        with pytest.raises(ValueError, match="TRANSACTION_ID_INVALID"):
            await submit_arkade_outgoing_intent(INTENT_ID, "invalid", connection)
        assert await submit_arkade_outgoing_intent(INTENT_ID, "33" * 32, connection)

    async with connection.transaction():
        assert await settle_arkade_outgoing_intent(INTENT_ID, 0, connection)
    settled = await get_arkade_outgoing_intent(INTENT_ID, conn=connection)
    assert settled and settled.status == "settled"
    assert settled.actual_fee_msat == 0
    async with connection.transaction():
        with pytest.raises(ValueError, match="INVALID_TRANSITION"):
            await settle_arkade_outgoing_intent(INTENT_ID, 0, connection)

    over_id = "55" * 16
    async with connection.transaction():
        await create_arkade_outgoing_intent(
            _intent().copy(update={"intent_id": over_id}), conn=connection
        )
        await claim_arkade_outgoing_inputs(
            [input_row.copy(update={"intent_id": over_id, "txid": "66" * 32})],
            conn=connection,
        )
        assert await submit_arkade_outgoing_intent(over_id, "66" * 32, connection)
    async with connection.transaction():
        with pytest.raises(ValueError, match="FEE_EXCEEDED"):
            await settle_arkade_outgoing_intent(over_id, 1, connection)

    released_id = "44" * 16
    released_input = input_row.copy(
        update={"intent_id": released_id, "txid": "77" * 32}
    )
    async with connection.transaction():
        await create_arkade_outgoing_intent(
            _intent().copy(update={"intent_id": released_id}), conn=connection
        )
        await claim_arkade_outgoing_inputs([released_input], conn=connection)
        assert await release_arkade_outgoing_intent(released_id, connection)
    released = await get_arkade_outgoing_intent(released_id, conn=connection)
    assert released and released.status == "released"
    assert not await get_arkade_outgoing_intent_inputs(released_id, conn=connection)


@pytest.mark.anyio
async def test_dispute_and_release_are_forward_only(connection):
    async with connection.transaction():
        await create_arkade_outgoing_intent(_intent(), conn=connection)
        await claim_arkade_outgoing_inputs(
            [
                ArkadeOutgoingIntentInput(
                    intent_id=INTENT_ID,
                    txid="55" * 32,
                    vout=0,
                    amount_sat=10,
                )
            ],
            conn=connection,
        )
        assert await submit_arkade_outgoing_intent(INTENT_ID, "33" * 32, connection)
        with pytest.raises(ValueError, match="INVALID_TRANSITION"):
            await release_arkade_outgoing_intent(INTENT_ID, connection)
        assert await dispute_arkade_outgoing_intent(INTENT_ID, connection)


@pytest.mark.anyio
async def test_input_claims_are_unique_across_intents(connection):
    other_id = "44" * 16
    input_row = ArkadeOutgoingIntentInput(
        intent_id=INTENT_ID, txid="55" * 32, vout=0, amount_sat=10
    )
    async with connection.transaction():
        await create_arkade_outgoing_intent(_intent(), conn=connection)
        await create_arkade_outgoing_intent(
            _intent().copy(update={"intent_id": other_id}), conn=connection
        )
        claimed = await claim_arkade_outgoing_inputs([input_row], conn=connection)
        assert len(claimed) == 1
        assert isinstance(claimed[0].claimed_at, datetime)
        retry = await claim_arkade_outgoing_inputs([input_row], conn=connection)
        assert retry[0].dict(exclude={"claimed_at"}) == claimed[0].dict(
            exclude={"claimed_at"}
        )
        with pytest.raises(ValueError, match="ALREADY_CLAIMED"):
            await claim_arkade_outgoing_inputs(
                [input_row.copy(update={"amount_sat": 11})], conn=connection
            )
        with pytest.raises(ValueError, match="ALREADY_CLAIMED"):
            await claim_arkade_outgoing_inputs(
                [input_row.copy(update={"intent_id": other_id})], conn=connection
            )

        other_input = input_row.copy(update={"intent_id": other_id, "txid": "77" * 32})
        assert await claim_arkade_outgoing_inputs([other_input], conn=connection)
        new_input = input_row.copy(update={"txid": "66" * 32})
        with pytest.raises(ValueError, match="ALREADY_CLAIMED"):
            await claim_arkade_outgoing_inputs(
                [new_input, other_input.copy(update={"intent_id": INTENT_ID})],
                conn=connection,
            )
        assert not await connection.fetchone(
            "SELECT 1 FROM arkade_outgoing_intent_inputs WHERE txid = :txid",
            {"txid": new_input.txid},
        )

        assert await submit_arkade_outgoing_intent(INTENT_ID, "33" * 32, connection)
        with pytest.raises(ValueError, match="NOT_RESERVED"):
            await claim_arkade_outgoing_inputs([input_row], conn=connection)
