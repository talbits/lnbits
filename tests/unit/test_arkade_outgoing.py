from datetime import datetime, timedelta, timezone
from typing import cast

import pytest
from pydantic import ValidationError
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
from lnbits.core.models.arkade import (
    ArkadeOutgoingIntent,
    ArkadeOutgoingIntentInput,
)
from lnbits.db import SQLITE, Connection


@pytest.fixture
async def connection(monkeypatch):
    monkeypatch.setattr(db_module, "DB_TYPE", SQLITE)
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.connect() as raw:
        connection = Connection(cast(AsyncConnection, raw), SQLITE, "test", None)
        await connection.execute("CREATE TABLE accounts (id TEXT PRIMARY KEY)")
        await connection.execute(
            'CREATE TABLE wallets (id TEXT PRIMARY KEY, "user" TEXT NOT NULL)'
        )
        await connection.execute(
            "INSERT INTO accounts (id) VALUES (:account_id), (:other_account_id)",
            {"account_id": ACCOUNT_ID, "other_account_id": "aa" * 16},
        )
        await connection.execute(
            'INSERT INTO wallets (id, "user") VALUES (:wallet_id, :account_id)',
            {"wallet_id": WALLET_ID, "account_id": ACCOUNT_ID},
        )
        await migrations.m055_create_arkade_outgoing_tables(connection)
        yield connection
    await engine.dispose()


ACCOUNT_ID = "00" * 16
WALLET_ID = "11" * 16
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
