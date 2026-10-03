from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from typing import cast
from unittest.mock import AsyncMock

import httpx
import pytest
from bech32 import CHARSET, bech32_hrp_expand, bech32_polymod, convertbits
from coincurve import PrivateKey, PublicKeyXOnly
from pydantic import ValidationError
from sqlalchemy.exc import OperationalError
from sqlalchemy.ext.asyncio import AsyncConnection, create_async_engine

import lnbits.db as db_module
from lnbits.core import migrations
from lnbits.core.crud.arkade_lightning_events import (
    create_arkade_lightning_terminal_event,
)
from lnbits.core.crud.arkade_outgoing import (
    authorize_arkade_outgoing_intent,
    create_arkade_outgoing_intent,
    dispute_arkade_outgoing_intent,
    get_arkade_outgoing_intent,
    get_arkade_outgoing_intent_inputs,
    get_arkade_submitted_outgoing_intents,
    record_arkade_outgoing_input_facts,
    refund_arkade_lightning_intent,
    release_arkade_outgoing_intent,
    settle_arkade_lightning_intent,
    settle_arkade_outgoing_intent,
    submit_arkade_lightning_intent,
    submit_arkade_outgoing_intent,
)
from lnbits.core.crud.payments import (
    get_payment_by_native_id,
    refund_arkade_lightning_payment,
    settle_arkade_lightning_payment,
    update_payment,
)
from lnbits.core.models.arkade import (
    ArkadeLightningFundingEvidence,
    ArkadeLightningQuoteInput,
    ArkadeOutgoingChangeCommitment,
    ArkadeOutgoingEvidenceResult,
    ArkadeOutgoingIntent,
    ArkadeOutgoingIntentInput,
    ArkadeOutgoingSelectedInput,
)
from lnbits.core.models.payments import PaymentState
from lnbits.core.services import arkade, payments
from lnbits.core.services.arkade_evidence import (
    ArkadeLightningEvidenceStatus,
    ArkadeLightningEvidenceVerdict,
)
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
            "identity_descriptor TEXT, "
            "backup_acknowledged_at TIMESTAMP, created_at TIMESTAMP, "
            "updated_at TIMESTAMP, "
            "ready_at TIMESTAMP)"
        )
        await connection.execute(
            "INSERT INTO arkade_account_bindings (account_id, state, enrollment_id, "
            "network, server_url, server_pubkey, identity_xonly_pubkey, "
            "identity_descriptor, "
            "backup_acknowledged_at, ready_at) "
            "VALUES (:account_id, 'ready', :enrollment_id, "
            "'regtest', 'http://indexer', :server_pubkey, :identity, "
            ":descriptor, 1, 1)",
            {
                "account_id": ACCOUNT_ID,
                "enrollment_id": "33" * 16,
                "server_pubkey": "44" * 32,
                "identity": IDENTITY_XONLY,
                "descriptor": IDENTITY_DESCRIPTOR,
            },
        )
        await connection.execute(
            "CREATE TABLE arkade_receive_requests ("
            "native_request_id TEXT PRIMARY KEY, account_id TEXT NOT NULL, "
            '"index" INTEGER, script TEXT)'
        )
        await connection.execute(
            "CREATE TABLE arkade_reconciliation_state ("
            "account_id TEXT PRIMARY KEY, state TEXT NOT NULL, last_error TEXT, "
            "observed_at TIMESTAMP, updated_at TIMESTAMP)"
        )
        await connection.execute(
            "CREATE TABLE audit ("
            "component TEXT, ip_address TEXT, user_id TEXT, path TEXT, "
            "request_type TEXT, request_method TEXT, request_details TEXT, "
            "response_code TEXT, duration REAL NOT NULL, delete_at TIMESTAMP, "
            "created_at TIMESTAMP)"
        )
        await migrations.m055_create_arkade_outgoing_tables(connection)
        await migrations.m057_add_arkade_outgoing_outputs(connection)
        await migrations.m058_add_arkade_lightning_quote_fields(connection)
        await migrations.m059_create_arkade_lightning_terminal_events(connection)
        await migrations.m060_add_arkade_lightning_refund_binding(connection)
        await migrations.m061_add_arkade_lightning_failed_state(connection)
        await migrations.m062_extend_arkade_reconciliation_errors(connection)
        await migrations.m064_arkade_maintenance(connection)
        await migrations.m063_arkade_outgoing_retryable_invoice(connection)
        await migrations.m065_arkade_receipt_facts_and_funded_failure_repair(connection)
        yield connection
    await engine.dispose()


ACCOUNT_ID = "00" * 16
WALLET_ID = "11" * 16
OTHER_WALLET_ID = "66" * 16
SECOND_WALLET_ID = "88" * 16
NO_SEND_WALLET_ID = "aa" * 16
INTENT_ID = "22" * 16
IDENTITY_XONLY = "ea7e6686484c82084359642815cdcc7e99e68e97026d8d266f192671e31285df"
IDENTITY_DESCRIPTOR = (
    "tr([00000000/86'/1'/0']"
    "tpubDDG8vJgmngBej3WYjjomDbJkb5kmpiFbQbGeb5m4pnKrT4pv7U7kzwmMfSCPaiJ8ZuJdxFTgPungFZ9gj"
    "kLU98ruqahEYmUu68WPizuo9s1/0/*)"
)


def _intent(*, expires_at: datetime | None = None, amount_msat: int = 10_000):
    return ArkadeOutgoingIntent(
        intent_id=INTENT_ID,
        account_id=ACCOUNT_ID,
        wallet_id=WALLET_ID,
        amount_msat=amount_msat,
        max_fee_msat=0,
        destination="tark1qpzyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyf242424242424242424242424242424242424242424242424242uer577",
        expires_at=expires_at
        or (datetime.now(timezone.utc) + timedelta(hours=1)).replace(microsecond=0),
    )


async def _credit(connection, wallet_id: str, amount_msat: int):
    await connection.execute(
        "INSERT INTO apipayments (amount, wallet_id, memo, time, status, protocol) "
        "VALUES (:amount, :wallet_id, 'credit', 1, 'success', 'lightning')",
        {"amount": amount_msat, "wallet_id": wallet_id},
    )


async def _backing(_account_id, **_kwargs):
    assert _kwargs.get("spendable_only") is True
    return [
        arkade.ArkadeIndexerVtxo(
            txid="99" * 32,
            vout=0,
            amount_sat=100,
            script="aa",
        )
    ]


async def _low_backing(_account_id, **_kwargs):
    return [
        arkade.ArkadeIndexerVtxo(
            txid="98" * 32,
            vout=0,
            amount_sat=10,
            script="aa",
        )
    ]


async def _exact_backing(_account_id, **_kwargs):
    return [
        arkade.ArkadeIndexerVtxo(
            txid="97" * 32,
            vout=0,
            amount_sat=70,
            script="aa",
        )
    ]


async def _lightning_backing(_account_id, **_kwargs):
    if _kwargs.get("scripts"):
        return [
            arkade.ArkadeIndexerVtxo(
                txid="55" * 32,
                vout=0,
                amount_sat=5_001,
                script=CHANGE_SCRIPT,
                arkade_txid="55" * 32,
            )
        ]
    return [
        arkade.ArkadeIndexerVtxo(
            txid="96" * 32,
            vout=0,
            amount_sat=20_000,
            script="aa",
        )
    ]


def _selected(txid: str = "97" * 32, amount_sat: int = 40):
    return [ArkadeOutgoingSelectedInput(txid=txid, vout=0, amount_sat=amount_sat)]


DESTINATION_SCRIPT = "5120" + "aa" * 32
CHANGE_SCRIPT = "512045710c478a9202033ccf0ffbb0a27e8883d4cb3f6957460a8f7f4cbc800eec1f"
CHANGE_ADDRESS = (
    "tark1qpzyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3"
    "zyg3t3p3rc4yszqv7v7rlmkz38azyr6n9n762hgc9g7l6vhjqqamqlwpa9fv"
)
CHANGE_CHILD = "ea7e6686484c82084359642815cdcc7e99e68e97026d8d266f192671e31285df"
CHANGE_TAPLEAF = (
    "51b27520ea7e6686484c82084359642815cdcc7e99e68e97026d8d266f192671e31285dfacc0"
)
CHANGE_CONTROL = (
    "c150929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0"
    "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)


def _change():
    return ArkadeOutgoingChangeCommitment(
        index=0,
        address=CHANGE_ADDRESS,
        script=CHANGE_SCRIPT,
        child_xonly_pubkey=CHANGE_CHILD,
        amount_sat=30,
        exit_tapleaf=CHANGE_TAPLEAF,
        exit_control_block=CHANGE_CONTROL,
    )


@pytest.mark.anyio
def _observed(
    txid: str = "97" * 32,
    amount_sat: int = 40,
    script: str = "aa",
    **flags,
):
    return arkade.ArkadeIndexerVtxo(
        txid=txid, vout=0, amount_sat=amount_sat, script=script, **flags
    )


LIGHTNING_HASH = "ab" * 32


@pytest.mark.anyio
@pytest.mark.parametrize("compressed", [True, False])
async def test_fetch_operator_pubkey_normalizes_both_key_encodings(
    monkeypatch, compressed
):
    public = PrivateKey.from_int(1).public_key
    encoded = (
        public.format(compressed=True).hex()
        if compressed
        else public.format()[1:].hex()
    )

    class Response:
        def raise_for_status(self):
            pass

        def json(self):
            return {"signerPubkey": encoded}

    class Client:
        def __init__(self, **_kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            pass

        async def get(self, _url):
            return Response()

    monkeypatch.setattr(arkade.httpx, "AsyncClient", Client)
    assert await arkade.fetch_arkade_operator_pubkey("http://indexer") == (
        PublicKeyXOnly(public.format()[1:]).format().hex()
    )


class _LightningInvoice:
    def __init__(self, amount_msat: int | None = 5_000_000, expiry_time=None):
        self.amount_msat = amount_msat
        self.payment_hash = LIGHTNING_HASH
        self.expiry_time = (
            expiry_time or int(datetime.now(timezone.utc).timestamp()) + 3600
        )


def _lightning_quote(**updates):
    data = {
        "bolt11": "lnbc-lightning-test",
        "payment_hash": LIGHTNING_HASH,
        "amount_msat": 5_000_000,
        "max_fee_msat": 15_000,
        "quote_pair": "arkade:BTC->lightning:BTC",
        "quote_from_amount_sat": 5_001,
        "quote_to_amount_sat": 5_000,
        "quote_valid_until": datetime.now(timezone.utc) + timedelta(hours=1),
        "refund_locktime": int(datetime.now(timezone.utc).timestamp()) + 20_000,
        "solver_pubkey": "cd" * 32,
        "swap_rfq_id": "rfq-lightning-test",
        "lockup_address": CHANGE_ADDRESS,
    }
    data.update(updates)
    return ArkadeLightningQuoteInput(**data)


def _arkade_address(fill: int) -> str:
    """Encode a valid regtest tark address whose payload repeats one byte."""
    payload = bytes([0]) + bytes([fill]) * 64
    data = convertbits(payload, 8, 5, True)
    assert data is not None
    values = [*data, 0, 0, 0, 0, 0, 0]
    polymod = bech32_polymod(bech32_hrp_expand("tark") + values) ^ 0x2BC830A3
    checksum = [(polymod >> 5 * (5 - index)) & 31 for index in range(6)]
    return "tark1" + "".join(CHARSET[value] for value in data + checksum)


def _distinct_lightning_quote(seq: str, **updates):
    """Build another Lightning quote for the same test account.

    The payment hash, swap rfq id and lockup address are unique per swap, so a
    fresh intent needs its own triple. Pair it with ``_lightning_decoder``.
    """
    return _lightning_quote(
        bolt11=f"lnbc-lightning-test-{seq}",
        payment_hash=(seq * 32)[:64],
        swap_rfq_id=f"rfq-lightning-test-{seq}",
        lockup_address=_arkade_address(int(seq, 16)),
        **updates,
    )


def _lightning_decoder(*sequences: str, amount_msat: int = 5_000_000):
    """Decode the shared test invoice and each ``_distinct_lightning_quote``."""
    invoices = {"lnbc-lightning-test": _LightningInvoice(amount_msat=amount_msat)}
    for seq in sequences:
        invoice = _LightningInvoice(amount_msat=amount_msat)
        invoice.payment_hash = (seq * 32)[:64]
        invoices[f"lnbc-lightning-test-{seq}"] = invoice
    return lambda value: invoices[value]


@pytest.mark.anyio
async def test_reservation_debits_and_replays_atomically(connection, monkeypatch):
    monkeypatch.setattr(
        settings, "lnbits_effective_installation_mode", "arkade_noncustodial"
    )
    monkeypatch.setattr(arkade, "fetch_arkade_indexer_vtxos", _backing)
    await _credit(connection, WALLET_ID, 20_000)
    intent = _intent().copy(
        update={"expires_at": datetime.now(timezone.utc) + timedelta(hours=1)}
    )
    assert intent.expires_at.microsecond

    reserved, payment = await arkade.reserve_arkade_outgoing_intent(
        ACCOUNT_ID, intent, conn=connection
    )
    assert reserved.intent_id == intent.intent_id
    assert reserved.amount_msat == intent.amount_msat
    assert reserved.expires_at == intent.expires_at.replace(microsecond=0)
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
async def test_reservation_enforces_logical_balance_without_backing_lookup(
    connection, monkeypatch
):
    monkeypatch.setattr(
        settings, "lnbits_effective_installation_mode", "arkade_noncustodial"
    )
    backing = AsyncMock(side_effect=AssertionError("reservation scanned backing"))
    monkeypatch.setattr(arkade, "fetch_arkade_indexer_vtxos", backing)
    await _credit(connection, WALLET_ID, 5_000)
    with pytest.raises(arkade.ArkadeOutgoingError, match="INSUFFICIENT_FUNDS"):
        await arkade.reserve_arkade_outgoing_intent(
            ACCOUNT_ID, _intent(amount_msat=10_000), conn=connection
        )

    await _credit(connection, WALLET_ID, 20_000)
    intent, payment = await arkade.reserve_arkade_outgoing_intent(
        ACCOUNT_ID,
        _intent(amount_msat=10_000).copy(update={"intent_id": "66" * 16}),
        conn=connection,
    )
    assert intent.status == "reserved"
    assert payment.status == PaymentState.PENDING
    backing.assert_not_awaited()


@pytest.mark.anyio
async def test_lightning_reservation_enforces_wallet_balance_including_fee_reserve(
    connection, monkeypatch
):
    """The fee cap is part of the obligation and cannot exceed the wallet."""
    monkeypatch.setattr(
        settings, "lnbits_effective_installation_mode", "arkade_noncustodial"
    )

    backing = AsyncMock(side_effect=AssertionError("reservation scanned backing"))
    monkeypatch.setattr(arkade, "fetch_arkade_indexer_vtxos", backing)
    monkeypatch.setattr(arkade.bolt11, "decode", lambda _bolt11: _LightningInvoice())
    # Exactly the 5,000 sat invoice without room for its 20 sat fee cap.
    await _credit(connection, WALLET_ID, 5_000_000)
    with pytest.raises(arkade.ArkadeOutgoingError, match="^ARKADE_INSUFFICIENT_FUNDS$"):
        await arkade.reserve_arkade_lightning_intent(
            ACCOUNT_ID,
            WALLET_ID,
            _lightning_quote(),
            connection,
            idempotency_key="07" * 16,
        )
    # The selected wallet can cover amount and fee reservation; account-wide
    # balances and the advisory coin snapshot do not determine permission.
    await _credit(connection, WALLET_ID, 20_000)
    await _credit(connection, SECOND_WALLET_ID, 1_000_000)
    intent, payment = await arkade.reserve_arkade_lightning_intent(
        ACCOUNT_ID,
        WALLET_ID,
        _lightning_quote(),
        connection,
        idempotency_key="07" * 16,
    )
    assert intent.status == "quote_ready"
    assert payment.status == PaymentState.PENDING
    backing.assert_not_awaited()


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("amount_sat", "fee_sat"),
    [(500, 2), (1_000, 4), (1_153, 54), (9_970, 30), (50_000, 151)],
)
async def test_lightning_reservation_enforces_user_fee_cap(
    connection, monkeypatch, amount_sat, fee_sat
):
    monkeypatch.setattr(
        settings, "lnbits_effective_installation_mode", "arkade_noncustodial"
    )

    monkeypatch.setattr(
        arkade.bolt11,
        "decode",
        lambda _bolt11: _LightningInvoice(amount_msat=amount_sat * 1000),
    )
    # The wallet balance covers the invoice and cap; only invalid quote caps
    # should be rejected.
    await _credit(connection, WALLET_ID, (amount_sat + fee_sat + 1) * 1000)
    quote = _lightning_quote(
        amount_msat=amount_sat * 1000,
        max_fee_msat=fee_sat * 1000,
        quote_from_amount_sat=amount_sat + fee_sat,
        quote_to_amount_sat=amount_sat,
    )

    for updates in (
        {"max_fee_msat": 50_001_000},
        {"quote_from_amount_sat": amount_sat + fee_sat + 1},
    ):
        with pytest.raises(
            arkade.ArkadeOutgoingError, match="^ARKADE_OUTGOING_INVALID_REQUEST$"
        ):
            await arkade.reserve_arkade_lightning_intent(
                ACCOUNT_ID,
                WALLET_ID,
                quote.copy(update=updates),
                connection,
                idempotency_key="08" * 16,
            )

    reserved, payment = await arkade.reserve_arkade_lightning_intent(
        ACCOUNT_ID,
        WALLET_ID,
        quote,
        connection,
        idempotency_key="08" * 16,
    )

    assert reserved.quote_from_amount_sat == amount_sat + fee_sat
    assert reserved.max_fee_msat == fee_sat * 1000
    assert payment.status == PaymentState.PENDING.value


@pytest.mark.anyio
async def test_reservation_debits_and_replays_logical_native_balance(
    connection, monkeypatch
):
    """A replay returns the same logical reservation without a second debit."""
    monkeypatch.setattr(
        settings, "lnbits_effective_installation_mode", "arkade_noncustodial"
    )
    monkeypatch.setattr(arkade, "fetch_arkade_indexer_vtxos", _exact_backing)
    await _credit(connection, WALLET_ID, 70_000)
    balance = await connection.fetchone(
        "SELECT balance FROM balances WHERE wallet_id = :wallet_id",
        {"wallet_id": WALLET_ID},
    )
    assert balance["balance"] == 70_000

    reserved, payment = await arkade.reserve_arkade_outgoing_intent(
        ACCOUNT_ID, _intent(amount_msat=10_000), conn=connection
    )

    assert reserved.status == "reserved"
    assert payment.amount == -10_000
    reserved_balance = await connection.fetchone(
        "SELECT balance FROM balances WHERE wallet_id = :wallet_id",
        {"wallet_id": WALLET_ID},
    )
    assert reserved_balance["balance"] == 60_000

    replay, replay_payment = await arkade.reserve_arkade_outgoing_intent(
        ACCOUNT_ID, _intent(amount_msat=10_000), conn=connection
    )
    assert replay == reserved
    assert replay_payment == payment
    replay_balance = await connection.fetchone(
        "SELECT balance FROM balances WHERE wallet_id = :wallet_id",
        {"wallet_id": WALLET_ID},
    )
    assert replay_balance["balance"] == 60_000


@pytest.mark.anyio
async def test_reservation_uses_logical_lightning_balance_and_fee_reserve(
    connection, monkeypatch
):
    """The selected wallet funds the invoice and its fee reserve atomically."""
    monkeypatch.setattr(
        settings, "lnbits_effective_installation_mode", "arkade_noncustodial"
    )

    async def backing(_account_id, **kwargs):
        assert kwargs.get("spendable_only") is True
        return [_observed(amount_sat=5_015)]

    monkeypatch.setattr(arkade, "fetch_arkade_indexer_vtxos", backing)
    monkeypatch.setattr(arkade.bolt11, "decode", _lightning_decoder("31"))
    # The wallet holds precisely the invoice plus its fee cap.
    await _credit(connection, WALLET_ID, 5_015_000)

    reserved, payment = await arkade.reserve_arkade_lightning_intent(
        ACCOUNT_ID,
        WALLET_ID,
        _lightning_quote(),
        connection,
        idempotency_key="09" * 16,
    )
    assert reserved.status == "quote_ready"
    assert reserved.max_fee_msat == 15_000
    assert payment.amount == -5_000_000
    balance = await connection.fetchone(
        "SELECT balance FROM balances WHERE wallet_id = :wallet_id",
        {"wallet_id": WALLET_ID},
    )
    assert balance["balance"] == 15_000

    replay, replay_payment = await arkade.reserve_arkade_lightning_intent(
        ACCOUNT_ID,
        WALLET_ID,
        _lightning_quote(),
        connection,
        idempotency_key="09" * 16,
    )
    assert replay == reserved
    assert replay_payment == payment

    # The funded amount and fee reserve are committed, so the wallet cannot
    # reserve the same balance twice.
    with pytest.raises(arkade.ArkadeOutgoingError, match="^ARKADE_INSUFFICIENT_FUNDS$"):
        await arkade.reserve_arkade_lightning_intent(
            ACCOUNT_ID,
            WALLET_ID,
            _distinct_lightning_quote("31"),
            connection,
            idempotency_key="31" * 16,
        )


@pytest.mark.anyio
async def test_lightning_replay_after_settlement_returns_recorded_pair(
    connection, monkeypatch
):
    """A settled send replays as its recorded pair, never as corrupt.

    The payment row carries the settlement fee once the send settles, so the
    replay path must expect that fee instead of the pending zero.
    """
    monkeypatch.setattr(
        settings, "lnbits_effective_installation_mode", "arkade_noncustodial"
    )

    async def backing(_account_id, **kwargs):
        assert kwargs.get("spendable_only") is True
        return [_observed(amount_sat=5_015)]

    monkeypatch.setattr(arkade, "fetch_arkade_indexer_vtxos", backing)
    monkeypatch.setattr(arkade.bolt11, "decode", _lightning_decoder("32"))
    await _credit(connection, WALLET_ID, 5_015_000)
    quote = _distinct_lightning_quote("32")

    reserved, payment = await arkade.reserve_arkade_lightning_intent(
        ACCOUNT_ID, WALLET_ID, quote, connection, idempotency_key="32" * 16
    )
    async with connection.transaction():
        assert await submit_arkade_lightning_intent(
            reserved.intent_id,
            "ab" * 32,
            lockup_address=quote.lockup_address,
            swap_rfq_id=quote.swap_rfq_id,
            solver_pubkey=quote.solver_pubkey,
            sender_pubkey="cd" * 32,
            refund_pk_script="51",
            conn=connection,
        )
        assert await settle_arkade_lightning_intent(
            reserved.intent_id,
            "ef" * 32,
            account_id=ACCOUNT_ID,
            wallet_id=WALLET_ID,
            conn=connection,
        )
    payment.status = PaymentState.SUCCESS.value
    payment.fee = -1_000
    await update_payment(payment, conn=connection)

    replay, replayed_payment = await arkade.reserve_arkade_lightning_intent(
        ACCOUNT_ID, WALLET_ID, quote, connection, idempotency_key="32" * 16
    )
    assert replay.status == "settled"
    assert replay == await get_arkade_outgoing_intent(
        reserved.intent_id, conn=connection
    )
    assert replayed_payment.status == PaymentState.SUCCESS.value
    assert replayed_payment.fee == -1_000


@pytest.mark.anyio
async def test_lightning_replay_after_quote_window_returns_recorded_pair(
    connection, monkeypatch
):
    """Quote and invoice expiry gate new reservations, not recorded replays."""
    monkeypatch.setattr(
        settings, "lnbits_effective_installation_mode", "arkade_noncustodial"
    )

    async def backing(_account_id, **kwargs):
        assert kwargs.get("spendable_only") is True
        return [_observed(amount_sat=5_015)]

    monkeypatch.setattr(arkade, "fetch_arkade_indexer_vtxos", backing)
    monkeypatch.setattr(arkade.bolt11, "decode", _lightning_decoder("33"))
    await _credit(connection, WALLET_ID, 5_015_000)
    quote = _distinct_lightning_quote("33")

    reserved, payment = await arkade.reserve_arkade_lightning_intent(
        ACCOUNT_ID, WALLET_ID, quote, connection, idempotency_key="33" * 16
    )

    class FrozenClock(datetime):
        current = datetime.now(timezone.utc) + timedelta(hours=2)

        @classmethod
        def now(cls, tz=None):
            return cls.current if tz is not None else cls.current.replace(tzinfo=None)

    monkeypatch.setattr(arkade, "datetime", FrozenClock)

    replay, replayed_payment = await arkade.reserve_arkade_lightning_intent(
        ACCOUNT_ID, WALLET_ID, quote, connection, idempotency_key="33" * 16
    )
    assert replay == reserved
    assert replayed_payment == payment


@pytest.mark.anyio
async def test_failed_report_is_diagnostic_and_keeps_funded_debit_pending(
    connection, monkeypatch
):
    """A browser report cannot release a funded payment without proof."""
    monkeypatch.setattr(
        settings, "lnbits_effective_installation_mode", "arkade_noncustodial"
    )

    async def backing(_account_id, **kwargs):
        assert kwargs.get("spendable_only") is True
        return [_observed(amount_sat=5_015)]

    monkeypatch.setattr(arkade, "fetch_arkade_indexer_vtxos", backing)
    monkeypatch.setattr(arkade.bolt11, "decode", _lightning_decoder("34"))
    await _credit(connection, WALLET_ID, 5_015_000)
    quote = _distinct_lightning_quote("34")
    reserved, _payment = await arkade.reserve_arkade_lightning_intent(
        ACCOUNT_ID, WALLET_ID, quote, connection, idempotency_key="34" * 16
    )
    async with connection.transaction():
        assert await submit_arkade_lightning_intent(
            reserved.intent_id,
            "ab" * 32,
            lockup_address=quote.lockup_address,
            swap_rfq_id=quote.swap_rfq_id,
            solver_pubkey=quote.solver_pubkey,
            sender_pubkey="cd" * 32,
            refund_pk_script="51",
            conn=connection,
        )

    result = await arkade.fail_arkade_lightning_intent(
        ACCOUNT_ID, reserved.intent_id, "claim_attempt_failed", conn=connection
    )

    assert result.status == "submitted"
    assert result.failure_reason == "claim_attempt_failed"
    assert result.failed_at is not None
    stored = await get_arkade_outgoing_intent(reserved.intent_id, conn=connection)
    assert stored and stored.status == "submitted"
    assert stored.failure_reason == "claim_attempt_failed"
    failed_payment = await get_payment_by_native_id(reserved.intent_id, conn=connection)
    assert failed_payment is not None
    assert failed_payment.status == PaymentState.PENDING.value
    assert failed_payment.fee == 0
    reconciliation = await connection.fetchone(
        "SELECT state, last_error FROM arkade_reconciliation_state "
        "WHERE account_id = :account_id",
        {"account_id": ACCOUNT_ID},
    )
    assert reconciliation is None
    events = await connection.fetchall(
        "SELECT event_id, terminal_state FROM arkade_lightning_terminal_events"
    )
    assert events == []

    replay = await arkade.fail_arkade_lightning_intent(
        ACCOUNT_ID, reserved.intent_id, "claim_attempt_failed", conn=connection
    )
    assert replay.status == "submitted"
    events = await connection.fetchall(
        "SELECT event_id FROM arkade_lightning_terminal_events"
    )
    assert events == []
    with pytest.raises(
        arkade.ArkadeOutgoingError, match="^ARKADE_OUTGOING_IDEMPOTENCY_CONFLICT$"
    ):
        await arkade.fail_arkade_lightning_intent(
            ACCOUNT_ID, reserved.intent_id, "different_reason", conn=connection
        )


async def _seed_legacy_funded_failure(connection, monkeypatch, idempotency_key):
    monkeypatch.setattr(
        settings, "lnbits_effective_installation_mode", "arkade_noncustodial"
    )
    created = await _submitted_lightning_intent(
        connection, monkeypatch, idempotency_key
    )
    intent = await get_arkade_outgoing_intent(created.intent_id, conn=connection)
    assert intent and intent.arkade_txid
    now = datetime.now(timezone.utc)
    async with connection.transaction():
        await connection.execute(
            "UPDATE arkade_outgoing_intents SET status = 'failed', "
            "arkade_txid = :arkade_txid, failed_at = :now, "
            "failure_reason = 'legacy_browser_failure' "
            "WHERE intent_id = :intent_id",
            {
                "intent_id": intent.intent_id,
                "arkade_txid": intent.arkade_txid,
                "now": now,
            },
        )
        await connection.execute(
            "UPDATE apipayments SET status = 'failed' "
            "WHERE protocol = 'arkade' AND native_id = :intent_id",
            {"intent_id": intent.intent_id},
        )
        await connection.execute(
            "INSERT INTO arkade_lightning_terminal_events "
            "(event_id, terminal_state, payment_payload, next_attempt_at) "
            "VALUES (:intent_id, 'failed', '{}', :now)",
            {"intent_id": intent.intent_id, "now": now},
        )
    return intent


@pytest.mark.anyio
async def test_m065_reopens_legacy_funded_failure_and_allows_proven_terminal_event(
    connection, monkeypatch
):
    intent = await _seed_legacy_funded_failure(connection, monkeypatch, "81" * 16)

    await migrations.m065_arkade_receipt_facts_and_funded_failure_repair(connection)

    reopened = await get_arkade_outgoing_intent(intent.intent_id, conn=connection)
    pending = await get_payment_by_native_id(intent.intent_id, conn=connection)
    assert reopened and reopened.status == "submitted"
    assert reopened.failure_reason == "legacy_browser_failure"
    assert reopened.failed_at is not None
    assert pending and pending.status == PaymentState.PENDING.value and pending.fee == 0
    assert (
        await connection.fetchone(
            "SELECT event_id FROM arkade_lightning_terminal_events "
            "WHERE event_id = :intent_id AND terminal_state = 'failed'",
            {"intent_id": intent.intent_id},
        )
        is None
    )

    async with connection.transaction():
        assert await settle_arkade_lightning_intent(
            intent.intent_id,
            "ef" * 32,
            account_id=ACCOUNT_ID,
            wallet_id=WALLET_ID,
            conn=connection,
        )
        assert await settle_arkade_lightning_payment(
            intent.intent_id,
            account_id=ACCOUNT_ID,
            wallet_id=WALLET_ID,
            amount_msat=intent.amount_msat,
            arkade_address=intent.destination,
            conn=connection,
        )
        payment = await get_payment_by_native_id(intent.intent_id, conn=connection)
        assert payment is not None
        event = await create_arkade_lightning_terminal_event(
            intent.intent_id, "settled", payment, connection
        )
    assert event.terminal_state == "settled"


@pytest.mark.anyio
async def test_m065_duplicate_retry_collision_fails_without_mutating_legacy_failure(
    connection, monkeypatch
):
    intent = await _seed_legacy_funded_failure(connection, monkeypatch, "82" * 16)
    await connection.execute(
        "CREATE UNIQUE INDEX legacy_global_input_claim "
        "ON arkade_outgoing_intent_inputs (txid, vout)"
    )
    await connection.execute(
        "INSERT INTO arkade_outgoing_intents "
        "(intent_id, account_id, wallet_id, amount_msat, max_fee_msat, "
        "destination, destination_kind, status, payment_hash, expires_at) "
        "SELECT :retry_id, account_id, wallet_id, amount_msat, max_fee_msat, "
        "destination, destination_kind, 'reserved', payment_hash, expires_at "
        "FROM arkade_outgoing_intents WHERE intent_id = :intent_id",
        {"intent_id": intent.intent_id, "retry_id": "99" * 16},
    )

    with pytest.raises(RuntimeError, match="shares a payment hash with live/settled"):
        await migrations.m065_arkade_receipt_facts_and_funded_failure_repair(connection)

    failed = await get_arkade_outgoing_intent(intent.intent_id, conn=connection)
    failed_payment = await get_payment_by_native_id(intent.intent_id, conn=connection)
    old_event = await connection.fetchone(
        "SELECT terminal_state FROM arkade_lightning_terminal_events "
        "WHERE event_id = :intent_id",
        {"intent_id": intent.intent_id},
    )
    input_index = await connection.fetchone(
        "SELECT name FROM sqlite_master WHERE type = 'index' "
        "AND name = 'legacy_global_input_claim'"
    )
    assert failed and failed.status == "failed"
    assert failed_payment and failed_payment.status == PaymentState.FAILED.value
    assert old_event and old_event["terminal_state"] == "failed"
    assert input_index is not None


@pytest.mark.anyio
async def test_m065_rolls_back_schema_and_ledger_repair_on_database_error(
    connection, monkeypatch
):
    intent = await _seed_legacy_funded_failure(connection, monkeypatch, "83" * 16)
    await connection.execute(
        "CREATE UNIQUE INDEX legacy_global_input_claim "
        "ON arkade_outgoing_intent_inputs (txid, vout)"
    )
    await connection.execute(
        "CREATE TRIGGER injected_m065_failure BEFORE UPDATE OF status ON apipayments "
        f"WHEN OLD.native_id = '{intent.intent_id}' "
        "BEGIN SELECT RAISE(ABORT, 'injected migration failure'); END"
    )

    with pytest.raises(Exception, match="injected migration failure"):
        await migrations.m065_arkade_receipt_facts_and_funded_failure_repair(connection)

    failed = await get_arkade_outgoing_intent(intent.intent_id, conn=connection)
    failed_payment = await get_payment_by_native_id(intent.intent_id, conn=connection)
    old_event = await connection.fetchone(
        "SELECT terminal_state FROM arkade_lightning_terminal_events "
        "WHERE event_id = :intent_id",
        {"intent_id": intent.intent_id},
    )
    input_index = await connection.fetchone(
        "SELECT name FROM sqlite_master WHERE type = 'index' "
        "AND name = 'legacy_global_input_claim'"
    )
    assert failed and failed.status == "failed"
    assert failed_payment and failed_payment.status == PaymentState.FAILED.value
    assert old_event and old_event["terminal_state"] == "failed"
    assert input_index is not None


@pytest.mark.anyio
async def test_failed_report_requires_a_submitted_intent(connection, monkeypatch):
    """Only a funded swap can fail, and the reason must be usable evidence."""
    monkeypatch.setattr(
        settings, "lnbits_effective_installation_mode", "arkade_noncustodial"
    )

    async def backing(_account_id, **kwargs):
        return [_observed(amount_sat=5_015)]

    monkeypatch.setattr(arkade, "fetch_arkade_indexer_vtxos", backing)
    monkeypatch.setattr(arkade.bolt11, "decode", _lightning_decoder("35"))
    await _credit(connection, WALLET_ID, 5_015_000)
    quote = _distinct_lightning_quote("35")
    reserved, _payment = await arkade.reserve_arkade_lightning_intent(
        ACCOUNT_ID, WALLET_ID, quote, connection, idempotency_key="35" * 16
    )

    with pytest.raises(
        arkade.ArkadeOutgoingError, match="^ARKADE_LIGHTNING_FAILURE_REASON_INVALID$"
    ):
        await arkade.fail_arkade_lightning_intent(
            ACCOUNT_ID, reserved.intent_id, "   ", conn=connection
        )
    with pytest.raises(
        arkade.ArkadeOutgoingError, match="^ARKADE_INTENT_INVALID_TRANSITION$"
    ):
        await arkade.fail_arkade_lightning_intent(
            ACCOUNT_ID, reserved.intent_id, "claim_attempt_failed", conn=connection
        )


@pytest.mark.anyio
async def test_reservation_never_oversubscribes_one_coin_pool(connection, monkeypatch):
    """A fee reserve left open must keep its coins out of reach."""
    monkeypatch.setattr(
        settings, "lnbits_effective_installation_mode", "arkade_noncustodial"
    )

    async def backing(_account_id, **kwargs):
        assert kwargs.get("spendable_only") is True
        return [_observed(amount_sat=1_000)]

    monkeypatch.setattr(arkade, "fetch_arkade_indexer_vtxos", backing)
    monkeypatch.setattr(
        arkade.bolt11, "decode", _lightning_decoder("51", amount_msat=997_000)
    )
    await _credit(connection, WALLET_ID, 1_000_000)

    # The 997 sat invoice commits the whole pool: its 3 sat spread still has to
    # come out of the same coins when the swap settles.
    reserved, _payment = await arkade.reserve_arkade_lightning_intent(
        ACCOUNT_ID,
        WALLET_ID,
        _distinct_lightning_quote(
            "51",
            amount_msat=997_000,
            max_fee_msat=3_000,
            quote_from_amount_sat=1_000,
            quote_to_amount_sat=997,
        ),
        connection,
        idempotency_key="51" * 16,
    )
    assert reserved.status == "quote_ready"

    # The 3 sat remainder is not free: it is the open intent's fee reserve.
    with pytest.raises(arkade.ArkadeOutgoingError, match="^ARKADE_INSUFFICIENT_FUNDS$"):
        await arkade.reserve_arkade_outgoing_intent(
            ACCOUNT_ID,
            _intent(amount_msat=3_000).copy(update={"intent_id": "52" * 16}),
            conn=connection,
        )


async def _quote_ready_intent(connection, monkeypatch, seq: str):
    """Reserve one Lightning intent on an exactly backed wallet."""

    async def backing(_account_id, **kwargs):
        assert kwargs.get("spendable_only") is True
        return [_observed(amount_sat=5_015)]

    monkeypatch.setattr(arkade, "fetch_arkade_indexer_vtxos", backing)
    monkeypatch.setattr(arkade.bolt11, "decode", _lightning_decoder(seq))
    await _credit(connection, WALLET_ID, 5_015_000)
    intent, _payment = await arkade.reserve_arkade_lightning_intent(
        ACCOUNT_ID,
        WALLET_ID,
        _distinct_lightning_quote(seq),
        connection,
        idempotency_key=seq * 16,
    )
    assert intent.status == "quote_ready"
    return intent


@pytest.mark.anyio
async def test_quote_ready_intent_release_refunds_the_wallet(connection, monkeypatch):
    """Cancelling at the approval dialog must return the reserved funds."""
    monkeypatch.setattr(
        settings, "lnbits_effective_installation_mode", "arkade_noncustodial"
    )
    intent = await _quote_ready_intent(connection, monkeypatch, "61")

    assert await arkade.release_arkade_outgoing_payment(
        ACCOUNT_ID, intent.intent_id, conn=connection
    )
    released = await get_arkade_outgoing_intent(intent.intent_id, conn=connection)
    assert released and released.status == "released"
    released_payment = await get_payment_by_native_id(intent.intent_id, conn=connection)
    assert released_payment and released_payment.status == PaymentState.FAILED.value
    balance = await connection.fetchone(
        "SELECT balance FROM balances WHERE wallet_id = :wallet_id",
        {"wallet_id": WALLET_ID},
    )
    assert balance["balance"] == 5_015_000
    # Releasing again is an idempotent no-op.
    assert not await arkade.release_arkade_outgoing_payment(
        ACCOUNT_ID, intent.intent_id, conn=connection
    )


@pytest.mark.anyio
async def test_funded_intent_cannot_be_released(connection, monkeypatch):
    """A funded swap must be resolved by settlement, refund or dispute."""
    monkeypatch.setattr(
        settings, "lnbits_effective_installation_mode", "arkade_noncustodial"
    )
    intent = await _quote_ready_intent(connection, monkeypatch, "62")
    await connection.execute(
        "UPDATE arkade_outgoing_intents SET arkade_txid = :txid "
        "WHERE intent_id = :intent_id",
        {"txid": "ab" * 32, "intent_id": intent.intent_id},
    )

    with pytest.raises(
        arkade.ArkadeOutgoingError, match="^ARKADE_INTENT_INVALID_TRANSITION$"
    ):
        await arkade.release_arkade_outgoing_payment(
            ACCOUNT_ID, intent.intent_id, conn=connection
        )


@pytest.mark.anyio
async def test_expired_unfunded_reservation_releases_once_and_frees_invoice(
    connection, monkeypatch
):
    """A reservation nothing funded must expire and let the invoice retry."""
    monkeypatch.setattr(
        settings, "lnbits_effective_installation_mode", "arkade_noncustodial"
    )

    async def backing(_account_id, **kwargs):
        assert kwargs.get("spendable_only") is True
        return [
            _observed(txid=f"{index:064x}", amount_sat=5_015)
            for index in (61, 62, 63, 64, 65, 66)
        ]

    monkeypatch.setattr(arkade, "fetch_arkade_indexer_vtxos", backing)
    monkeypatch.setattr(
        arkade.bolt11, "decode", _lightning_decoder("71", "72", "73", "74", "75")
    )
    await _credit(connection, WALLET_ID, 30_000_000)

    async def reserve(quote, key: str):
        intent, _payment = await arkade.reserve_arkade_lightning_intent(
            ACCOUNT_ID, WALLET_ID, quote, connection, idempotency_key=key
        )
        assert intent.status == "quote_ready"
        return intent

    async def balance() -> int:
        row = await connection.fetchone(
            "SELECT balance FROM balances WHERE wallet_id = :wallet_id",
            {"wallet_id": WALLET_ID},
        )
        return int(row["balance"])

    def same_invoice_quote(seq: str):
        return _distinct_lightning_quote(seq).copy(
            update={
                "bolt11": "lnbc-lightning-test-71",
                "payment_hash": ("71" * 32)[:64],
            }
        )

    expired = await reserve(_distinct_lightning_quote("71"), "71" * 16)
    untouched = await reserve(_distinct_lightning_quote("73"), "73" * 16)
    funded = await reserve(_distinct_lightning_quote("74"), "74" * 16)
    # A second live intent for the same invoice stays impossible.
    with pytest.raises(arkade.ArkadeOutgoingError, match="IDEMPOTENCY_CONFLICT"):
        await reserve(same_invoice_quote("72"), "72" * 16)

    await connection.execute(
        "UPDATE arkade_outgoing_intents SET expires_at = :expires_at, "
        "reserved_at = :reserved_at WHERE intent_id = :intent_id",
        {
            "expires_at": datetime.now(timezone.utc) - timedelta(minutes=1),
            "reserved_at": datetime.now(timezone.utc) - timedelta(minutes=11),
            "intent_id": expired.intent_id,
        },
    )
    await connection.execute(
        "UPDATE arkade_outgoing_intents SET status = 'submitted', "
        "arkade_txid = :txid WHERE intent_id = :intent_id",
        {"txid": "ab" * 32, "intent_id": funded.intent_id},
    )
    before = await balance()

    async with connection.transaction():
        assert await arkade.expire_arkade_outgoing_reservations(connection) == 1

    released = await get_arkade_outgoing_intent(expired.intent_id, conn=connection)
    assert released and released.status == "released"
    released_payment = await get_payment_by_native_id(
        expired.intent_id, conn=connection
    )
    assert released_payment and released_payment.status == PaymentState.FAILED.value
    assert "expired" in released_payment.labels
    assert await balance() - before == 5_000_000
    untouched_stored = await get_arkade_outgoing_intent(
        untouched.intent_id, conn=connection
    )
    assert untouched_stored and untouched_stored.status == "quote_ready"
    funded_stored = await get_arkade_outgoing_intent(funded.intent_id, conn=connection)
    assert funded_stored and funded_stored.status == "submitted"

    async with connection.transaction():
        assert await arkade.expire_arkade_outgoing_reservations(connection) == 0
    still_released = await get_arkade_outgoing_intent(
        expired.intent_id, conn=connection
    )
    assert still_released and still_released.released_at == released.released_at

    retry = await reserve(same_invoice_quote("72"), "72" * 16)
    assert retry.intent_id != expired.intent_id
    with pytest.raises(arkade.ArkadeOutgoingError, match="IDEMPOTENCY_CONFLICT"):
        await reserve(same_invoice_quote("75"), "75" * 16)


@pytest.mark.anyio
async def test_pending_check_expires_unfunded_reservation(connection, monkeypatch):
    """The periodic pending check is what actually expires the reservation."""
    monkeypatch.setattr(
        settings, "lnbits_effective_installation_mode", "arkade_noncustodial"
    )

    async def backing(_account_id, **_kwargs):
        return [_observed(amount_sat=5_015)]

    monkeypatch.setattr(arkade, "fetch_arkade_indexer_vtxos", backing)
    monkeypatch.setattr(arkade.bolt11, "decode", _lightning_decoder("76"))
    await _credit(connection, WALLET_ID, 5_015_000)
    intent, _payment = await arkade.reserve_arkade_lightning_intent(
        ACCOUNT_ID,
        WALLET_ID,
        _distinct_lightning_quote("76"),
        connection,
        idempotency_key="76" * 16,
    )
    await connection.execute(
        "UPDATE arkade_outgoing_intents SET expires_at = :expires_at, "
        "reserved_at = :reserved_at WHERE intent_id = :intent_id",
        {
            "expires_at": datetime.now(timezone.utc) - timedelta(minutes=1),
            "reserved_at": datetime.now(timezone.utc) - timedelta(minutes=11),
            "intent_id": intent.intent_id,
        },
    )

    @asynccontextmanager
    async def use_connection():
        yield connection

    async def none(**_kwargs):
        return []

    monkeypatch.setattr(payments.db, "connect", use_connection)
    monkeypatch.setattr(payments, "get_arkade_ready_account_ids", none)
    monkeypatch.setattr(payments, "get_arkade_submitted_outgoing_intents", none)

    await payments.check_pending_payments()

    stored = await get_arkade_outgoing_intent(intent.intent_id, conn=connection)
    assert stored and stored.status == "released"
    stored_payment = await get_payment_by_native_id(intent.intent_id, conn=connection)
    assert stored_payment and stored_payment.status == PaymentState.FAILED.value
    assert "expired" in stored_payment.labels


@pytest.mark.anyio
async def test_reservation_ignores_legacy_reconciliation_diagnostic(
    connection, monkeypatch
):
    """Historical account diagnostics no longer grant payment permission."""
    monkeypatch.setattr(
        settings, "lnbits_effective_installation_mode", "arkade_noncustodial"
    )
    monkeypatch.setattr(arkade, "fetch_arkade_indexer_vtxos", _backing)
    await _credit(connection, WALLET_ID, 20_000)
    await connection.execute(
        "INSERT INTO arkade_reconciliation_state "
        "(account_id, state, last_error) VALUES "
        "(:account_id, 'reconciliation_required', 'ARKADE_RECONCILIATION_REQUIRED')",
        {"account_id": ACCOUNT_ID},
    )

    intent, _payment = await arkade.reserve_arkade_outgoing_intent(
        ACCOUNT_ID, _intent(), conn=connection
    )

    assert intent.intent_id == INTENT_ID
    assert intent.status == "reserved"


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
@pytest.mark.parametrize("case", ["malformed", "network", "server"])
async def test_reservation_rejects_invalid_destination_before_debit(
    connection, monkeypatch, case
):
    monkeypatch.setattr(
        settings, "lnbits_effective_installation_mode", "arkade_noncustodial"
    )
    monkeypatch.setattr(
        arkade,
        "fetch_arkade_indexer_vtxos",
        AsyncMock(side_effect=AssertionError("must validate before indexer I/O")),
    )
    intent = _intent()
    if case == "malformed":
        intent.destination = "tark1typo"
    elif case == "network":
        await connection.execute(
            "UPDATE arkade_account_bindings SET network = 'bitcoin' "
            "WHERE account_id = :account_id",
            {"account_id": ACCOUNT_ID},
        )
    else:
        await connection.execute(
            "UPDATE arkade_account_bindings SET server_pubkey = :server_pubkey "
            "WHERE account_id = :account_id",
            {"account_id": ACCOUNT_ID, "server_pubkey": "55" * 32},
        )

    with pytest.raises(arkade.ArkadeOutgoingError, match="OUTPUT_INVALID"):
        await arkade.reserve_arkade_outgoing_intent(ACCOUNT_ID, intent, conn=connection)
    assert not await get_arkade_outgoing_intent(INTENT_ID, conn=connection)
    assert not await get_payment_by_native_id(INTENT_ID, conn=connection)


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
    reserved, payment = await arkade.reserve_arkade_outgoing_intent(
        ACCOUNT_ID,
        _intent().copy(update={"intent_id": "66" * 16}),
        conn=connection,
    )
    assert reserved.status == "reserved"
    assert payment.status == PaymentState.PENDING.value


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
async def test_reservation_does_not_gate_on_backing_snapshot(connection, monkeypatch):
    monkeypatch.setattr(
        settings, "lnbits_effective_installation_mode", "arkade_noncustodial"
    )

    backing = AsyncMock(
        return_value=[
            arkade.ArkadeIndexerVtxo(
                txid="96" * 32, vout=0, amount_sat=10, script="aa"
            ),
            arkade.ArkadeIndexerVtxo(
                txid="96" * 32, vout=0, amount_sat=20, script="aa"
            ),
        ]
    )
    monkeypatch.setattr(arkade, "fetch_arkade_indexer_vtxos", backing)
    await _credit(connection, WALLET_ID, 20_000)
    intent, payment = await arkade.reserve_arkade_outgoing_intent(
        ACCOUNT_ID, _intent(), conn=connection
    )
    assert intent.status == "reserved"
    assert payment.status == PaymentState.PENDING.value
    backing.assert_not_awaited()


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
    now = datetime.now(timezone.utc).replace(microsecond=0)
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
        with pytest.raises(ValueError, match="INITIAL_STATE_INVALID"):
            await create_arkade_outgoing_intent(
                _intent().copy(
                    update={
                        "intent_id": "55" * 16,
                        "destination_script": DESTINATION_SCRIPT,
                    }
                ),
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
        await record_arkade_outgoing_input_facts(
            [input_row.copy(update={"amount_sat": 9})], conn=connection
        )
        with pytest.raises(ValueError, match="INPUTS_INSUFFICIENT"):
            await submit_arkade_outgoing_intent(INTENT_ID, "33" * 32, connection)
        await record_arkade_outgoing_input_facts(
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
        await record_arkade_outgoing_input_facts(
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
        await record_arkade_outgoing_input_facts([released_input], conn=connection)
        assert await release_arkade_outgoing_intent(released_id, connection)
    released = await get_arkade_outgoing_intent(released_id, conn=connection)
    assert released and released.status == "released"
    assert not await get_arkade_outgoing_intent_inputs(released_id, conn=connection)


@pytest.mark.anyio
async def test_dispute_and_release_are_forward_only(connection):
    async with connection.transaction():
        await create_arkade_outgoing_intent(_intent(), conn=connection)
        await record_arkade_outgoing_input_facts(
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
    disputed = await get_arkade_outgoing_intent(INTENT_ID, conn=connection)
    assert disputed and disputed.arkade_txid is None
    assert disputed.actual_fee_msat is None


@pytest.mark.anyio
async def test_input_facts_are_idempotent_per_intent_not_exclusive(
    connection,
):
    other_id = "44" * 16
    input_row = ArkadeOutgoingIntentInput(
        intent_id=INTENT_ID, txid="55" * 32, vout=0, amount_sat=10
    )
    async with connection.transaction():
        await create_arkade_outgoing_intent(_intent(), conn=connection)
        await create_arkade_outgoing_intent(
            _intent().copy(update={"intent_id": other_id}), conn=connection
        )
        recorded = await record_arkade_outgoing_input_facts(
            [input_row], conn=connection
        )
        assert len(recorded) == 1
        assert isinstance(recorded[0].claimed_at, datetime)
        retry = await record_arkade_outgoing_input_facts([input_row], conn=connection)
        assert retry[0].dict(exclude={"claimed_at"}) == recorded[0].dict(
            exclude={"claimed_at"}
        )
        with pytest.raises(ValueError, match="INPUT_FACT_CONFLICT"):
            await record_arkade_outgoing_input_facts(
                [input_row.copy(update={"amount_sat": 11})], conn=connection
            )

        other_input = input_row.copy(update={"intent_id": other_id})
        other_facts = await record_arkade_outgoing_input_facts(
            [other_input], conn=connection
        )
        assert len(other_facts) == 1
        assert await get_arkade_outgoing_intent_inputs(INTENT_ID, conn=connection)
        assert await get_arkade_outgoing_intent_inputs(other_id, conn=connection)

        with pytest.raises(ValueError, match="INPUT_FACT_CONFLICT"):
            await record_arkade_outgoing_input_facts(
                [input_row, input_row.copy(update={"amount_sat": 11})],
                conn=connection,
            )

        assert await submit_arkade_outgoing_intent(INTENT_ID, "33" * 32, connection)
        with pytest.raises(ValueError, match="NOT_RESERVED"):
            await record_arkade_outgoing_input_facts([input_row], conn=connection)


@pytest.mark.anyio
@pytest.mark.parametrize("with_change", [False, True])
async def test_authorize_exact_inputs_and_submitted_replay(
    connection, monkeypatch, with_change
):
    monkeypatch.setattr(
        settings, "lnbits_effective_installation_mode", "arkade_noncustodial"
    )
    monkeypatch.setattr(arkade, "fetch_arkade_indexer_vtxos", _backing)
    await _credit(connection, WALLET_ID, 20_000)
    await arkade.reserve_arkade_outgoing_intent(ACCOUNT_ID, _intent(), conn=connection)

    async def registered(_account_id, conn=None):
        return [SimpleNamespace(script="aa")]

    async def exact(_account_id, outpoints):
        assert outpoints == [("97" * 32, 0)]
        return [
            arkade.ArkadeIndexerVtxo(
                txid="97" * 32,
                vout=0,
                amount_sat=10 if not with_change else 40,
                script="aa",
            )
        ]

    monkeypatch.setattr(arkade, "get_arkade_receive_requests", registered)
    monkeypatch.setattr(arkade, "fetch_arkade_indexer_vtxos_for_outpoints", exact)
    selected = _selected(amount_sat=40 if with_change else 10)
    change = _change() if with_change else None
    result = await arkade.authorize_arkade_outgoing(
        ACCOUNT_ID,
        INTENT_ID,
        selected,
        conn=connection,
        destination_script=DESTINATION_SCRIPT,
        change=change,
    )
    assert result.status == "submitted"
    assert result.inputs[0].txid == "97" * 32
    stored = await get_arkade_outgoing_intent(INTENT_ID, conn=connection)
    assert stored
    assert stored.destination_script == DESTINATION_SCRIPT
    assert stored.change_index == (0 if with_change else None)
    assert stored.change_script == (CHANGE_SCRIPT if with_change else None)
    assert stored.change_amount_sat == (30 if with_change else None)

    async def unavailable(_account_id, outpoints):
        raise AssertionError("submitted replay must not fetch indexer evidence")

    monkeypatch.setattr(arkade, "fetch_arkade_indexer_vtxos_for_outpoints", unavailable)
    replay = await arkade.authorize_arkade_outgoing(
        ACCOUNT_ID,
        INTENT_ID,
        selected,
        conn=connection,
        destination_script=DESTINATION_SCRIPT,
        change=change,
    )
    assert replay == result


@pytest.mark.anyio
@pytest.mark.parametrize("previous_status", ["settled", "submitted"])
async def test_authorize_does_not_require_registered_input(
    connection, monkeypatch, previous_status
):
    monkeypatch.setattr(
        settings, "lnbits_effective_installation_mode", "arkade_noncustodial"
    )
    monkeypatch.setattr(arkade, "fetch_arkade_indexer_vtxos", _backing)
    await _credit(connection, WALLET_ID, 20_000)
    previous = _intent().copy(
        update={"intent_id": "ab" * 16, "idempotency_key": "previous"}
    )
    await arkade.reserve_arkade_outgoing_intent(ACCOUNT_ID, previous, conn=connection)
    await connection.execute(
        "UPDATE arkade_outgoing_intents SET status = :status, "
        "change_script = :script WHERE intent_id = :id",
        {"status": previous_status, "script": CHANGE_SCRIPT, "id": previous.intent_id},
    )
    await arkade.reserve_arkade_outgoing_intent(ACCOUNT_ID, _intent(), conn=connection)

    async def registered(*args, **kwargs):
        return [SimpleNamespace(script="aa")]

    async def exact(*args, **kwargs):
        return [
            arkade.ArkadeIndexerVtxo(
                txid="97" * 32, vout=0, amount_sat=10, script=CHANGE_SCRIPT
            )
        ]

    monkeypatch.setattr(arkade, "get_arkade_receive_requests", registered)
    monkeypatch.setattr(arkade, "fetch_arkade_indexer_vtxos_for_outpoints", exact)
    result = await arkade.authorize_arkade_outgoing(
        ACCOUNT_ID,
        INTENT_ID,
        _selected(amount_sat=10),
        conn=connection,
        destination_script=DESTINATION_SCRIPT,
    )
    assert result.status == "submitted"


async def _submitted_intent(connection):
    await _credit(connection, WALLET_ID, 20_000)
    await arkade.reserve_arkade_outgoing_intent(
        ACCOUNT_ID,
        _intent(),
        conn=connection,
    )
    claim = ArkadeOutgoingIntentInput(
        intent_id=INTENT_ID, txid="97" * 32, vout=0, amount_sat=10
    )
    async with connection.transaction():
        await authorize_arkade_outgoing_intent(
            [claim],
            connection,
            destination_script=DESTINATION_SCRIPT,
        )
    return claim


@pytest.mark.anyio
async def test_release_cannot_refund_submitted_intent(connection, monkeypatch):
    monkeypatch.setattr(
        settings, "lnbits_effective_installation_mode", "arkade_noncustodial"
    )
    monkeypatch.setattr(arkade, "fetch_arkade_indexer_vtxos", _backing)
    await _submitted_intent(connection)

    with pytest.raises(arkade.ArkadeOutgoingError, match="INVALID_TRANSITION"):
        await arkade.release_arkade_outgoing_payment(
            ACCOUNT_ID, INTENT_ID, conn=connection
        )
    payment = await get_payment_by_native_id(INTENT_ID, conn=connection)
    intent = await get_arkade_outgoing_intent(INTENT_ID, conn=connection)
    assert payment and payment.status == "pending"
    assert intent and intent.status == "submitted"


@pytest.mark.anyio
async def test_submitted_intent_enumeration_is_account_scoped(connection, monkeypatch):
    monkeypatch.setattr(
        settings, "lnbits_effective_installation_mode", "arkade_noncustodial"
    )
    monkeypatch.setattr(arkade, "fetch_arkade_indexer_vtxos", _backing)
    await _submitted_intent(connection)
    foreign_id = "88" * 16
    foreign = _intent().copy(
        update={
            "intent_id": foreign_id,
            "account_id": "aa" * 16,
            "wallet_id": OTHER_WALLET_ID,
        }
    )
    async with connection.transaction():
        await create_arkade_outgoing_intent(foreign, conn=connection)
        await authorize_arkade_outgoing_intent(
            [
                ArkadeOutgoingIntentInput(
                    intent_id=foreign_id, txid="98" * 32, vout=0, amount_sat=10
                )
            ],
            connection,
            destination_script=DESTINATION_SCRIPT,
        )
    result = await get_arkade_submitted_outgoing_intents(
        account_id=ACCOUNT_ID, conn=connection
    )
    assert [intent.intent_id for intent in result] == [INTENT_ID]


@pytest.mark.anyio
async def test_reconcile_outgoing_settles_intent_and_payment(connection, monkeypatch):
    monkeypatch.setattr(
        settings, "lnbits_effective_installation_mode", "arkade_noncustodial"
    )
    monkeypatch.setattr(arkade, "fetch_arkade_indexer_vtxos", _backing)
    claim = await _submitted_intent(connection)
    evidence = ArkadeOutgoingEvidenceResult(status="verified", arkade_txid="cc" * 32)
    monkeypatch.setattr(
        arkade, "verify_arkade_outgoing_evidence", AsyncMock(return_value=evidence)
    )

    @asynccontextmanager
    async def use_connection():
        yield connection

    monkeypatch.setattr(arkade.db, "connect", use_connection)
    result = await arkade.reconcile_arkade_outgoing_intent(INTENT_ID, ACCOUNT_ID)
    replay = await arkade.reconcile_arkade_outgoing_intent(INTENT_ID, ACCOUNT_ID)

    assert result == evidence
    assert replay is None
    settled = await get_arkade_outgoing_intent(INTENT_ID, conn=connection)
    payment = await get_payment_by_native_id(INTENT_ID, conn=connection)
    assert settled and settled.status == "settled"
    assert settled.arkade_txid == "cc" * 32
    assert settled.actual_fee_msat == 0
    assert payment and payment.status == PaymentState.SUCCESS.value
    assert payment.fee == 0
    assert claim.txid == "97" * 32


@pytest.mark.anyio
async def test_reconcile_outgoing_rolls_back_when_payment_cas_fails(
    connection, monkeypatch
):
    monkeypatch.setattr(
        settings, "lnbits_effective_installation_mode", "arkade_noncustodial"
    )
    monkeypatch.setattr(arkade, "fetch_arkade_indexer_vtxos", _backing)
    await _submitted_intent(connection)
    evidence = ArkadeOutgoingEvidenceResult(status="verified", arkade_txid="cc" * 32)
    monkeypatch.setattr(
        arkade, "verify_arkade_outgoing_evidence", AsyncMock(return_value=evidence)
    )
    monkeypatch.setattr(
        arkade, "settle_arkade_outgoing_payment", AsyncMock(return_value=False)
    )

    @asynccontextmanager
    async def use_connection():
        yield connection

    monkeypatch.setattr(arkade.db, "connect", use_connection)
    with pytest.raises(arkade.ArkadeReceiveError, match="CORRUPT"):
        await arkade.reconcile_arkade_outgoing_intent(INTENT_ID, ACCOUNT_ID)

    intent = await get_arkade_outgoing_intent(INTENT_ID, conn=connection)
    payment = await get_payment_by_native_id(INTENT_ID, conn=connection)
    assert intent and intent.status == "submitted"
    assert intent.arkade_txid is None
    assert intent.actual_fee_msat is None
    assert payment and payment.status == PaymentState.PENDING.value


@pytest.mark.anyio
@pytest.mark.parametrize("status", ["pending", "contradictory"])
async def test_reconcile_outgoing_keeps_pending_or_disputes(
    connection, monkeypatch, status
):
    monkeypatch.setattr(
        settings, "lnbits_effective_installation_mode", "arkade_noncustodial"
    )
    monkeypatch.setattr(arkade, "fetch_arkade_indexer_vtxos", _backing)
    await _submitted_intent(connection)
    evidence = ArkadeOutgoingEvidenceResult(status=status, code="test")
    monkeypatch.setattr(
        arkade, "verify_arkade_outgoing_evidence", AsyncMock(return_value=evidence)
    )

    @asynccontextmanager
    async def use_connection():
        yield connection

    monkeypatch.setattr(arkade.db, "connect", use_connection)
    result = await arkade.reconcile_arkade_outgoing_intent(INTENT_ID, ACCOUNT_ID)

    assert result == evidence
    intent = await get_arkade_outgoing_intent(INTENT_ID, conn=connection)
    payment = await get_payment_by_native_id(INTENT_ID, conn=connection)
    assert intent and intent.status == (
        "disputed" if status == "contradictory" else "submitted"
    )
    assert payment and payment.status == PaymentState.PENDING.value


@pytest.mark.anyio
async def test_authorize_records_input_facts_without_coin_permissions(
    connection, monkeypatch
):
    monkeypatch.setattr(
        settings, "lnbits_effective_installation_mode", "arkade_noncustodial"
    )
    await _credit(connection, WALLET_ID, 20_000)
    await arkade.reserve_arkade_outgoing_intent(ACCOUNT_ID, _intent(), conn=connection)
    indexer = AsyncMock(side_effect=AssertionError("authorization queried coin state"))
    monkeypatch.setattr(arkade, "fetch_arkade_indexer_vtxos_for_outpoints", indexer)
    monkeypatch.setattr(arkade, "get_arkade_receive_requests", indexer)

    result = await arkade.authorize_arkade_outgoing(
        ACCOUNT_ID,
        INTENT_ID,
        _selected(amount_sat=40),
        conn=connection,
        destination_script=DESTINATION_SCRIPT,
    )

    assert result.status == "submitted"
    assert [(item.txid, item.vout, item.amount_sat) for item in result.inputs] == [
        ("97" * 32, 0, 40)
    ]
    indexer.assert_not_awaited()


@pytest.mark.anyio
@pytest.mark.parametrize("payment_case", ["missing", "corrupt", "nonpending"])
async def test_authorize_rejects_corrupt_payment_pair(
    connection, monkeypatch, payment_case
):
    monkeypatch.setattr(
        settings, "lnbits_effective_installation_mode", "arkade_noncustodial"
    )
    monkeypatch.setattr(arkade, "fetch_arkade_indexer_vtxos", _backing)
    await _credit(connection, WALLET_ID, 20_000)
    await arkade.reserve_arkade_outgoing_intent(ACCOUNT_ID, _intent(), conn=connection)
    if payment_case == "missing":
        await connection.execute(
            "DELETE FROM apipayments WHERE native_id = :intent_id",
            {"intent_id": INTENT_ID},
        )
    else:
        await connection.execute(
            "UPDATE apipayments SET status = :status, arkade_address = :address "
            "WHERE native_id = :intent_id",
            {
                "status": "success" if payment_case == "nonpending" else "pending",
                "address": "wrong" if payment_case == "corrupt" else "tark1destination",
                "intent_id": INTENT_ID,
            },
        )

    async def registered(_account_id, conn=None):
        return [SimpleNamespace(script="aa")]

    monkeypatch.setattr(arkade, "get_arkade_receive_requests", registered)
    monkeypatch.setattr(
        arkade,
        "fetch_arkade_indexer_vtxos_for_outpoints",
        AsyncMock(return_value=[_observed(amount_sat=10)]),
    )
    with pytest.raises(arkade.ArkadeOutgoingError, match="CORRUPT"):
        await arkade.authorize_arkade_outgoing(
            ACCOUNT_ID,
            INTENT_ID,
            _selected(amount_sat=10),
            conn=connection,
            destination_script=DESTINATION_SCRIPT,
        )
    current = await get_arkade_outgoing_intent(INTENT_ID, conn=connection)
    assert current and current.status == "reserved"
    assert not await get_arkade_outgoing_intent_inputs(INTENT_ID, conn=connection)


@pytest.mark.anyio
async def test_authorize_allows_cross_intent_input_fact_overlap(
    connection, monkeypatch
):
    monkeypatch.setattr(
        settings, "lnbits_effective_installation_mode", "arkade_noncustodial"
    )
    await _credit(connection, WALLET_ID, 20_000)
    await arkade.reserve_arkade_outgoing_intent(ACCOUNT_ID, _intent(), conn=connection)
    competing_id = "44" * 16
    competing_input = ArkadeOutgoingIntentInput(
        intent_id=competing_id, txid="97" * 32, vout=0, amount_sat=10
    )
    async with connection.transaction():
        await create_arkade_outgoing_intent(
            _intent().copy(update={"intent_id": competing_id}), conn=connection
        )
        await record_arkade_outgoing_input_facts([competing_input], conn=connection)

    result = await arkade.authorize_arkade_outgoing(
        ACCOUNT_ID,
        INTENT_ID,
        _selected(amount_sat=10),
        conn=connection,
        destination_script=DESTINATION_SCRIPT,
    )
    assert result.status == "submitted"
    assert len(result.inputs) == 1
    assert await get_arkade_outgoing_intent_inputs(competing_id, conn=connection)


@pytest.mark.anyio
async def test_authorize_crud_rejects_false_transition(connection, monkeypatch):
    async with connection.transaction():
        await create_arkade_outgoing_intent(_intent(), conn=connection)
        monkeypatch.setattr(
            "lnbits.core.crud.arkade_outgoing._transition_arkade_outgoing_intent",
            AsyncMock(return_value=False),
        )
        with pytest.raises(ValueError, match="INVALID_TRANSITION"):
            await authorize_arkade_outgoing_intent(
                [
                    ArkadeOutgoingIntentInput(
                        intent_id=INTENT_ID,
                        txid="97" * 32,
                        vout=0,
                        amount_sat=40,
                    )
                ],
                connection,
                destination_script=DESTINATION_SCRIPT,
            )


@pytest.mark.anyio
async def test_authorize_requires_descriptor_for_output_commitment(
    connection, monkeypatch
):
    monkeypatch.setattr(
        settings, "lnbits_effective_installation_mode", "arkade_noncustodial"
    )
    monkeypatch.setattr(arkade, "fetch_arkade_indexer_vtxos", _backing)
    await _credit(connection, WALLET_ID, 20_000)
    await arkade.reserve_arkade_outgoing_intent(ACCOUNT_ID, _intent(), conn=connection)
    await connection.execute(
        "UPDATE arkade_account_bindings SET identity_descriptor = NULL "
        "WHERE account_id = :account_id",
        {"account_id": ACCOUNT_ID},
    )
    indexer = AsyncMock(side_effect=AssertionError("descriptor must be checked first"))
    monkeypatch.setattr(arkade, "fetch_arkade_indexer_vtxos_for_outpoints", indexer)

    with pytest.raises(
        arkade.ArkadeOutgoingError, match="ARKADE_DESCRIPTOR_REENROLLMENT_REQUIRED"
    ):
        await arkade.authorize_arkade_outgoing(
            ACCOUNT_ID,
            INTENT_ID,
            _selected(),
            conn=connection,
            destination_script=DESTINATION_SCRIPT,
        )

    current = await get_arkade_outgoing_intent(INTENT_ID, conn=connection)
    assert current and current.status == "reserved"
    assert not await get_arkade_outgoing_intent_inputs(INTENT_ID, conn=connection)
    indexer.assert_not_awaited()


@pytest.mark.anyio
async def test_authorize_expired_intent_fails_closed(connection, monkeypatch):
    monkeypatch.setattr(
        settings, "lnbits_effective_installation_mode", "arkade_noncustodial"
    )
    monkeypatch.setattr(arkade, "fetch_arkade_indexer_vtxos", _backing)
    await _credit(connection, WALLET_ID, 20_000)
    now = datetime.now(timezone.utc).replace(microsecond=0)
    expired = _intent().copy(
        update={
            "expires_at": now - timedelta(hours=1),
            "reserved_at": now - timedelta(hours=2),
        }
    )
    await arkade.reserve_arkade_outgoing_intent(ACCOUNT_ID, expired, conn=connection)
    with pytest.raises(arkade.ArkadeOutgoingError, match="EXPIRED"):
        await arkade.authorize_arkade_outgoing(
            ACCOUNT_ID,
            INTENT_ID,
            _selected(),
            conn=connection,
            destination_script=DESTINATION_SCRIPT,
        )


@pytest.mark.anyio
async def test_outgoing_get_is_unavailable_in_custodial_mode(connection, monkeypatch):
    monkeypatch.setattr(settings, "lnbits_effective_installation_mode", "custodial")
    with pytest.raises(arkade.ArkadeOutgoingError, match="OUTGOING_UNAVAILABLE"):
        await arkade.get_arkade_outgoing_intent_for_account(
            ACCOUNT_ID, INTENT_ID, conn=connection
        )


@pytest.mark.anyio
async def test_outgoing_reserved_response_has_no_output_script(connection, monkeypatch):
    monkeypatch.setattr(
        settings, "lnbits_effective_installation_mode", "arkade_noncustodial"
    )
    monkeypatch.setattr(arkade, "fetch_arkade_indexer_vtxos", _backing)
    await _credit(connection, WALLET_ID, 20_000)
    await arkade.reserve_arkade_outgoing_intent(ACCOUNT_ID, _intent(), conn=connection)
    response = await arkade.get_arkade_outgoing_intent_for_account(
        ACCOUNT_ID, INTENT_ID, conn=connection
    )
    assert response.status == "reserved"
    assert response.destination_script is None


@pytest.mark.anyio
async def test_outgoing_output_validation_rejects_wrong_destination_and_child(
    connection,
):
    intent = _intent()
    binding = await arkade.get_arkade_binding(ACCOUNT_ID, conn=connection)
    assert binding
    with pytest.raises(arkade.ArkadeOutgoingError, match="OUTPUT_INVALID"):
        arkade._validate_outgoing_outputs(intent, binding, "5120" + "bb" * 32, None)
    with pytest.raises(arkade.ArkadeOutgoingError, match="OUTPUT_INVALID"):
        arkade._validate_outgoing_outputs(
            intent,
            binding,
            DESTINATION_SCRIPT,
            _change().copy(update={"child_xonly_pubkey": "bb" * 32}),
        )


@pytest.mark.anyio
async def test_authorize_rejects_change_index_used_by_receive_mapping(
    connection, monkeypatch
):
    monkeypatch.setattr(
        settings, "lnbits_effective_installation_mode", "arkade_noncustodial"
    )
    monkeypatch.setattr(arkade, "fetch_arkade_indexer_vtxos", _backing)
    await _credit(connection, WALLET_ID, 20_000)
    await arkade.reserve_arkade_outgoing_intent(ACCOUNT_ID, _intent(), conn=connection)
    await connection.execute(
        "INSERT INTO arkade_receive_requests "
        '(native_request_id, account_id, "index", script) '
        "VALUES (:id, :account_id, :index, :script)",
        {
            "id": "66" * 16,
            "account_id": ACCOUNT_ID,
            "index": 0,
            "script": "5120" + "cc" * 32,
        },
    )
    monkeypatch.setattr(
        arkade,
        "get_arkade_receive_requests",
        AsyncMock(return_value=[SimpleNamespace(script="aa")]),
    )
    monkeypatch.setattr(
        arkade,
        "fetch_arkade_indexer_vtxos_for_outpoints",
        AsyncMock(return_value=[_observed(amount_sat=40)]),
    )
    with pytest.raises(arkade.ArkadeOutgoingError, match="OUTPUT_CONFLICT"):
        await arkade.authorize_arkade_outgoing(
            ACCOUNT_ID,
            INTENT_ID,
            _selected(),
            conn=connection,
            destination_script=DESTINATION_SCRIPT,
            change=_change(),
        )


@pytest.mark.anyio
async def test_exact_indexer_fetch_rejects_repeated_page(connection, monkeypatch):
    monkeypatch.setattr(
        arkade,
        "get_arkade_binding",
        AsyncMock(
            return_value=SimpleNamespace(state="ready", server_url="http://indexer")
        ),
    )

    class Response:
        def raise_for_status(self):
            return None

        def json(self):
            return {
                "vtxos": [],
                "page": {"current": 0, "next": 0, "total": 2},
            }

    class Client:
        calls = []

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return None

        async def get(self, _url, params):
            self.calls.append(params)
            return Response()

    client = Client()
    monkeypatch.setattr(arkade.httpx, "AsyncClient", lambda **_kwargs: client)
    with pytest.raises(arkade.ArkadeReceiveError, match="INVALID_RESPONSE"):
        await arkade.fetch_arkade_indexer_vtxos_for_outpoints(
            ACCOUNT_ID, [("97" * 32, 0)]
        )
    assert len(client.calls) == 1
    assert ("outpoints", f'{"97" * 32}:0') in client.calls[0]
    assert ("spendableOnly", "true") in client.calls[0]


@pytest.mark.anyio
async def test_exact_indexer_fetch_accepts_empty_first_page(monkeypatch):
    monkeypatch.setattr(
        arkade,
        "get_arkade_binding",
        AsyncMock(
            return_value=SimpleNamespace(state="ready", server_url="http://indexer")
        ),
    )

    class Response:
        def raise_for_status(self):
            return None

        def json(self):
            return {"vtxos": [], "page": {"current": 1, "next": 0, "total": 0}}

    class Client:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return None

        async def get(self, _url, params):
            assert ("outpoints", f'{"97" * 32}:0') in params
            return Response()

    monkeypatch.setattr(arkade.httpx, "AsyncClient", lambda **_kwargs: Client())
    assert (
        await arkade.fetch_arkade_indexer_vtxos_for_outpoints(
            ACCOUNT_ID, [("97" * 32, 0)]
        )
        == []
    )


@pytest.mark.anyio
async def test_exact_indexer_fetch_bounds_large_pagination(connection, monkeypatch):
    monkeypatch.setattr(
        arkade,
        "get_arkade_binding",
        AsyncMock(
            return_value=SimpleNamespace(state="ready", server_url="http://indexer")
        ),
    )

    class Response:
        def __init__(self, current):
            self.current = current

        def raise_for_status(self):
            return None

        def json(self):
            return {
                "vtxos": [],
                "page": {
                    "current": self.current,
                    "next": self.current + 1,
                    "total": 1000,
                },
            }

    class Client:
        calls = []

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return None

        async def get(self, _url, params):
            self.calls.append(params)
            return Response(len(self.calls) - 1)

    client = Client()
    monkeypatch.setattr(arkade.httpx, "AsyncClient", lambda **_kwargs: client)
    with pytest.raises(arkade.ArkadeReceiveError, match="INVALID_RESPONSE"):
        await arkade.fetch_arkade_indexer_vtxos_for_outpoints(
            ACCOUNT_ID, [("97" * 32, 0)]
        )
    assert len(client.calls) == 2


@pytest.mark.anyio
async def test_exact_indexer_fetch_transport_error_is_sanitized(monkeypatch):
    monkeypatch.setattr(
        arkade,
        "get_arkade_binding",
        AsyncMock(
            return_value=SimpleNamespace(state="ready", server_url="http://indexer")
        ),
    )

    class Client:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return None

        async def get(self, *_args, **_kwargs):
            raise httpx.ConnectError("upstream secret")

    monkeypatch.setattr(arkade.httpx, "AsyncClient", lambda **_kwargs: Client())
    with pytest.raises(arkade.ArkadeReceiveError, match="UNAVAILABLE"):
        await arkade.fetch_arkade_indexer_vtxos_for_outpoints(
            ACCOUNT_ID, [("97" * 32, 0)]
        )


def _wire_vtxo(**updates):
    wire = {
        "outpoint": {"txid": "97" * 32, "vout": 0},
        "amount": "40",
        "script": "aa",
        "isPreconfirmed": False,
        "isSpent": False,
        "isSwept": False,
        "isUnrolled": False,
        "createdAt": "1735689600",
        "expiresAt": None,
        "commitmentTxids": [],
        "spentBy": None,
        "settledBy": None,
        "arkTxid": None,
    }
    wire.update(updates)
    return {"vtxos": [wire]}


@pytest.mark.parametrize(
    "field", ["createdAt", "expiresAt", "commitmentTxids", "isUnrolled"]
)
def test_indexer_parser_requires_spendability_facts(field):
    wire = _wire_vtxo()
    del wire["vtxos"][0][field]
    with pytest.raises(arkade.ArkadeReceiveError, match="INVALID_RESPONSE"):
        arkade.parse_indexer_vtxos(wire)


def test_indexer_parser_preserves_expiry_and_terminal_facts():
    parsed = arkade.parse_indexer_vtxos(
        _wire_vtxo(
            expiresAt="1735689599",
            settledBy="66" * 32,
            arkTxid="77" * 32,
            commitmentTxids=["88" * 32],
        )
    )[0]
    assert parsed.expires_at is None
    assert parsed.expires_at_height == 1_735_689_599
    assert parsed.settled_by == "66" * 32
    assert parsed.arkade_txid == "77" * 32
    assert parsed.commitment_txids == ["88" * 32]

    timestamp = arkade.parse_indexer_vtxos(_wire_vtxo(expiresAt="1735689600"))[0]
    assert timestamp.expires_at == datetime(2025, 1, 1, tzinfo=timezone.utc)


@pytest.mark.parametrize("value", ["0", "-1", "invalid"])
def test_indexer_parser_rejects_invalid_expiry(value):
    with pytest.raises(arkade.ArkadeReceiveError, match="INVALID_RESPONSE"):
        arkade.parse_indexer_vtxos(_wire_vtxo(expiresAt=value))


@pytest.mark.parametrize("field", ["amount", "createdAt", "expiresAt"])
def test_indexer_parser_rejects_oversized_decimal(field):
    with pytest.raises(arkade.ArkadeReceiveError, match="INVALID_RESPONSE"):
        arkade.parse_indexer_vtxos(_wire_vtxo(**{field: "9" * 5000}))


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("invoice", "expected"),
    [
        (_LightningInvoice(amount_msat=None), "ARKADE_OUTGOING_AMOUNT_INVALID"),
        (
            _LightningInvoice(
                expiry_time=int(datetime.now(timezone.utc).timestamp()) - 1
            ),
            "ARKADE_OUTGOING_EXPIRED",
        ),
        (_LightningInvoice(amount_msat=499_000), "ARKADE_OUTGOING_AMOUNT_INVALID"),
        (
            _LightningInvoice(amount_msat=50_001_000),
            "ARKADE_OUTGOING_AMOUNT_INVALID",
        ),
    ],
    ids=["amountless", "expired", "below-card-bound", "above-card-bound"],
)
async def test_lightning_quote_rejects_invalid_invoice_facts(
    connection, monkeypatch, invoice, expected
):
    monkeypatch.setattr(
        settings, "lnbits_effective_installation_mode", "arkade_noncustodial"
    )
    monkeypatch.setattr(arkade, "fetch_arkade_indexer_vtxos", _lightning_backing)
    monkeypatch.setattr(arkade.bolt11, "decode", lambda _bolt11: invoice)
    with pytest.raises(arkade.ArkadeOutgoingError, match=f"^{expected}$"):
        await arkade.reserve_arkade_lightning_intent(
            ACCOUNT_ID,
            WALLET_ID,
            _lightning_quote(),
            connection,
            idempotency_key="01" * 16,
        )


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("updates", "expected"),
    [
        ({"quote_to_amount_sat": 5_001}, "ARKADE_TRANSFER_AMOUNT_CONFLICT"),
        ({"max_fee_msat": 1}, "ARKADE_OUTGOING_INVALID_REQUEST"),
        ({"quote_pair": "arkade:BTC->arkade:BTC"}, "ARKADE_OUTGOING_OUTPUT_INVALID"),
        (
            {"quote_valid_until": datetime.now(timezone.utc) - timedelta(seconds=1)},
            "ARKADE_OUTGOING_EXPIRED",
        ),
        (
            {"refund_locktime": int(datetime.now(timezone.utc).timestamp()) + 60},
            "ARKADE_OUTGOING_OUTPUT_INVALID",
        ),
    ],
    ids=["amount-conflict", "fee-cap", "pair", "quote-expiry", "refund-headroom"],
)
async def test_lightning_quote_rejects_binding_and_fee_violations(
    connection, monkeypatch, updates, expected
):
    monkeypatch.setattr(
        settings, "lnbits_effective_installation_mode", "arkade_noncustodial"
    )
    monkeypatch.setattr(arkade, "fetch_arkade_indexer_vtxos", _lightning_backing)
    monkeypatch.setattr(arkade.bolt11, "decode", lambda _bolt11: _LightningInvoice())
    with pytest.raises(arkade.ArkadeOutgoingError, match=f"^{expected}$"):
        await arkade.reserve_arkade_lightning_intent(
            ACCOUNT_ID,
            WALLET_ID,
            _lightning_quote(**updates),
            connection,
            idempotency_key="02" * 16,
        )


@pytest.mark.anyio
async def test_lightning_quote_rejects_fee_above_backend_ceiling(
    connection, monkeypatch
):
    monkeypatch.setattr(
        settings, "lnbits_effective_installation_mode", "arkade_noncustodial"
    )
    monkeypatch.setattr(arkade, "fetch_arkade_indexer_vtxos", _lightning_backing)
    monkeypatch.setattr(arkade.bolt11, "decode", lambda _bolt11: _LightningInvoice())
    quote = _lightning_quote(
        quote_from_amount_sat=5_016,
        max_fee_msat=50_001_000,
    )
    with pytest.raises(
        arkade.ArkadeOutgoingError,
        match="^ARKADE_OUTGOING_INVALID_REQUEST$",
    ):
        await arkade.reserve_arkade_lightning_intent(
            ACCOUNT_ID,
            WALLET_ID,
            quote,
            connection,
            idempotency_key="05" * 16,
        )


def test_lightning_quote_model_rejects_missing_or_invalid_bindings():
    with pytest.raises(ValidationError):
        _lightning_quote(solver_pubkey="invalid")
    with pytest.raises(ValidationError):
        _lightning_quote(lockup_address="has whitespace")
    with pytest.raises(ValidationError):
        ArkadeLightningQuoteInput(**{**_lightning_quote().dict(), "extra": True})


@pytest.mark.anyio
async def test_lightning_quote_ready_is_atomic_and_idempotent(connection, monkeypatch):
    monkeypatch.setattr(
        settings, "lnbits_effective_installation_mode", "arkade_noncustodial"
    )
    monkeypatch.setattr(arkade, "fetch_arkade_indexer_vtxos", _lightning_backing)
    monkeypatch.setattr(arkade.bolt11, "decode", lambda _bolt11: _LightningInvoice())
    await _credit(connection, WALLET_ID, 10_000_000)
    quote = _lightning_quote()
    accepted, payment = await arkade.reserve_arkade_lightning_intent(
        ACCOUNT_ID,
        WALLET_ID,
        quote,
        connection,
        idempotency_key="03" * 16,
    )
    assert accepted.status == "quote_ready"
    assert accepted.destination == quote.bolt11
    assert accepted.quote_from_amount_sat == quote.quote_from_amount_sat
    assert payment.status == PaymentState.PENDING.value

    replay, replay_payment = await arkade.reserve_arkade_lightning_intent(
        ACCOUNT_ID,
        WALLET_ID,
        quote,
        connection,
        idempotency_key="03" * 16,
    )
    assert replay == accepted
    assert replay_payment == payment

    with pytest.raises(arkade.ArkadeOutgoingError, match="IDEMPOTENCY_CONFLICT"):
        await arkade.reserve_arkade_lightning_intent(
            ACCOUNT_ID,
            WALLET_ID,
            quote.copy(update={"swap_rfq_id": "different-rfq"}),
            connection,
            idempotency_key="03" * 16,
        )
    with pytest.raises(ValueError, match="INVALID_TRANSITION"):
        async with connection.transaction():
            await release_arkade_outgoing_intent(accepted.intent_id, connection)


@pytest.mark.anyio
async def test_lightning_submit_accepts_a_lockup_claimed_before_submit(
    connection, monkeypatch
):
    """A browser that dies between funding and submit must still be able to
    report the funding when it comes back, even though the solver claimed the
    lockup in the meantime: the spend is classified from evidence later, not
    gated at recording time."""
    monkeypatch.setattr(
        settings, "lnbits_effective_installation_mode", "arkade_noncustodial"
    )
    monkeypatch.setattr(arkade, "fetch_arkade_indexer_vtxos", _lightning_backing)
    monkeypatch.setattr(arkade.bolt11, "decode", lambda _bolt11: _LightningInvoice())
    await _credit(connection, WALLET_ID, 10_000_000)
    quote = _lightning_quote()
    accepted, _ = await arkade.reserve_arkade_lightning_intent(
        ACCOUNT_ID,
        WALLET_ID,
        quote,
        connection,
        idempotency_key="0a" * 16,
    )

    async def claimed_lockup(_account_id, **kwargs):
        assert kwargs["spendable_only"] is False
        return [
            arkade.ArkadeIndexerVtxo(
                txid="55" * 32,
                vout=0,
                amount_sat=quote.quote_from_amount_sat,
                script=CHANGE_SCRIPT,
                is_spent=True,
                spent_by="88" * 32,
                arkade_txid="99" * 32,
            )
        ]

    monkeypatch.setattr(arkade, "fetch_arkade_indexer_vtxos", claimed_lockup)
    submitted = await arkade.submit_arkade_lightning_intent(
        ACCOUNT_ID,
        accepted.intent_id,
        ArkadeLightningFundingEvidence(
            ark_txid="55" * 32,
            lockup_address=quote.lockup_address,
            swap_rfq_id=quote.swap_rfq_id,
            solver_pubkey=quote.solver_pubkey,
            sender_pubkey=IDENTITY_XONLY,
            refund_pk_script="5120" + IDENTITY_XONLY,
        ),
        conn=connection,
    )
    assert submitted.status == "submitted"
    assert submitted.arkade_txid == "55" * 32


@pytest.mark.anyio
async def test_lightning_submit_records_public_funding_and_is_idempotent(
    connection, monkeypatch
):
    monkeypatch.setattr(
        settings, "lnbits_effective_installation_mode", "arkade_noncustodial"
    )

    monkeypatch.setattr(arkade, "fetch_arkade_indexer_vtxos", _lightning_backing)
    monkeypatch.setattr(arkade.bolt11, "decode", lambda _bolt11: _LightningInvoice())
    await _credit(connection, WALLET_ID, 10_000_000)
    quote = _lightning_quote(
        quote_valid_until=datetime.now(timezone.utc) + timedelta(hours=1),
        refund_locktime=int(datetime.now(timezone.utc).timestamp()) + 20_000,
    )
    accepted, _ = await arkade.reserve_arkade_lightning_intent(
        ACCOUNT_ID,
        WALLET_ID,
        quote,
        connection,
        idempotency_key="04" * 16,
    )
    funding = ArkadeLightningFundingEvidence(
        ark_txid="55" * 32,
        lockup_address=quote.lockup_address,
        swap_rfq_id=quote.swap_rfq_id,
        solver_pubkey=quote.solver_pubkey,
        sender_pubkey=IDENTITY_XONLY,
        refund_pk_script="5120" + IDENTITY_XONLY,
    )

    submitted = await arkade.submit_arkade_lightning_intent(
        ACCOUNT_ID, accepted.intent_id, funding, conn=connection
    )
    assert submitted.status == "submitted"
    assert submitted.arkade_txid == funding.ark_txid
    assert submitted.destination_kind == "lightning"
    assert submitted.quote_pair == quote.quote_pair
    assert submitted.quote_from_amount_sat == quote.quote_from_amount_sat
    assert submitted.quote_to_amount_sat == quote.quote_to_amount_sat
    assert submitted.quote_valid_until is not None
    assert submitted.refund_locktime == quote.refund_locktime
    assert submitted.solver_pubkey == quote.solver_pubkey
    assert submitted.swap_rfq_id == quote.swap_rfq_id
    assert submitted.lockup_address == quote.lockup_address
    inputs = await get_arkade_outgoing_intent_inputs(
        accepted.intent_id, conn=connection
    )
    assert [(item.txid, item.vout, item.amount_sat) for item in inputs] == [
        (funding.ark_txid, 0, quote.quote_from_amount_sat)
    ]

    replay = await arkade.submit_arkade_lightning_intent(
        ACCOUNT_ID, accepted.intent_id, funding, conn=connection
    )
    assert replay == submitted
    with pytest.raises(arkade.ArkadeOutgoingError, match="IDEMPOTENCY_CONFLICT"):
        await arkade.submit_arkade_lightning_intent(
            ACCOUNT_ID,
            accepted.intent_id,
            funding.copy(update={"ark_txid": "66" * 32}),
            conn=connection,
        )
    with pytest.raises(arkade.ArkadeOutgoingError, match="INVALID_TRANSITION"):
        await arkade.release_arkade_outgoing_payment(
            ACCOUNT_ID, accepted.intent_id, conn=connection
        )


@pytest.mark.anyio
async def test_lightning_terminal_intent_and_payment_cas_are_atomic_and_isolated(
    connection, monkeypatch
):
    monkeypatch.setattr(
        settings, "lnbits_effective_installation_mode", "arkade_noncustodial"
    )
    monkeypatch.setattr(arkade, "fetch_arkade_indexer_vtxos", _lightning_backing)

    def decode_invoice(bolt11):
        invoice = _LightningInvoice()
        if bolt11 == "lnbc-lightning-refund":
            invoice.payment_hash = "ef" * 32
        return invoice

    monkeypatch.setattr(arkade.bolt11, "decode", decode_invoice)
    await _credit(connection, WALLET_ID, 10_000_000)

    quote = _lightning_quote()
    intent, _payment = await arkade.reserve_arkade_lightning_intent(
        ACCOUNT_ID,
        WALLET_ID,
        quote,
        connection,
        idempotency_key="05" * 16,
    )
    await _credit(connection, SECOND_WALLET_ID, 7_000_000)
    async with connection.transaction():
        assert await submit_arkade_lightning_intent(
            intent.intent_id,
            "55" * 32,
            lockup_address=quote.lockup_address,
            swap_rfq_id=quote.swap_rfq_id,
            solver_pubkey=quote.solver_pubkey,
            sender_pubkey=IDENTITY_XONLY,
            refund_pk_script="5120" + IDENTITY_XONLY,
            conn=connection,
        )
        await connection.execute(
            "INSERT INTO arkade_outgoing_intent_inputs "
            "(intent_id, txid, vout, amount_sat) "
            "VALUES (:intent_id, :txid, 0, :amount_sat)",
            {
                "intent_id": intent.intent_id,
                "txid": "55" * 32,
                "amount_sat": intent.quote_from_amount_sat,
            },
        )

    with pytest.raises(ValueError, match="BINDING_MISMATCH"):
        async with connection.transaction():
            await settle_arkade_lightning_intent(
                intent.intent_id,
                "66" * 32,
                account_id="aa" * 16,
                wallet_id=WALLET_ID,
                conn=connection,
            )
    with pytest.raises(ValueError, match="BINDING_MISMATCH"):
        async with connection.transaction():
            await settle_arkade_lightning_payment(
                intent.intent_id,
                account_id=ACCOUNT_ID,
                wallet_id=SECOND_WALLET_ID,
                amount_msat=intent.amount_msat,
                arkade_address=quote.bolt11,
                conn=connection,
            )

    with pytest.raises(ValueError, match="BINDING_MISMATCH"):
        async with connection.transaction():
            assert await settle_arkade_lightning_intent(
                intent.intent_id,
                "66" * 32,
                account_id=ACCOUNT_ID,
                wallet_id=WALLET_ID,
                conn=connection,
            )
            await settle_arkade_lightning_payment(
                intent.intent_id,
                account_id=ACCOUNT_ID,
                wallet_id=WALLET_ID,
                amount_msat=intent.amount_msat,
                arkade_address="wrong-destination",
                conn=connection,
            )
    rolled_back = await get_arkade_outgoing_intent(intent.intent_id, conn=connection)
    rolled_back_payment = await get_payment_by_native_id(
        intent.intent_id, conn=connection
    )
    assert rolled_back and rolled_back.status == "submitted"
    assert rolled_back.arkade_txid == "55" * 32
    assert rolled_back.settlement_ark_txid is None
    assert rolled_back_payment and rolled_back_payment.status == PaymentState.PENDING

    async with connection.transaction():
        await connection.execute(
            "UPDATE arkade_outgoing_intents SET max_fee_msat = 500 "
            "WHERE intent_id = :intent_id",
            {"intent_id": intent.intent_id},
        )
    with pytest.raises(ValueError, match="FEE_EXCEEDED"):
        async with connection.transaction():
            await settle_arkade_lightning_intent(
                intent.intent_id,
                "66" * 32,
                account_id=ACCOUNT_ID,
                wallet_id=WALLET_ID,
                conn=connection,
            )
    async with connection.transaction():
        await connection.execute(
            "UPDATE arkade_outgoing_intents SET max_fee_msat = 15000 "
            "WHERE intent_id = :intent_id",
            {"intent_id": intent.intent_id},
        )

    async with connection.transaction():
        assert await settle_arkade_lightning_intent(
            intent.intent_id,
            "66" * 32,
            account_id=ACCOUNT_ID,
            wallet_id=WALLET_ID,
            conn=connection,
        )
        assert await settle_arkade_lightning_payment(
            intent.intent_id,
            account_id=ACCOUNT_ID,
            wallet_id=WALLET_ID,
            amount_msat=intent.amount_msat,
            arkade_address=quote.bolt11,
            conn=connection,
        )
    settled = await get_arkade_outgoing_intent(intent.intent_id, conn=connection)
    settled_payment = await get_payment_by_native_id(intent.intent_id, conn=connection)
    assert settled and settled.status == "settled"
    assert settled.arkade_txid == "55" * 32
    assert settled.settlement_ark_txid == "66" * 32
    assert settled.refund_ark_txid is None
    assert settled.actual_fee_msat == 1_000
    assert settled_payment and settled_payment.status == PaymentState.SUCCESS
    assert settled_payment.fee == -1_000
    receipt_facts = await get_arkade_outgoing_intent_inputs(
        intent.intent_id, conn=connection
    )
    assert [(item.txid, item.vout, item.amount_sat) for item in receipt_facts] == [
        ("55" * 32, 0, intent.quote_from_amount_sat)
    ]
    balance = await connection.fetchone(
        "SELECT balance FROM balances WHERE wallet_id = :wallet_id",
        {"wallet_id": WALLET_ID},
    )
    other_balance = await connection.fetchone(
        "SELECT balance FROM balances WHERE wallet_id = :wallet_id",
        {"wallet_id": SECOND_WALLET_ID},
    )
    assert balance["balance"] == 4_999_000
    assert other_balance["balance"] == 7_000_000

    async with connection.transaction():
        assert not await settle_arkade_lightning_intent(
            intent.intent_id,
            "66" * 32,
            account_id=ACCOUNT_ID,
            wallet_id=WALLET_ID,
            conn=connection,
        )
        assert not await settle_arkade_lightning_payment(
            intent.intent_id,
            account_id=ACCOUNT_ID,
            wallet_id=WALLET_ID,
            amount_msat=intent.amount_msat,
            arkade_address=quote.bolt11,
            conn=connection,
        )

    await _credit(connection, WALLET_ID, 20_000)
    refund_quote = _lightning_quote(
        bolt11="lnbc-lightning-refund",
        payment_hash="ef" * 32,
        lockup_address="refund-lockup",
        swap_rfq_id="rfq-refund",
    )
    refund_intent, _ = await arkade.reserve_arkade_lightning_intent(
        ACCOUNT_ID,
        WALLET_ID,
        refund_quote,
        connection,
        idempotency_key="07" * 16,
    )
    async with connection.transaction():
        assert await submit_arkade_lightning_intent(
            refund_intent.intent_id,
            "77" * 32,
            lockup_address=refund_quote.lockup_address,
            swap_rfq_id=refund_quote.swap_rfq_id,
            solver_pubkey=refund_quote.solver_pubkey,
            sender_pubkey=IDENTITY_XONLY,
            refund_pk_script="5120" + IDENTITY_XONLY,
            conn=connection,
        )
    async with connection.transaction():
        assert await refund_arkade_lightning_intent(
            refund_intent.intent_id,
            "88" * 32,
            account_id=ACCOUNT_ID,
            wallet_id=WALLET_ID,
            conn=connection,
        )
        assert await refund_arkade_lightning_payment(
            refund_intent.intent_id,
            account_id=ACCOUNT_ID,
            wallet_id=WALLET_ID,
            amount_msat=refund_intent.amount_msat,
            arkade_address=refund_quote.bolt11,
            conn=connection,
        )
    refunded = await get_arkade_outgoing_intent(
        refund_intent.intent_id, conn=connection
    )
    refunded_payment = await get_payment_by_native_id(
        refund_intent.intent_id, conn=connection
    )
    assert refunded and refunded.status == "refunded"
    assert refunded.arkade_txid == "77" * 32
    assert refunded.refund_ark_txid == "88" * 32
    assert refunded.settlement_ark_txid is None
    assert refunded.actual_fee_msat == 0
    assert refunded_payment and refunded_payment.status == PaymentState.FAILED
    assert refunded_payment.fee == 0
    with pytest.raises(ValueError, match="INVALID_TRANSITION|CONFLICT"):
        async with connection.transaction():
            await settle_arkade_lightning_intent(
                refund_intent.intent_id,
                "99" * 32,
                account_id=ACCOUNT_ID,
                wallet_id=WALLET_ID,
                conn=connection,
            )
    async with connection.transaction():
        assert not await refund_arkade_lightning_intent(
            refund_intent.intent_id,
            "88" * 32,
            account_id=ACCOUNT_ID,
            wallet_id=WALLET_ID,
            conn=connection,
        )
        assert not await refund_arkade_lightning_payment(
            refund_intent.intent_id,
            account_id=ACCOUNT_ID,
            wallet_id=WALLET_ID,
            amount_msat=refund_intent.amount_msat,
            arkade_address=refund_quote.bolt11,
            conn=connection,
        )


@pytest.mark.anyio
async def test_lightning_submit_requires_public_funding_observation(
    connection, monkeypatch
):
    monkeypatch.setattr(
        settings, "lnbits_effective_installation_mode", "arkade_noncustodial"
    )
    monkeypatch.setattr(arkade, "fetch_arkade_indexer_vtxos", _lightning_backing)
    monkeypatch.setattr(arkade.bolt11, "decode", lambda _bolt11: _LightningInvoice())
    await _credit(connection, WALLET_ID, 10_000_000)
    quote = _lightning_quote()
    accepted, _ = await arkade.reserve_arkade_lightning_intent(
        ACCOUNT_ID,
        WALLET_ID,
        quote,
        connection,
        idempotency_key="06" * 16,
    )

    async def no_lockup_observation(_account_id, **kwargs):
        assert kwargs["spendable_only"] is False
        return []

    monkeypatch.setattr(arkade, "fetch_arkade_indexer_vtxos", no_lockup_observation)
    funding = ArkadeLightningFundingEvidence(
        ark_txid="55" * 32,
        lockup_address=quote.lockup_address,
        swap_rfq_id=quote.swap_rfq_id,
        solver_pubkey=quote.solver_pubkey,
        sender_pubkey=IDENTITY_XONLY,
        refund_pk_script="5120" + IDENTITY_XONLY,
    )
    with pytest.raises(
        arkade.ArkadeOutgoingError,
        match="^ARKADE_OUTGOING_INDEXER_UNAVAILABLE$",
    ):
        await arkade.submit_arkade_lightning_intent(
            ACCOUNT_ID, accepted.intent_id, funding, conn=connection
        )
    current = await get_arkade_outgoing_intent(accepted.intent_id, conn=connection)
    assert current and current.status == "quote_ready"
    assert current.arkade_txid is None


def _connection_db_proxy(connection):
    class _Proxy:
        @asynccontextmanager
        async def connect(self):
            yield connection

        @asynccontextmanager
        async def reuse_conn(self, conn):
            yield conn

    return _Proxy()


async def _submitted_lightning_intent(connection, monkeypatch, idempotency_key):
    payment_hash = idempotency_key * 2
    funding_txid = idempotency_key * 2

    async def funding_backing(_account_id, **kwargs):
        if kwargs.get("scripts"):
            return [
                arkade.ArkadeIndexerVtxo(
                    txid=funding_txid,
                    vout=0,
                    amount_sat=5_001,
                    script=CHANGE_SCRIPT,
                    arkade_txid=funding_txid,
                )
            ]
        return await _lightning_backing(_account_id, **kwargs)

    monkeypatch.setattr(arkade, "fetch_arkade_indexer_vtxos", funding_backing)
    monkeypatch.setattr(
        arkade, "decode_arkade_address_script", lambda *args: CHANGE_SCRIPT
    )

    def decode_invoice(_bolt11):
        invoice = _LightningInvoice()
        invoice.payment_hash = payment_hash
        return invoice

    monkeypatch.setattr(arkade.bolt11, "decode", decode_invoice)
    await _credit(connection, WALLET_ID, 6_000_000)
    quote = _lightning_quote(
        payment_hash=payment_hash,
        lockup_address=f"lockup-{idempotency_key}",
        swap_rfq_id=f"rfq-{idempotency_key}",
    )
    intent, _ = await arkade.reserve_arkade_lightning_intent(
        ACCOUNT_ID,
        WALLET_ID,
        quote,
        connection,
        idempotency_key=idempotency_key,
    )
    funding = ArkadeLightningFundingEvidence(
        ark_txid=funding_txid,
        lockup_address=quote.lockup_address,
        swap_rfq_id=quote.swap_rfq_id,
        solver_pubkey=quote.solver_pubkey,
        sender_pubkey=IDENTITY_XONLY,
        refund_pk_script="5120" + IDENTITY_XONLY,
    )
    await arkade.submit_arkade_lightning_intent(
        ACCOUNT_ID, intent.intent_id, funding, conn=connection
    )
    return intent


def _patch_lightning_reconcile_io(connection, monkeypatch, verdict):
    original_intent = arkade.get_arkade_outgoing_intent
    original_inputs = arkade.get_arkade_outgoing_intent_inputs
    original_payment = arkade.get_payment_by_native_id
    original_binding = arkade.get_arkade_binding

    async def get_intent(intent_id, conn=None):
        return await original_intent(intent_id, conn=conn or connection)

    async def get_payment(native_id, conn=None):
        return await original_payment(native_id, conn=conn or connection)

    async def get_inputs(intent_id, conn=None):
        return await original_inputs(intent_id, conn=conn or connection)

    async def get_binding(account_id, conn=None):
        return await original_binding(account_id, conn=conn or connection)

    monkeypatch.setattr(arkade, "db", _connection_db_proxy(connection))
    monkeypatch.setattr(arkade, "get_arkade_outgoing_intent", get_intent)
    monkeypatch.setattr(arkade, "get_arkade_outgoing_intent_inputs", get_inputs)
    monkeypatch.setattr(arkade, "get_payment_by_native_id", get_payment)
    monkeypatch.setattr(arkade, "get_arkade_binding", get_binding)
    monkeypatch.setattr(
        arkade, "fetch_arkade_operator_pubkey", AsyncMock(return_value="44" * 32)
    )
    monkeypatch.setattr(
        arkade, "decode_arkade_address_script", lambda *args: CHANGE_SCRIPT
    )
    monkeypatch.setattr(arkade, "fetch_arkade_indexer_vtxos", _lightning_backing)
    monkeypatch.setattr(
        arkade,
        "fetch_arkade_indexer_virtual_tx",
        AsyncMock(return_value=None),
    )
    from lnbits.core.services import arkade_evidence

    monkeypatch.setattr(
        arkade_evidence,
        "verify_arkade_lightning_terminal_evidence",
        lambda *args, **kwargs: verdict,
    )


@pytest.mark.anyio
async def test_lightning_reconcile_claim_is_atomic_and_idempotent(
    connection, monkeypatch
):
    monkeypatch.setattr(
        settings, "lnbits_effective_installation_mode", "arkade_noncustodial"
    )
    intent = await _submitted_lightning_intent(connection, monkeypatch, "10" * 16)
    _patch_lightning_reconcile_io(
        connection,
        monkeypatch,
        ArkadeLightningEvidenceVerdict(
            ArkadeLightningEvidenceStatus.CLAIMED, ark_txid="66" * 32
        ),
    )

    verdict = await arkade.reconcile_arkade_lightning_intent(
        intent.intent_id, ACCOUNT_ID
    )
    assert verdict and verdict.status == ArkadeLightningEvidenceStatus.CLAIMED
    settled = await get_arkade_outgoing_intent(intent.intent_id, conn=connection)
    payment = await get_payment_by_native_id(intent.intent_id, conn=connection)
    assert settled and settled.status == "settled"
    assert payment and payment.status == PaymentState.SUCCESS
    receipt_facts = await get_arkade_outgoing_intent_inputs(
        intent.intent_id, conn=connection
    )
    assert len(receipt_facts) == 1
    assert receipt_facts[0].amount_sat == intent.quote_from_amount_sat
    reconciliation = await connection.fetchone(
        "SELECT state FROM arkade_reconciliation_state WHERE account_id = :account_id",
        {"account_id": ACCOUNT_ID},
    )
    assert reconciliation is None
    assert (
        await connection.fetchone(
            "SELECT COUNT(*) AS count FROM arkade_lightning_terminal_events"
        )
    )["count"] == 1

    assert (
        await arkade.reconcile_arkade_lightning_intent(intent.intent_id, ACCOUNT_ID)
        is None
    )
    assert (
        await connection.fetchone(
            "SELECT COUNT(*) AS count FROM arkade_lightning_terminal_events"
        )
    )["count"] == 1


@pytest.mark.anyio
async def test_lightning_reconcile_refund_and_contradiction(connection, monkeypatch):
    monkeypatch.setattr(
        settings, "lnbits_effective_installation_mode", "arkade_noncustodial"
    )
    intent = await _submitted_lightning_intent(connection, monkeypatch, "11" * 16)
    _patch_lightning_reconcile_io(
        connection,
        monkeypatch,
        ArkadeLightningEvidenceVerdict(
            ArkadeLightningEvidenceStatus.REFUNDED, ark_txid="77" * 32
        ),
    )
    await arkade.reconcile_arkade_lightning_intent(intent.intent_id, ACCOUNT_ID)
    refunded = await get_arkade_outgoing_intent(intent.intent_id, conn=connection)
    payment = await get_payment_by_native_id(intent.intent_id, conn=connection)
    assert refunded and refunded.status == "refunded"
    assert payment and payment.status == PaymentState.FAILED and payment.fee == 0

    intent = await _submitted_lightning_intent(connection, monkeypatch, "12" * 16)
    _patch_lightning_reconcile_io(
        connection,
        monkeypatch,
        ArkadeLightningEvidenceVerdict(
            ArkadeLightningEvidenceStatus.CONTRADICTORY,
            reason="conflicting public spend",
        ),
    )
    await arkade.reconcile_arkade_lightning_intent(intent.intent_id, ACCOUNT_ID)
    disputed = await get_arkade_outgoing_intent(intent.intent_id, conn=connection)
    payment = await get_payment_by_native_id(intent.intent_id, conn=connection)
    state = await connection.fetchone(
        "SELECT state FROM arkade_reconciliation_state WHERE account_id = :account_id",
        {"account_id": ACCOUNT_ID},
    )
    assert disputed and disputed.status == "disputed"
    assert payment and payment.status == PaymentState.PENDING
    assert state is None


@pytest.mark.anyio
async def test_lightning_reconcile_retries_public_failure_without_double_apply(
    connection, monkeypatch
):
    monkeypatch.setattr(
        settings, "lnbits_effective_installation_mode", "arkade_noncustodial"
    )
    intent = await _submitted_lightning_intent(connection, monkeypatch, "13" * 16)
    verdict = ArkadeLightningEvidenceVerdict(
        ArkadeLightningEvidenceStatus.CLAIMED, ark_txid="99" * 32
    )
    _patch_lightning_reconcile_io(connection, monkeypatch, verdict)
    failure = AsyncMock(side_effect=arkade.ArkadeReceiveError("temporary"))
    monkeypatch.setattr(arkade, "fetch_arkade_indexer_vtxos", failure)
    with pytest.raises(arkade.ArkadeReceiveError):
        await arkade.reconcile_arkade_lightning_intent(intent.intent_id, ACCOUNT_ID)
    pending = await get_arkade_outgoing_intent(intent.intent_id, conn=connection)
    assert pending and pending.status == "submitted"
    assert (
        await connection.fetchone(
            "SELECT COUNT(*) AS count FROM arkade_lightning_terminal_events"
        )
    )["count"] == 0

    monkeypatch.setattr(arkade, "fetch_arkade_indexer_vtxos", _lightning_backing)
    await arkade.reconcile_arkade_lightning_intent(intent.intent_id, ACCOUNT_ID)
    assert (
        await connection.fetchone(
            "SELECT COUNT(*) AS count FROM arkade_lightning_terminal_events"
        )
    )["count"] == 1


@pytest.mark.anyio
async def test_lightning_reconcile_rejects_cross_account_without_transition(
    connection, monkeypatch
):
    monkeypatch.setattr(
        settings, "lnbits_effective_installation_mode", "arkade_noncustodial"
    )
    intent = await _submitted_lightning_intent(connection, monkeypatch, "14" * 16)
    _patch_lightning_reconcile_io(
        connection,
        monkeypatch,
        ArkadeLightningEvidenceVerdict(ArkadeLightningEvidenceStatus.PENDING),
    )
    assert (
        await arkade.reconcile_arkade_lightning_intent(intent.intent_id, "aa" * 16)
        is None
    )
    current = await get_arkade_outgoing_intent(intent.intent_id, conn=connection)
    assert current and current.status == "submitted"
