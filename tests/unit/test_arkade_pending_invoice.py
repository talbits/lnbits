from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from typing import cast

import pytest
from lnurl import LnurlWithdrawResponse
from sqlalchemy.ext.asyncio import AsyncConnection, create_async_engine

import lnbits.db as db_module
from lnbits.core import migrations
from lnbits.core.crud.payments import compare_and_set_arkade_payment_failed
from lnbits.core.models import (
    ArkadeIndexerVtxo,
    ArkadeReceiveAcknowledgement,
    CreateInvoice,
    PaymentState,
    Wallet,
)
from lnbits.core.services import arkade, payments
from lnbits.db import SQLITE, Connection
from lnbits.settings import settings
from lnbits.task_manager import task_manager

ACCOUNT_ID = "00" * 16
WALLET_ID = "11" * 16
SECOND_WALLET_ID = "22" * 16


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
            "deleted BOOLEAN NOT NULL DEFAULT false, created_at INTEGER, "
            "updated_at INTEGER, wallet_type TEXT DEFAULT 'lightning', "
            "shared_wallet_id TEXT, currency TEXT, lightning_address TEXT, "
            "extra TEXT, stored_paylinks TEXT)"
        )
        await connection.execute(
            "INSERT INTO accounts (id) VALUES (:id)", {"id": ACCOUNT_ID}
        )
        for wallet_id in (WALLET_ID, SECOND_WALLET_ID):
            await connection.execute(
                'INSERT INTO wallets (id, "user", name, adminkey, inkey) '
                "VALUES (:id, :user, 'test', 'a', 'b')",
                {"id": wallet_id, "user": ACCOUNT_ID},
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
        await migrations.m052_create_arkade_account_bindings_table(connection)
        await migrations.m053_create_arkade_receive_tables(connection)
        now = datetime.now(timezone.utc)
        await connection.execute(
            "INSERT INTO arkade_account_bindings "
            "(account_id, state, enrollment_id, network, server_url, server_pubkey, "
            "identity_xonly_pubkey, backup_acknowledged_at, ready_at) VALUES "
            "(:account_id, 'ready', :enrollment_id, 'regtest', 'http://arkade', "
            ":server, :identity, :ack, :ready)",
            {
                "account_id": ACCOUNT_ID,
                "enrollment_id": "33" * 16,
                "server": "44" * 32,
                "identity": "55" * 32,
                "ack": now,
                "ready": now,
            },
        )
        await migrations.m054_add_payment_protocol_identity(connection)
        yield connection
    await engine.dispose()


@pytest.fixture
def ready_mode(monkeypatch):
    monkeypatch.setattr(
        settings, "lnbits_effective_installation_mode", "arkade_noncustodial"
    )
    wallets = {
        wallet_id: Wallet(
            id=wallet_id,
            user=ACCOUNT_ID,
            name="test",
            adminkey="a",
            inkey="b",
            lightning_address="test-address",
        )
        for wallet_id in (WALLET_ID, SECOND_WALLET_ID)
    }

    async def get_test_wallet(wallet_id, conn=None):
        return wallets.get(wallet_id)

    monkeypatch.setattr(arkade, "get_wallet", get_test_wallet)
    monkeypatch.setattr(payments, "get_wallet", get_test_wallet)


async def _count(connection, table: str) -> int:
    queries = {
        "apipayments": "SELECT COUNT(*) AS count FROM apipayments",
        "arkade_receive_requests": (
            "SELECT COUNT(*) AS count FROM arkade_receive_requests"
        ),
    }
    row = await connection.fetchone(queries[table])
    return int(row["count"])


@pytest.mark.anyio
async def test_create_payment_request_routes_arkade_and_preserves_fields(
    ready_mode, mocker
):
    payment = object()
    helper = mocker.patch.object(
        payments,
        "create_arkade_pending_invoice",
        return_value=payment,
    )
    data = CreateInvoice(
        out=False,
        amount=42,
        expiry=600,
        extra={"tag": "route"},
        extension="ext",
        webhook="https://example.com/webhook",
        labels=["label"],
        external_id="external",
    )

    assert await payments.create_payment_request(WALLET_ID, data) is payment
    helper.assert_awaited_once_with(
        wallet_id=WALLET_ID,
        amount=42,
        memo=settings.lnbits_site_title,
        currency="sat",
        expiry=600,
        extra={"tag": "route"},
        extension="ext",
        webhook="https://example.com/webhook",
        labels=["label"],
        external_id="external",
    )


@pytest.mark.anyio
async def test_create_payment_request_rejects_lightning_options_before_arkade_rows(
    ready_mode, mocker
):
    helper = mocker.patch.object(payments, "create_arkade_pending_invoice")
    data = CreateInvoice(
        out=False,
        amount=42,
        internal=True,
        payment_hash="11" * 32,
        description_hash="22" * 32,
        unhashed_description="33",
        bolt11="lightning-invoice",
        lnurl_withdraw=LnurlWithdrawResponse.parse_obj(
            {
                "tag": "withdrawRequest",
                "callback": "https://example.com/callback",
                "k1": "randomk1value",
                "minWithdrawable": 1000,
                "maxWithdrawable": 1_500_000,
            }
        ),
        fiat_provider="stripe",
    )

    with pytest.raises(ValueError, match="ARKADE_INVOICE_UNSUPPORTED"):
        await payments.create_payment_request(WALLET_ID, data)
    helper.assert_not_awaited()


@pytest.mark.anyio
async def test_arkade_pending_invoice_pair_and_units(connection, ready_mode):
    payment = await payments.create_arkade_pending_invoice(
        wallet_id=WALLET_ID,
        amount=42,
        memo="arkade receive",
        extra={"tag": "test"},
        extension="ext",
        webhook="https://example.com/webhook",
        labels=["label"],
        external_id="external",
        expiry=600,
        idempotency_key="66" * 16,
        conn=connection,
    )
    request = await arkade.get_arkade_receive_request_by_idempotency(
        ACCOUNT_ID, "66" * 16, conn=connection
    )

    assert request is not None
    assert payment.protocol == "arkade"
    assert payment.status == "pending"
    assert payment.amount == 42_000
    assert payment.checking_id is None
    assert payment.payment_hash is None
    assert payment.bolt11 is None
    assert payment.arkade_address is None
    assert payment.native_id == request.native_request_id
    assert payment.native_id is not None
    assert payment.wallet_id == request.wallet_id == WALLET_ID
    assert payment.memo == "arkade receive"
    assert payment.extra["tag"] == "test"
    assert payment.expiry is not None
    assert request.expires_at.timestamp() == payment.expiry.timestamp()
    stored_payment = await payments.get_payment_by_native_id(
        payment.native_id, conn=connection
    )
    assert stored_payment is not None
    assert stored_payment.memo == "arkade receive"
    assert stored_payment.extension == "ext"
    assert stored_payment.webhook == "https://example.com/webhook"
    assert stored_payment.labels == ["label"]
    assert stored_payment.external_id == "external"
    assert stored_payment.extra == {"tag": "test"}
    assert await _count(connection, "apipayments") == 1
    assert await _count(connection, "arkade_receive_requests") == 1


@pytest.mark.anyio
async def test_arkade_pending_invoice_replay_and_conflicts(connection, ready_mode):
    key = "77" * 16
    first = await payments.create_arkade_pending_invoice(
        wallet_id=WALLET_ID,
        amount=10,
        memo="first",
        idempotency_key=key,
        conn=connection,
    )
    replay = await payments.create_arkade_pending_invoice(
        wallet_id=WALLET_ID,
        amount=10,
        memo="replay",
        idempotency_key=key,
        conn=connection,
    )
    assert replay.native_id == first.native_id
    assert await _count(connection, "apipayments") == 1
    assert await _count(connection, "arkade_receive_requests") == 1

    with pytest.raises(arkade.ArkadeReceiveError, match="IDEMPOTENCY_CONFLICT"):
        await payments.create_arkade_pending_invoice(
            wallet_id=WALLET_ID,
            amount=11,
            memo="amount conflict",
            idempotency_key=key,
            conn=connection,
        )

    with pytest.raises(arkade.ArkadeReceiveError, match="IDEMPOTENCY_CONFLICT"):
        await payments.create_arkade_pending_invoice(
            wallet_id=SECOND_WALLET_ID,
            amount=10,
            memo="wallet conflict",
            idempotency_key=key,
            conn=connection,
        )


def _acknowledgement(request, amount_sat: int | None = None):
    return ArkadeReceiveAcknowledgement(
        native_request_id=request.native_request_id,
        account_id=ACCOUNT_ID,
        wallet_id=request.wallet_id,
        idempotency_key=request.idempotency_key,
        amount_sat=amount_sat or request.amount_sat,
        index=7,
        address="tark-address",
        script="5120" + "aa" * 32,
        child_xonly_pubkey="55" * 32,
        network=request.network,
        server_url=request.server_url,
        server_pubkey=request.server_pubkey,
        expires_at=int(request.expires_at.timestamp()),
        signature="66" * 64,
        exit_tapleaf="00" * 38,
        exit_control_block="00" * 65,
    )


@pytest.mark.anyio
async def test_acknowledgement_updates_payment_and_duplicate_is_idempotent(
    connection, ready_mode, mocker
):
    payment = await payments.create_arkade_pending_invoice(
        wallet_id=WALLET_ID,
        amount=42,
        memo="ack",
        idempotency_key="99" * 16,
        conn=connection,
    )
    assert payment.native_id is not None
    request = await arkade.get_arkade_receive_request_by_idempotency(
        ACCOUNT_ID, "99" * 16, conn=connection
    )
    assert request is not None
    mocker.patch.object(arkade, "validate_arkade_address_script")
    mocker.patch.object(arkade, "verify_receive_proof")
    mocker.patch.object(arkade, "verify_receive_exit_membership")

    acknowledgement = _acknowledgement(request)
    result = await arkade.acknowledge_arkade_receive(
        ACCOUNT_ID, acknowledgement, conn=connection
    )
    stored = await payments.get_payment_by_native_id(payment.native_id, conn=connection)
    assert result.state == "acknowledged"
    assert stored is not None
    assert stored.arkade_address == "tark-address"

    duplicate = await arkade.acknowledge_arkade_receive(
        ACCOUNT_ID, acknowledgement, conn=connection
    )
    assert duplicate == result
    stored = await payments.get_payment_by_native_id(payment.native_id, conn=connection)
    assert stored is not None
    assert stored.arkade_address == "tark-address"


@pytest.mark.anyio
async def test_acknowledgement_mismatch_rolls_back_request_update(
    connection, ready_mode, mocker
):
    payment = await payments.create_arkade_pending_invoice(
        wallet_id=WALLET_ID,
        amount=42,
        memo="mismatch",
        idempotency_key="aa" * 16,
        conn=connection,
    )
    assert payment.native_id is not None
    request = await arkade.get_arkade_receive_request_by_idempotency(
        ACCOUNT_ID, "aa" * 16, conn=connection
    )
    assert request is not None
    mocker.patch.object(arkade, "validate_arkade_address_script")
    mocker.patch.object(arkade, "verify_receive_proof")
    mocker.patch.object(arkade, "verify_receive_exit_membership")

    await connection.execute(
        "UPDATE apipayments SET amount = :amount WHERE native_id = :native_id",
        {"amount": 41_000, "native_id": payment.native_id},
    )
    with pytest.raises(arkade.ArkadeReceiveError, match="MAPPING_CONFLICT"):
        await arkade.acknowledge_arkade_receive(
            ACCOUNT_ID, _acknowledgement(request), conn=connection
        )
    stored_request = await arkade.get_arkade_receive_request(
        request.native_request_id, conn=connection
    )
    assert stored_request is not None
    assert stored_request.state == "pending"
    stored_payment = await payments.get_payment_by_native_id(
        payment.native_id, conn=connection
    )
    assert stored_payment is not None
    assert stored_payment.arkade_address is None


@pytest.mark.anyio
async def test_acknowledgement_payment_failure_rolls_back_request_update(
    connection, ready_mode, mocker
):
    payment = await payments.create_arkade_pending_invoice(
        wallet_id=WALLET_ID,
        amount=42,
        memo="failure",
        idempotency_key="bb" * 16,
        conn=connection,
    )
    assert payment.native_id is not None
    request = await arkade.get_arkade_receive_request_by_idempotency(
        ACCOUNT_ID, "bb" * 16, conn=connection
    )
    assert request is not None
    mocker.patch.object(arkade, "validate_arkade_address_script")
    mocker.patch.object(arkade, "verify_receive_proof")
    mocker.patch.object(arkade, "verify_receive_exit_membership")
    mocker.patch.object(
        arkade, "update_payment", side_effect=RuntimeError("injected payment failure")
    )

    with pytest.raises(RuntimeError, match="injected payment failure"):
        await arkade.acknowledge_arkade_receive(
            ACCOUNT_ID, _acknowledgement(request), conn=connection
        )
    stored_request = await arkade.get_arkade_receive_request(
        request.native_request_id, conn=connection
    )
    assert stored_request is not None
    assert stored_request.state == "pending"
    stored_payment = await payments.get_payment_by_native_id(
        payment.native_id, conn=connection
    )
    assert stored_payment is not None
    assert stored_payment.arkade_address is None


@pytest.mark.anyio
async def test_arkade_pending_invoice_rolls_back_pair(
    connection, ready_mode, monkeypatch
):
    async def fail_create_payment(*args, **kwargs):
        raise RuntimeError("injected payment failure")

    monkeypatch.setattr(payments, "create_payment", fail_create_payment)
    with pytest.raises(RuntimeError, match="injected payment failure"):
        await payments.create_arkade_pending_invoice(
            wallet_id=WALLET_ID,
            amount=21,
            memo="rollback",
            idempotency_key="88" * 16,
            conn=connection,
        )

    assert await _count(connection, "apipayments") == 0
    assert await _count(connection, "arkade_receive_requests") == 0


@pytest.mark.anyio
async def test_nested_transaction_preserves_outer_rollback(connection):
    await connection.execute(
        "CREATE TABLE transaction_probe (id INTEGER PRIMARY KEY, value TEXT)"
    )

    with pytest.raises(ValueError, match="force outer rollback"):
        async with connection.transaction():
            await connection.execute(
                "INSERT INTO transaction_probe (id, value) VALUES (1, 'outer')"
            )
            with pytest.raises(RuntimeError, match="Nested transactions"):
                async with connection.transaction():
                    pass
            raise ValueError("force outer rollback")

    row = await connection.fetchone("SELECT COUNT(*) AS count FROM transaction_probe")
    assert row["count"] == 0


async def _prepare_reconciliation_payment(connection, ready_mode, status="pending"):
    payment = await payments.create_arkade_pending_invoice(
        wallet_id=WALLET_ID,
        amount=42,
        memo="reconcile",
        idempotency_key="ab" * 16,
        conn=connection,
    )
    assert payment.native_id is not None
    request = await arkade.get_arkade_receive_request(
        payment.native_id, conn=connection
    )
    assert request is not None
    script = "5120" + "aa" * 32
    await connection.execute(
        'UPDATE arkade_receive_requests SET "index" = 7, address = :address, '
        "script = :script, child_xonly_pubkey = :child, state = 'acknowledged' "
        "WHERE native_request_id = :native_id",
        {
            "address": "tark-address",
            "script": script,
            "child": "55" * 32,
            "native_id": payment.native_id,
        },
    )
    await connection.execute(
        "UPDATE apipayments SET arkade_address = :address, status = :status "
        "WHERE native_id = :native_id",
        {
            "address": "tark-address",
            "status": status,
            "native_id": payment.native_id,
        },
    )
    evidence = ArkadeIndexerVtxo(
        txid="cc" * 32,
        vout=0,
        amount_sat=42,
        script=script,
    )
    return payment.native_id, evidence


@pytest.mark.anyio
async def test_reconcile_settles_exact_payment_once(connection, ready_mode):
    native_id, evidence = await _prepare_reconciliation_payment(connection, ready_mode)

    async with connection.transaction():
        first = await arkade.reconcile_arkade_receive(
            ACCOUNT_ID, [evidence], conn=connection
        )
    async with connection.transaction():
        replay = await arkade.reconcile_arkade_receive(
            ACCOUNT_ID, [evidence], conn=connection
        )

    payment = await payments.get_payment_by_native_id(native_id, conn=connection)
    request = await arkade.get_arkade_receive_request(native_id, conn=connection)
    assert payment is not None
    assert request is not None
    assert payment.amount == 42_000
    assert payment.status == PaymentState.SUCCESS.value
    assert request.state == "settled"
    assert len(first) == 1
    assert replay == []
    balance = await connection.fetchone(
        "SELECT balance FROM balances WHERE wallet_id = :wallet_id",
        {"wallet_id": WALLET_ID},
    )
    assert balance is not None
    assert balance["balance"] == 42_000


@pytest.mark.anyio
async def test_reconcile_late_failed_payment_succeeds(connection, ready_mode):
    native_id, evidence = await _prepare_reconciliation_payment(
        connection, ready_mode, status=PaymentState.FAILED.value
    )

    async with connection.transaction():
        settled = await arkade.reconcile_arkade_receive(
            ACCOUNT_ID, [evidence], conn=connection
        )

    payment = await payments.get_payment_by_native_id(native_id, conn=connection)
    assert payment is not None
    assert payment.status == PaymentState.SUCCESS.value
    assert len(settled) == 1


@pytest.mark.anyio
async def test_reconcile_mapping_conflict_is_sticky_without_settlement(
    connection, ready_mode
):
    native_id, evidence = await _prepare_reconciliation_payment(connection, ready_mode)
    await connection.execute(
        "UPDATE apipayments SET wallet_id = :wallet_id WHERE native_id = :native_id",
        {"wallet_id": SECOND_WALLET_ID, "native_id": native_id},
    )

    async with connection.transaction():
        settled = await arkade.reconcile_arkade_receive(
            ACCOUNT_ID, [evidence], conn=connection
        )

    payment = await payments.get_payment_by_native_id(native_id, conn=connection)
    request = await arkade.get_arkade_receive_request(native_id, conn=connection)
    reconciliation = await arkade.get_arkade_reconciliation(ACCOUNT_ID, conn=connection)
    assert settled == []
    assert payment is not None
    assert request is not None
    assert reconciliation is not None
    assert payment.status == PaymentState.PENDING.value
    assert request.state == "reconciliation_required"
    assert reconciliation.state == "reconciliation_required"


@pytest.mark.anyio
async def test_arkade_pending_check_queues_only_new_settlements(
    connection, ready_mode, mocker
):
    payment = await payments.create_arkade_pending_invoice(
        wallet_id=WALLET_ID,
        amount=42,
        memo="queue",
        idempotency_key="ac" * 16,
        conn=connection,
    )
    payment.status = PaymentState.SUCCESS.value
    while not task_manager.invoice_queue.empty():
        task_manager.invoice_queue.get_nowait()

    @asynccontextmanager
    async def use_connection():
        yield connection

    mocker.patch.object(payments.db, "connect", use_connection)
    mocker.patch.object(
        payments, "get_arkade_ready_account_ids", return_value=[ACCOUNT_ID]
    )
    fetch = mocker.patch.object(payments, "fetch_arkade_indexer_vtxos", return_value=[])
    reconcile = mocker.patch.object(
        payments,
        "reconcile_arkade_receive",
        side_effect=[[payment], []],
    )
    funding = mocker.patch.object(
        payments, "get_funding_source", side_effect=AssertionError("funding source")
    )

    await payments.check_pending_payments()
    await payments.check_pending_payments()

    assert fetch.await_count == 2
    assert reconcile.await_count == 2
    assert task_manager.invoice_queue.qsize() == 1
    funding.assert_not_called()
    task_manager.invoice_queue.get_nowait()


@pytest.mark.anyio
async def test_arkade_pending_check_isolates_indexer_failure(
    connection, ready_mode, mocker
):
    @asynccontextmanager
    async def use_connection():
        yield connection

    mocker.patch.object(payments.db, "connect", use_connection)
    mocker.patch.object(
        payments,
        "get_arkade_ready_account_ids",
        return_value=[ACCOUNT_ID, "dd" * 16],
    )
    mocker.patch.object(
        payments,
        "fetch_arkade_indexer_vtxos",
        side_effect=[arkade.ArkadeReceiveError("ARKADE_INDEXER_UNAVAILABLE"), []],
    )
    reconcile = mocker.patch.object(
        payments, "reconcile_arkade_receive", return_value=[]
    )
    funding = mocker.patch.object(
        payments, "get_funding_source", side_effect=AssertionError("funding source")
    )

    await payments.check_pending_payments()

    assert reconcile.await_count == 1
    funding.assert_not_called()


@pytest.mark.anyio
async def test_expiry_cas_does_not_overwrite_success(connection, ready_mode):
    payment = await payments.create_arkade_pending_invoice(
        wallet_id=WALLET_ID,
        amount=42,
        memo="expiry",
        idempotency_key="ad" * 16,
        conn=connection,
    )
    assert payment.native_id is not None
    await connection.execute(
        "UPDATE apipayments SET status = 'success' WHERE native_id = :native_id",
        {"native_id": payment.native_id},
    )

    updated = await compare_and_set_arkade_payment_failed(payment, conn=connection)

    stored = await payments.get_payment_by_native_id(payment.native_id, conn=connection)
    assert not updated
    assert stored is not None
    assert stored.status == PaymentState.SUCCESS.value


@pytest.mark.anyio
async def test_arkade_payment_status_does_not_use_funding_source(
    connection, ready_mode, mocker
):
    payment = await payments.create_arkade_pending_invoice(
        wallet_id=WALLET_ID,
        amount=42,
        memo="status",
        idempotency_key="ae" * 16,
        conn=connection,
    )
    funding = mocker.patch.object(
        payments, "get_funding_source", side_effect=AssertionError("funding source")
    )

    status = await payments.check_payment_status(payment)

    assert status.pending
    funding.assert_not_called()


@pytest.mark.anyio
async def test_arkade_pending_check_marks_expired_without_indexer(
    connection, ready_mode, mocker
):
    payment = await payments.create_arkade_pending_invoice(
        wallet_id=WALLET_ID,
        amount=42,
        memo="expired",
        expiry=1,
        idempotency_key="af" * 16,
        conn=connection,
    )
    await connection.execute(
        "UPDATE apipayments SET expiry = :expiry WHERE native_id = :native_id",
        {
            "expiry": datetime.now(timezone.utc) - timedelta(seconds=1),
            "native_id": payment.native_id,
        },
    )

    @asynccontextmanager
    async def use_connection():
        yield connection

    mocker.patch.object(payments.db, "connect", use_connection)
    mocker.patch.object(payments, "get_arkade_ready_account_ids", return_value=[])
    funding = mocker.patch.object(
        payments, "get_funding_source", side_effect=AssertionError("funding source")
    )

    await payments.check_pending_payments()

    assert payment.native_id is not None
    stored = await payments.get_payment_by_native_id(payment.native_id, conn=connection)
    assert stored is not None
    assert stored.status == PaymentState.FAILED.value
    assert "expired" in stored.labels
    funding.assert_not_called()
