import asyncio
from datetime import datetime, timedelta, timezone
from typing import cast
from unittest.mock import AsyncMock

import pytest
from sqlalchemy.ext.asyncio import AsyncConnection, create_async_engine

import lnbits.db as db_module
from lnbits.core import migrations, tasks
from lnbits.core.crud.arkade_lightning_events import (
    MAX_RETRY_DELAY_SECONDS,
    acknowledge_arkade_lightning_terminal_event,
    claim_arkade_lightning_terminal_events,
    create_arkade_lightning_terminal_event,
    get_arkade_lightning_terminal_event,
    retry_arkade_lightning_terminal_event,
)
from lnbits.core.crud.arkade_outgoing import create_arkade_outgoing_intent
from lnbits.core.crud.payments import create_payment
from lnbits.core.models import CreatePayment, PaymentState
from lnbits.core.models.arkade import ArkadeOutgoingIntent
from lnbits.db import SQLITE, Connection
from lnbits.settings import settings
from lnbits.task_manager import TaskManager

ACCOUNT_ID = "00" * 16
OTHER_ACCOUNT_ID = "aa" * 16
WALLET_ID = "11" * 16
OTHER_WALLET_ID = "66" * 16
INTENT_ID = "22" * 16
DESTINATION = "lnbc-test"
SETTLEMENT_TXID = "33" * 32
REFUND_TXID = "44" * 32


@pytest.fixture(autouse=True)
async def isolated_task_manager(monkeypatch):
    manager = TaskManager()
    manager.tasks = []
    monkeypatch.setattr(tasks, "task_manager", manager)
    yield manager
    pending = [task.task for task in manager.tasks]
    manager.cancel_all_tasks()
    await asyncio.gather(*pending, return_exceptions=True)


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
            "INSERT INTO accounts (id) VALUES (:account), (:other), (:wallet)",
            {
                "account": ACCOUNT_ID,
                "other": OTHER_ACCOUNT_ID,
                "wallet": WALLET_ID,
            },
        )
        await connection.execute(
            'INSERT INTO wallets (id, "user", name, adminkey, inkey) '
            "VALUES (:wallet, :account, 'main', 'admin', 'inkey'), "
            "(:other_wallet, :other, 'other', 'admin2', 'inkey2')",
            {
                "wallet": WALLET_ID,
                "account": ACCOUNT_ID,
                "other_wallet": OTHER_WALLET_ID,
                "other": OTHER_ACCOUNT_ID,
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
        # get_wallet reads this view, so the fixture must mirror production.
        await connection.execute(
            "CREATE VIEW balances AS SELECT apipayments.wallet_id, "
            "SUM(apipayments.amount - ABS(apipayments.fee)) AS balance "
            "FROM wallets LEFT JOIN apipayments "
            "ON apipayments.wallet_id = wallets.id "
            "WHERE (wallets.deleted = false OR wallets.deleted IS NULL) "
            "AND ((apipayments.status = 'success' AND apipayments.amount > 0) "
            "OR (apipayments.status IN ('success', 'pending') "
            "AND apipayments.amount < 0)) GROUP BY apipayments.wallet_id"
        )
        await connection.execute(
            "CREATE TABLE arkade_reconciliation_state ("
            "account_id TEXT PRIMARY KEY, state TEXT NOT NULL, last_error TEXT, "
            "observed_at TIMESTAMP, updated_at TIMESTAMP)"
        )
        await migrations.m055_create_arkade_outgoing_tables(connection)
        await migrations.m057_add_arkade_outgoing_outputs(connection)
        await migrations.m058_add_arkade_lightning_quote_fields(connection)
        await migrations.m059_create_arkade_lightning_terminal_events(connection)
        await migrations.m060_add_arkade_lightning_refund_binding(connection)
        await migrations.m061_add_arkade_lightning_failed_state(connection)
        await migrations.m062_extend_arkade_reconciliation_errors(connection)
        await migrations.m064_arkade_maintenance(connection)
        yield connection
    await engine.dispose()


def _intent(event_id: str = INTENT_ID, account_id: str = ACCOUNT_ID):
    now = datetime.now(timezone.utc).replace(microsecond=0)
    return ArkadeOutgoingIntent(
        intent_id=event_id,
        account_id=account_id,
        wallet_id=WALLET_ID,
        amount_msat=5_000_000,
        max_fee_msat=15_000,
        destination=DESTINATION,
        destination_kind="lightning",
        quote_pair="arkade:BTC->lightning:BTC",
        quote_from_amount_sat=5_001,
        quote_to_amount_sat=5_000,
        quote_valid_until=now + timedelta(hours=1),
        refund_locktime=1,
        solver_pubkey="55" * 32,
        swap_rfq_id=f"rfq-{event_id}",
        lockup_address=f"lockup-{event_id}",
        expires_at=now + timedelta(hours=2),
    )


async def _seed(
    connection: Connection,
    state: str = "settled",
    *,
    event_id: str = INTENT_ID,
    account_id: str = ACCOUNT_ID,
    extra: dict | None = None,
):
    intent = _intent(event_id, account_id)
    async with connection.transaction():
        await create_arkade_outgoing_intent(intent, conn=connection)
        await connection.execute(
            "UPDATE arkade_outgoing_intents SET status = :state, "
            "actual_fee_msat = :fee, settlement_ark_txid = :settlement, "
            "refund_ark_txid = :refund WHERE intent_id = :event_id",
            {
                "state": state,
                "fee": (
                    1_000 if state == "settled" else 0 if state == "refunded" else None
                ),
                "settlement": SETTLEMENT_TXID if state == "settled" else None,
                "refund": REFUND_TXID if state == "refunded" else None,
                "event_id": event_id,
            },
        )
        payment = await create_payment(
            None,
            CreatePayment(
                wallet_id=WALLET_ID,
                amount_msat=-intent.amount_msat,
                memo="Arkade Lightning payment",
                fee=1_000 if state == "settled" else 0,
                extra=extra,
                protocol="arkade",
                native_id=event_id,
                arkade_address=DESTINATION,
            ),
            status=PaymentState(
                {"settled": "success", "refunded": "failed", "disputed": "pending"}[
                    state
                ]
            ),
            conn=connection,
        )
    return intent, payment


@pytest.mark.anyio
async def test_insert_rolls_back_with_caller_transaction(connection):
    _, payment = await _seed(connection)
    with pytest.raises(RuntimeError, match="abort"):
        async with connection.transaction():
            await create_arkade_lightning_terminal_event(
                INTENT_ID, "settled", payment, connection
            )
            raise RuntimeError("abort")

    assert await get_arkade_lightning_terminal_event(INTENT_ID, connection) is None


@pytest.mark.anyio
async def test_replay_is_idempotent_and_immutable(connection):
    _, payment = await _seed(connection)
    async with connection.transaction():
        first = await create_arkade_lightning_terminal_event(
            INTENT_ID, "settled", payment, connection
        )
        replay = await create_arkade_lightning_terminal_event(
            INTENT_ID, "settled", payment, connection
        )
        assert replay == first
        count = await connection.fetchone(
            "SELECT COUNT(*) AS count FROM arkade_lightning_terminal_events"
        )
        assert count["count"] == 1
        await connection.execute(
            "UPDATE arkade_lightning_terminal_events SET terminal_state = :state "
            "WHERE event_id = :event_id",
            {"state": "refunded", "event_id": INTENT_ID},
        )
        with pytest.raises(ValueError, match="CONFLICT"):
            await create_arkade_lightning_terminal_event(
                INTENT_ID, "settled", payment, connection
            )
        await connection.execute(
            "UPDATE arkade_lightning_terminal_events SET terminal_state = :state, "
            "payment_payload = :payload WHERE event_id = :event_id",
            {"state": "settled", "payload": "{}", "event_id": INTENT_ID},
        )
        with pytest.raises(ValueError, match="CONFLICT"):
            await create_arkade_lightning_terminal_event(
                INTENT_ID, "settled", payment, connection
            )


@pytest.mark.anyio
async def test_claim_reclaims_stale_and_expired_leases(connection):
    _, payment = await _seed(connection, "disputed")
    async with connection.transaction():
        await create_arkade_lightning_terminal_event(
            INTENT_ID, "disputed", payment, connection
        )
        now = (datetime.now(timezone.utc) + timedelta(minutes=1)).replace(microsecond=0)
        first = await claim_arkade_lightning_terminal_events(
            connection, now=now, lease_seconds=10
        )
        assert len(first) == 1 and first[0].attempts == 1
        first_lease_token = cast(str, first[0].lease_token)
        assert not await acknowledge_arkade_lightning_terminal_event(
            INTENT_ID, "listeners", "wrong", connection, now=now
        )
        assert not await acknowledge_arkade_lightning_terminal_event(
            INTENT_ID,
            "listeners",
            first_lease_token,
            connection,
            now=now + timedelta(seconds=10),
        )
        stale = await claim_arkade_lightning_terminal_events(
            connection, now=now + timedelta(seconds=10), lease_seconds=10
        )
        assert len(stale) == 1 and stale[0].attempts == 2
        stale_lease_token = cast(str, stale[0].lease_token)
        expired = await claim_arkade_lightning_terminal_events(
            connection, now=now + timedelta(seconds=20), lease_seconds=10
        )
        assert len(expired) == 1 and expired[0].attempts == 3
        expired_lease_token = cast(str, expired[0].lease_token)
        assert (
            await acknowledge_arkade_lightning_terminal_event(
                INTENT_ID, "listeners", stale_lease_token, connection, now=now
            )
            is False
        )
        assert await acknowledge_arkade_lightning_terminal_event(
            INTENT_ID,
            "listeners",
            expired_lease_token,
            connection,
            now=now + timedelta(seconds=20),
        )
        assert await acknowledge_arkade_lightning_terminal_event(
            INTENT_ID,
            "webhook",
            expired_lease_token,
            connection,
            now=now + timedelta(seconds=20),
        )
        released = await get_arkade_lightning_terminal_event(INTENT_ID, connection)
        assert released and released.lease_token is None


@pytest.mark.anyio
async def test_retry_caps_delay_and_releases_lease(connection):
    _, payment = await _seed(connection, "disputed")
    async with connection.transaction():
        await create_arkade_lightning_terminal_event(
            INTENT_ID, "disputed", payment, connection
        )
        now = (datetime.now(timezone.utc) + timedelta(minutes=1)).replace(microsecond=0)
        [event] = await claim_arkade_lightning_terminal_events(
            connection, now=now, lease_seconds=60
        )
        event_lease_token = cast(str, event.lease_token)
        assert await retry_arkade_lightning_terminal_event(
            INTENT_ID,
            event_lease_token,
            MAX_RETRY_DELAY_SECONDS + 1,
            connection,
            now=now,
        )
        retried = await get_arkade_lightning_terminal_event(INTENT_ID, connection)
        assert retried and retried.lease_token is None and retried.lease_until is None
        assert retried.next_attempt_at == now + timedelta(
            seconds=MAX_RETRY_DELAY_SECONDS
        )


@pytest.mark.anyio
async def test_validation_rejects_terminal_inconsistencies(connection):
    _, payment = await _seed(connection)
    async with connection.transaction():
        await connection.execute(
            "UPDATE arkade_outgoing_intents SET actual_fee_msat = 0 "
            "WHERE intent_id = :event_id",
            {"event_id": INTENT_ID},
        )
        with pytest.raises(ValueError, match="FEE_OR_TXID"):
            await create_arkade_lightning_terminal_event(
                INTENT_ID, "settled", payment, connection
            )

    _, payment = await _seed(connection, event_id="77" * 16)
    async with connection.transaction():
        await connection.execute(
            "UPDATE arkade_outgoing_intents SET settlement_ark_txid = NULL "
            "WHERE intent_id = :event_id",
            {"event_id": "77" * 16},
        )
        with pytest.raises(ValueError, match="FEE_OR_TXID"):
            await create_arkade_lightning_terminal_event(
                "77" * 16, "settled", payment, connection
            )


@pytest.mark.anyio
async def test_validation_rejects_ownership_channel_secrets_and_stale_payment(
    connection,
):
    _, payment = await _seed(connection)
    async with connection.transaction():
        await connection.execute(
            "UPDATE arkade_outgoing_intents SET account_id = :account "
            "WHERE intent_id = :event_id",
            {"account": WALLET_ID, "event_id": INTENT_ID},
        )
        with pytest.raises(ValueError, match="ACCOUNT_MISMATCH"):
            await create_arkade_lightning_terminal_event(
                INTENT_ID, "settled", payment, connection
            )

    _, payment = await _seed(connection, event_id="77" * 16)
    async with connection.transaction():
        await create_arkade_lightning_terminal_event(
            "77" * 16, "settled", payment, connection
        )
        claimed = await claim_arkade_lightning_terminal_events(connection)
        with pytest.raises(ValueError, match="CHANNEL_INVALID"):
            await acknowledge_arkade_lightning_terminal_event(
                "77" * 16, "invalid", cast(str, claimed[0].lease_token), connection
            )

    _, secret_payment = await _seed(
        connection, event_id="88" * 16, extra={"claim_packet": "secret"}
    )
    async with connection.transaction():
        with pytest.raises(ValueError, match="SECRET"):
            await create_arkade_lightning_terminal_event(
                "88" * 16, "settled", secret_payment, connection
            )

    _, payment = await _seed(connection, event_id="99" * 16)
    async with connection.transaction():
        stale = payment.copy(update={"memo": "stale snapshot"})
        with pytest.raises(ValueError, match="SNAPSHOT_MISMATCH"):
            await create_arkade_lightning_terminal_event(
                "99" * 16, "settled", stale, connection
            )


@pytest.mark.anyio
@pytest.mark.parametrize("state", ["settled", "refunded", "disputed"])
async def test_valid_terminal_states_create(connection, state):
    _, payment = await _seed(connection, state)
    async with connection.transaction():
        event = await create_arkade_lightning_terminal_event(
            INTENT_ID, state, payment, connection
        )
    assert event.terminal_state == state


def _task_db_proxy(connection):
    class _Proxy:
        def connect(self):
            return connection_context()

    from contextlib import asynccontextmanager

    @asynccontextmanager
    async def connection_context():
        yield connection

    return _Proxy()


@pytest.mark.anyio
async def test_dispatcher_awaits_both_channels_before_ack(connection, monkeypatch):
    _, payment = await _seed(connection)
    async with connection.transaction():
        await create_arkade_lightning_terminal_event(
            INTENT_ID, "settled", payment, connection
        )
    monkeypatch.setattr(
        settings, "lnbits_effective_installation_mode", "arkade_noncustodial"
    )
    monkeypatch.setattr(tasks, "db", _task_db_proxy(connection))
    monkeypatch.setattr(tasks, "get_wallet", AsyncMock(return_value=object()))
    delivered = []

    async def deliver_listeners():
        delivered.append("listeners")

    monkeypatch.setattr(
        tasks,
        "send_payment_notification_in_background",
        lambda *_args, **_kwargs: asyncio.create_task(deliver_listeners()),
    )

    async def deliver_webhook(*_args, **_kwargs):
        delivered.append("webhook")

    monkeypatch.setattr(tasks, "dispatch_webhook", deliver_webhook)
    listener = AsyncMock()
    core = AsyncMock()
    tasks.task_manager.register_invoice_listener(listener, "extension")
    tasks.task_manager.register_invoice_listener(core, "core")
    await tasks.dispatch_arkade_lightning_terminal_events()

    event = await get_arkade_lightning_terminal_event(INTENT_ID, connection)
    assert delivered == ["listeners", "webhook"]
    listener.assert_awaited_once_with(payment)
    core.assert_not_awaited()
    assert event and event.listeners_delivered_at and event.webhook_delivered_at
    assert event.lease_token is None


@pytest.mark.anyio
@pytest.mark.parametrize("failure", ["listener", "ack", "webhook"])
async def test_dispatcher_recovers_delivery_after_restart(
    connection, monkeypatch, failure
):
    _, payment = await _seed(connection)
    async with connection.transaction():
        await create_arkade_lightning_terminal_event(
            INTENT_ID, "settled", payment, connection
        )
    monkeypatch.setattr(
        settings, "lnbits_effective_installation_mode", "arkade_noncustodial"
    )
    monkeypatch.setattr(tasks, "db", _task_db_proxy(connection))
    monkeypatch.setattr(tasks, "get_wallet", AsyncMock(return_value=object()))
    notification = AsyncMock()
    monkeypatch.setattr(
        tasks,
        "send_payment_notification_in_background",
        lambda *_args, **_kwargs: asyncio.create_task(notification()),
    )
    delivered = []

    async def listener(received):
        event = await get_arkade_lightning_terminal_event(INTENT_ID, connection)
        assert event and event.listeners_delivered_at is None
        if failure == "listener" and event.attempts == 1:
            # Simulate process loss while a callback is still in progress.
            raise asyncio.CancelledError()
        delivered.append(received.native_id)

    tasks.task_manager.register_invoice_listener(listener, "extension")
    webhook = AsyncMock(
        side_effect=(
            [RuntimeError("delivery failed"), None] if failure == "webhook" else None
        )
    )
    monkeypatch.setattr(tasks, "dispatch_webhook", webhook)
    original_ack = tasks.acknowledge_arkade_lightning_terminal_event

    async def acknowledge(event_id, channel, *args, **kwargs):
        if failure == "ack" and channel == "listeners":
            raise asyncio.CancelledError()
        return await original_ack(event_id, channel, *args, **kwargs)

    monkeypatch.setattr(
        tasks, "acknowledge_arkade_lightning_terminal_event", acknowledge
    )
    if failure in ("listener", "ack"):
        with pytest.raises(asyncio.CancelledError):
            await tasks.dispatch_arkade_lightning_terminal_events()
    else:
        await tasks.dispatch_arkade_lightning_terminal_events()
    event = await get_arkade_lightning_terminal_event(INTENT_ID, connection)
    assert event and event.webhook_delivered_at is None
    assert bool(event.listeners_delivered_at) == (failure == "webhook")

    # Restart with fresh listener tasks; only the database retains delivery state.
    old_manager = tasks.task_manager
    pending = [task.task for task in old_manager.tasks]
    old_manager.cancel_all_tasks()
    await asyncio.gather(*pending, return_exceptions=True)
    manager = TaskManager()
    manager.tasks = []
    monkeypatch.setattr(tasks, "task_manager", manager)
    manager.register_invoice_listener(listener, "extension")
    monkeypatch.setattr(
        tasks, "acknowledge_arkade_lightning_terminal_event", original_ack
    )
    async with connection.transaction():
        await connection.execute(
            "UPDATE arkade_lightning_terminal_events "
            "SET lease_until = NULL, next_attempt_at = :due WHERE event_id = :id",
            {"due": datetime.now(timezone.utc) - timedelta(minutes=1), "id": INTENT_ID},
        )
    try:
        await tasks.dispatch_arkade_lightning_terminal_events()
    finally:
        pending = [task.task for task in manager.tasks]
        manager.cancel_all_tasks()
        await asyncio.gather(*pending, return_exceptions=True)

    assert delivered == [INTENT_ID] * (2 if failure == "ack" else 1)
    event = await get_arkade_lightning_terminal_event(INTENT_ID, connection)
    assert event and event.listeners_delivered_at and event.webhook_delivered_at
    assert event.attempts == 2
    # Delivery retries do not write another terminal payment or charge another fee.
    row = await connection.fetchone(
        "SELECT COUNT(*) AS count, SUM(amount) AS amount, SUM(fee) AS fee "
        "FROM apipayments WHERE native_id = :id",
        {"id": INTENT_ID},
    )
    assert row and (row["count"], row["amount"], row["fee"]) == (
        1,
        payment.amount,
        payment.fee,
    )


@pytest.mark.anyio
async def test_dispatcher_status_only_for_non_success(connection, monkeypatch):
    _, payment = await _seed(connection, "refunded")
    async with connection.transaction():
        await create_arkade_lightning_terminal_event(
            INTENT_ID, "refunded", payment, connection
        )
    monkeypatch.setattr(
        settings, "lnbits_effective_installation_mode", "arkade_noncustodial"
    )
    monkeypatch.setattr(tasks, "db", _task_db_proxy(connection))
    monkeypatch.setattr(tasks, "get_wallet", AsyncMock(return_value=object()))
    notification = AsyncMock()
    monkeypatch.setattr(
        tasks,
        "send_payment_notification_in_background",
        lambda *_args, **kwargs: asyncio.create_task(notification(**kwargs)),
    )
    webhook = AsyncMock()
    monkeypatch.setattr(tasks, "dispatch_webhook", webhook)
    await tasks.dispatch_arkade_lightning_terminal_events()

    assert notification.await_args
    assert notification.await_args.kwargs["include_payment_alerts"] is False
    assert tasks.task_manager.internal_invoice_queue.empty()
    webhook.assert_awaited_once()


@pytest.mark.anyio
async def test_dispatcher_claims_each_slow_event_just_in_time(connection, monkeypatch):
    _, first_payment = await _seed(connection)
    second_intent, second_payment = await _seed(connection, event_id="77" * 16)
    async with connection.transaction():
        await create_arkade_lightning_terminal_event(
            INTENT_ID, "settled", first_payment, connection
        )
        await create_arkade_lightning_terminal_event(
            second_intent.intent_id, "settled", second_payment, connection
        )
    monkeypatch.setattr(
        settings, "lnbits_effective_installation_mode", "arkade_noncustodial"
    )
    monkeypatch.setattr(tasks, "db", _task_db_proxy(connection))
    monkeypatch.setattr(tasks, "get_wallet", AsyncMock(return_value=object()))
    limits = []
    original_claim = tasks.claim_arkade_lightning_terminal_events

    async def claim(connection, **kwargs):
        limits.append(kwargs["limit"])
        return await original_claim(connection, **kwargs)

    monkeypatch.setattr(tasks, "claim_arkade_lightning_terminal_events", claim)
    delivered = []

    async def deliver(**kwargs):
        await asyncio.sleep(0.01)
        delivered.append(kwargs["payment"].native_id)

    monkeypatch.setattr(
        tasks,
        "send_payment_notification_in_background",
        lambda _wallet, payment, **_kwargs: asyncio.create_task(
            deliver(payment=payment)
        ),
    )
    monkeypatch.setattr(tasks, "dispatch_webhook", AsyncMock())
    await tasks.dispatch_arkade_lightning_terminal_events()

    assert limits == [1, 1, 1]
    assert set(delivered) == {INTENT_ID, second_intent.intent_id}


@pytest.mark.anyio
async def test_dispatcher_retries_failed_delivery_without_ack(connection, monkeypatch):
    _, payment = await _seed(connection, event_id="77" * 16)
    async with connection.transaction():
        await create_arkade_lightning_terminal_event(
            "77" * 16, "settled", payment, connection
        )
    monkeypatch.setattr(
        settings, "lnbits_effective_installation_mode", "arkade_noncustodial"
    )
    monkeypatch.setattr(tasks, "db", _task_db_proxy(connection))
    monkeypatch.setattr(tasks, "get_wallet", AsyncMock(return_value=object()))

    async def fail_delivery():
        raise RuntimeError("temporary notification failure")

    monkeypatch.setattr(
        tasks,
        "send_payment_notification_in_background",
        lambda *_args, **_kwargs: asyncio.create_task(fail_delivery()),
    )
    await tasks.dispatch_arkade_lightning_terminal_events()

    event = await get_arkade_lightning_terminal_event("77" * 16, connection)
    assert event and event.attempts == 1
    assert event.listeners_delivered_at is None
    assert event.lease_token is None
