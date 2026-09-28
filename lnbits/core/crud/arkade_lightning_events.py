from datetime import datetime, timedelta, timezone
from secrets import token_hex
from typing import Literal

from lnbits.core.crud.arkade_outgoing import (
    _lightning_quote_fee_msat,
    get_arkade_outgoing_intent,
)
from lnbits.core.crud.payments import get_payment_by_native_id
from lnbits.core.models import Payment, PaymentState
from lnbits.core.models.arkade import ArkadeLightningTerminalEvent
from lnbits.db import Connection

TerminalState = Literal["settled", "refunded", "failed", "disputed"]
DeliveryChannel = Literal["listeners", "webhook"]
MAX_RETRY_DELAY_SECONDS = 60 * 60


def _require_active_transaction(conn: Connection) -> Connection:
    if conn._autocommit:
        raise RuntimeError("ARKADE_MUTATION_REQUIRES_TRANSACTION")
    return conn


def _safe_payment_payload(payment: Payment) -> str:
    if payment.preimage:
        raise ValueError("ARKADE_TERMINAL_EVENT_SECRET")
    if _contains_secret(payment.extra):
        raise ValueError("ARKADE_TERMINAL_EVENT_SECRET")
    return payment.json(
        exclude={"preimage", "payment_request"},
        sort_keys=True,
        separators=(",", ":"),
    )


def _contains_secret(value: object) -> bool:
    secret_names = {
        "claim_packet",
        "mnemonic",
        "nsec",
        "payment_request",
        "preimage",
        "private_key",
        "seed",
        "signing_key",
    }
    if isinstance(value, dict):
        return any(
            str(key).lower() in secret_names or _contains_secret(item)
            for key, item in value.items()
        )
    if isinstance(value, (list, tuple)):
        return any(_contains_secret(item) for item in value)
    return False


async def _validate_terminal_event(  # noqa: C901
    event_id: str, terminal_state: TerminalState, payment: Payment, conn: Connection
) -> str:
    intent = await get_arkade_outgoing_intent(event_id, conn=conn)
    if not intent or intent.destination_kind != "lightning":
        raise ValueError("ARKADE_TERMINAL_EVENT_BINDING_MISMATCH")
    if intent.status != terminal_state:
        raise ValueError("ARKADE_TERMINAL_EVENT_STATE_MISMATCH")
    wallet_account: dict | None = await conn.fetchone(
        'SELECT "user" FROM wallets WHERE id = :wallet_id',
        {"wallet_id": intent.wallet_id},
    )
    if not wallet_account or wallet_account["user"] != intent.account_id:
        raise ValueError("ARKADE_TERMINAL_EVENT_ACCOUNT_MISMATCH")
    persisted_payment = await get_payment_by_native_id(event_id, conn=conn)
    if not persisted_payment:
        raise ValueError("ARKADE_TERMINAL_EVENT_PAYMENT_NOT_FOUND")
    caller_payload = _safe_payment_payload(payment)
    persisted_payload = _safe_payment_payload(persisted_payment)
    if caller_payload != persisted_payload:
        raise ValueError("ARKADE_TERMINAL_EVENT_PAYMENT_SNAPSHOT_MISMATCH")
    if (
        persisted_payment.protocol != "arkade"
        or persisted_payment.native_id != event_id
        or payment.wallet_id != intent.wallet_id
        or persisted_payment.wallet_id != intent.wallet_id
        or persisted_payment.amount != -intent.amount_msat
        or persisted_payment.arkade_address != intent.destination
    ):
        raise ValueError("ARKADE_TERMINAL_EVENT_PAYMENT_MISMATCH")
    expected_status = {
        "settled": PaymentState.SUCCESS.value,
        "refunded": PaymentState.FAILED.value,
        "failed": PaymentState.FAILED.value,
        "disputed": PaymentState.PENDING.value,
    }[terminal_state]
    if persisted_payment.status != expected_status:
        raise ValueError("ARKADE_TERMINAL_EVENT_PAYMENT_STATE_MISMATCH")
    if terminal_state == "settled":
        expected_fee_msat = _lightning_quote_fee_msat(intent)
        if (
            intent.actual_fee_msat != expected_fee_msat
            or not intent.settlement_ark_txid
            or intent.refund_ark_txid is not None
            or persisted_payment.fee != -expected_fee_msat
        ):
            raise ValueError("ARKADE_TERMINAL_EVENT_FEE_OR_TXID_MISMATCH")
    elif terminal_state == "refunded":
        if (
            intent.actual_fee_msat != 0
            or not intent.refund_ark_txid
            or intent.settlement_ark_txid is not None
            or persisted_payment.fee != 0
        ):
            raise ValueError("ARKADE_TERMINAL_EVENT_FEE_OR_TXID_MISMATCH")
    elif (
        intent.actual_fee_msat is not None
        or intent.settlement_ark_txid is not None
        or intent.refund_ark_txid is not None
        or persisted_payment.fee != 0
    ):
        raise ValueError("ARKADE_TERMINAL_EVENT_FEE_MISMATCH")
    return persisted_payload


async def get_arkade_lightning_terminal_event(
    event_id: str, conn: Connection
) -> ArkadeLightningTerminalEvent | None:
    return await conn.fetchone(
        "SELECT * FROM arkade_lightning_terminal_events WHERE event_id = :event_id",
        {"event_id": event_id},
        ArkadeLightningTerminalEvent,
    )


async def create_arkade_lightning_terminal_event(
    event_id: str,
    terminal_state: TerminalState,
    payment: Payment,
    conn: Connection,
) -> ArkadeLightningTerminalEvent:
    """Insert the immutable terminal event in the terminal-state transaction."""
    connection = _require_active_transaction(conn)
    payload = await _validate_terminal_event(
        event_id, terminal_state, payment, connection
    )
    await connection.execute(
        f"""
        INSERT INTO arkade_lightning_terminal_events (
            event_id, terminal_state, payment_payload, next_attempt_at
        ) VALUES (
            :event_id, :terminal_state, :payment_payload,
            {connection.timestamp_placeholder('next_attempt_at')}
        ) ON CONFLICT (event_id) DO NOTHING
        """,  # noqa: S608
        {
            "event_id": event_id,
            "terminal_state": terminal_state,
            "payment_payload": payload,
            "next_attempt_at": datetime.now(timezone.utc),
        },
    )
    event = await get_arkade_lightning_terminal_event(event_id, connection)
    if not event:
        raise RuntimeError("ARKADE_TERMINAL_EVENT_UNAVAILABLE")
    if event.terminal_state != terminal_state or event.payment_payload != payload:
        raise ValueError("ARKADE_TERMINAL_EVENT_CONFLICT")
    return event


async def claim_arkade_lightning_terminal_events(
    conn: Connection,
    *,
    limit: int = 32,
    lease_seconds: int = 60,
    now: datetime | None = None,
) -> list[ArkadeLightningTerminalEvent]:
    """Claim a bounded due batch; stale leases are eligible again."""
    connection = _require_active_transaction(conn)
    if not 1 <= limit <= 100 or lease_seconds <= 0:
        raise ValueError("ARKADE_TERMINAL_EVENT_BATCH_INVALID")
    now = now or datetime.now(timezone.utc)
    due = await connection.fetchall(
        f"""
        SELECT * FROM arkade_lightning_terminal_events
        WHERE next_attempt_at <= {connection.timestamp_placeholder('now')}
          AND (
              lease_until IS NULL
              OR lease_until <= {connection.timestamp_placeholder('now')}
          )
          AND (listeners_delivered_at IS NULL OR webhook_delivered_at IS NULL)
        ORDER BY next_attempt_at, event_id
        LIMIT :limit
        """,  # noqa: S608
        {"now": now, "limit": limit},
        ArkadeLightningTerminalEvent,
    )
    claimed: list[ArkadeLightningTerminalEvent] = []
    for event in due:
        token = token_hex(16)
        lease_until = now + timedelta(seconds=lease_seconds)
        result = await connection.execute(
            f"""
            UPDATE arkade_lightning_terminal_events
            SET attempts = attempts + 1, lease_token = :lease_token,
                lease_until = {connection.timestamp_placeholder('lease_until')}
            WHERE event_id = :event_id
              AND next_attempt_at <= {connection.timestamp_placeholder('now')}
              AND (
                  lease_until IS NULL
                  OR lease_until <= {connection.timestamp_placeholder('now')}
              )
            AND (listeners_delivered_at IS NULL OR webhook_delivered_at IS NULL)
            """,  # noqa: S608
            {
                "event_id": event.event_id,
                "lease_token": token,
                "lease_until": lease_until,
                "now": now,
            },
        )
        if result.rowcount:
            claimed_event = await get_arkade_lightning_terminal_event(
                event.event_id, connection
            )
            if claimed_event:
                claimed.append(claimed_event)
    return claimed


async def acknowledge_arkade_lightning_terminal_event(
    event_id: str,
    channel: str,
    lease_token: str,
    conn: Connection,
    *,
    now: datetime | None = None,
) -> bool:
    """Acknowledge a channel only with the active lease after delivery."""
    connection = _require_active_transaction(conn)
    if channel not in ("listeners", "webhook"):
        raise ValueError("ARKADE_TERMINAL_EVENT_CHANNEL_INVALID")
    column = (
        "listeners_delivered_at" if channel == "listeners" else "webhook_delivered_at"
    )
    now = now or datetime.now(timezone.utc)
    result = await connection.execute(
        f"""
        UPDATE arkade_lightning_terminal_events
        SET {column} = {connection.timestamp_placeholder('now')}
        WHERE event_id = :event_id AND lease_token = :lease_token
          AND lease_until > {connection.timestamp_placeholder('now')}
          AND {column} IS NULL
        """,  # noqa: S608
        {"event_id": event_id, "lease_token": lease_token, "now": now},
    )
    if not result.rowcount:
        return False
    await connection.execute(
        """
        UPDATE arkade_lightning_terminal_events
        SET lease_token = NULL, lease_until = NULL
        WHERE event_id = :event_id AND lease_token = :lease_token
          AND listeners_delivered_at IS NOT NULL
          AND webhook_delivered_at IS NOT NULL
        """,
        {"event_id": event_id, "lease_token": lease_token},
    )
    return True


async def retry_arkade_lightning_terminal_event(
    event_id: str,
    lease_token: str,
    delay_seconds: int,
    conn: Connection,
    *,
    now: datetime | None = None,
) -> bool:
    """Release a claim and schedule a retry with a capped delay."""
    connection = _require_active_transaction(conn)
    if delay_seconds < 0:
        raise ValueError("ARKADE_TERMINAL_EVENT_DELAY_INVALID")
    now = now or datetime.now(timezone.utc)
    retry_at = now + timedelta(seconds=min(delay_seconds, MAX_RETRY_DELAY_SECONDS))
    result = await connection.execute(
        f"""
        UPDATE arkade_lightning_terminal_events
        SET next_attempt_at = {connection.timestamp_placeholder('next_attempt_at')},
            lease_token = NULL, lease_until = NULL
        WHERE event_id = :event_id AND lease_token = :lease_token
          AND lease_until > {connection.timestamp_placeholder('now')}
          AND (listeners_delivered_at IS NULL OR webhook_delivered_at IS NULL)
        """,  # noqa: S608
        {
            "event_id": event_id,
            "lease_token": lease_token,
            "next_attempt_at": retry_at,
            "now": now,
        },
    )
    return bool(result.rowcount)
