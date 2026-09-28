import re
from datetime import datetime, timezone

from lnbits.core.db import db
from lnbits.core.models.arkade import (
    ArkadeOutgoingIntent,
    ArkadeOutgoingIntentInput,
)
from lnbits.db import SQLITE, Connection

_TRANSITIONS = {
    ("reserved", "submitted"),
    ("reserved", "quote_ready"),
    ("reserved", "released"),
    ("quote_ready", "released"),
    ("quote_ready", "submitted"),
    ("submitted", "settled"),
    ("submitted", "disputed"),
}
_IMMUTABLE_FIELDS = (
    "intent_id",
    "account_id",
    "wallet_id",
    "amount_msat",
    "max_fee_msat",
    "destination",
    "destination_kind",
    "expires_at",
    "bolt11",
    "payment_hash",
    "quote_pair",
    "quote_from_amount_sat",
    "quote_to_amount_sat",
    "quote_valid_until",
    "refund_locktime",
    "solver_pubkey",
    "swap_rfq_id",
    "lockup_address",
)


def _require_active_transaction(conn: Connection) -> Connection:
    if conn._autocommit:
        raise RuntimeError("ARKADE_MUTATION_REQUIRES_TRANSACTION")
    return conn


async def _check_wallet_account(conn: Connection, intent: ArkadeOutgoingIntent) -> None:
    wallet = await conn.fetchone(
        'SELECT w.id FROM wallets w JOIN accounts a ON a.id = w."user" '
        "WHERE w.id = :wallet_id AND a.id = :account_id",
        {"wallet_id": intent.wallet_id, "account_id": intent.account_id},
    )
    if not wallet:
        raise ValueError("ARKADE_WALLET_ACCOUNT_MISMATCH")


async def get_arkade_outgoing_intent(
    intent_id: str, conn: Connection | None = None
) -> ArkadeOutgoingIntent | None:
    return await (conn or db).fetchone(
        "SELECT * FROM arkade_outgoing_intents WHERE intent_id = :intent_id",
        {"intent_id": intent_id},
        ArkadeOutgoingIntent,
    )


async def get_arkade_outgoing_intent_inputs(
    intent_id: str, conn: Connection | None = None
) -> list[ArkadeOutgoingIntentInput]:
    return await (conn or db).fetchall(
        "SELECT * FROM arkade_outgoing_intent_inputs "
        "WHERE intent_id = :intent_id ORDER BY txid, vout",
        {"intent_id": intent_id},
        ArkadeOutgoingIntentInput,
    )


async def get_arkade_submitted_outgoing_intents(
    limit: int = 100,
    conn: Connection | None = None,
    after_intent_id: str | None = None,
    account_id: str | None = None,
) -> list[ArkadeOutgoingIntent]:
    if not 1 <= limit <= 100:
        raise ValueError("ARKADE_OUTGOING_BATCH_INVALID")
    if after_intent_id is not None and not re.fullmatch(
        r"[0-9a-f]{32}", after_intent_id
    ):
        raise ValueError("ARKADE_OUTGOING_CURSOR_INVALID")
    where = "status = 'submitted'"
    values: dict[str, str | int] = {"limit": limit}
    if account_id is not None:
        where += " AND account_id = :account_id"
        values["account_id"] = account_id
    if after_intent_id is not None:
        where += " AND intent_id > :after_intent_id"
        values["after_intent_id"] = after_intent_id
    return await (conn or db).fetchall(
        "SELECT * FROM arkade_outgoing_intents "  # noqa: S608
        f"WHERE {where} ORDER BY intent_id "
        "LIMIT :limit",
        values,
        ArkadeOutgoingIntent,
    )


async def get_expired_arkade_outgoing_reservations(
    limit: int = 100,
    conn: Connection | None = None,
) -> list[ArkadeOutgoingIntent]:
    """Reservations past their TTL that never reported funding."""
    database = conn or db
    return await database.fetchall(
        "SELECT * FROM arkade_outgoing_intents "  # noqa: S608
        "WHERE status IN ('reserved', 'quote_ready') "
        "AND arkade_txid IS NULL "
        f"AND expires_at <= {database.timestamp_placeholder('now')} "
        "ORDER BY intent_id LIMIT :limit",
        {"now": datetime.now(timezone.utc), "limit": limit},
        ArkadeOutgoingIntent,
    )


def _same_immutable_fields(
    current: ArkadeOutgoingIntent, requested: ArkadeOutgoingIntent
) -> bool:
    return all(
        getattr(current, field) == getattr(requested, field)
        for field in _IMMUTABLE_FIELDS
    )


async def create_arkade_outgoing_intent(
    intent: ArkadeOutgoingIntent, conn: Connection
) -> ArkadeOutgoingIntent:
    connection = _require_active_transaction(conn)
    if connection.type == SQLITE:
        intent = intent.copy(
            update={"expires_at": intent.expires_at.replace(microsecond=0)}
        )
    if intent.status != "reserved" or any(
        getattr(intent, field) is not None
        for field in (
            "arkade_txid",
            "actual_fee_msat",
            "submitted_at",
            "settled_at",
            "released_at",
            "disputed_at",
            "destination_script",
            "change_index",
            "change_script",
            "change_amount_sat",
        )
    ):
        raise ValueError("ARKADE_INTENT_INITIAL_STATE_INVALID")

    existing = await get_arkade_outgoing_intent(intent.intent_id, conn=connection)
    if existing:
        if not _same_immutable_fields(existing, intent):
            raise ValueError("ARKADE_INTENT_IDEMPOTENCY_CONFLICT")
        return existing

    await _check_wallet_account(connection, intent)
    await connection.execute(
        f"""
        INSERT INTO arkade_outgoing_intents (
            intent_id, account_id, wallet_id, amount_msat, max_fee_msat,
            destination, destination_kind, status, bolt11, payment_hash,
            quote_pair, quote_from_amount_sat, quote_to_amount_sat,
            quote_valid_until, refund_locktime, solver_pubkey, swap_rfq_id,
            lockup_address, arkade_txid,
            actual_fee_msat, expires_at, created_at, updated_at, reserved_at,
            submitted_at, settled_at, released_at, disputed_at
        ) VALUES (
            :intent_id, :account_id, :wallet_id, :amount_msat, :max_fee_msat,
            :destination, :destination_kind, :status, :bolt11, :payment_hash,
            :quote_pair, :quote_from_amount_sat, :quote_to_amount_sat,
            {connection.timestamp_placeholder('quote_valid_until')},
            :refund_locktime, :solver_pubkey, :swap_rfq_id, :lockup_address,
            :arkade_txid,
            :actual_fee_msat, {connection.timestamp_placeholder('expires_at')},
            {connection.timestamp_placeholder('created_at')},
            {connection.timestamp_placeholder('updated_at')},
            {connection.timestamp_placeholder('reserved_at')},
            {connection.timestamp_placeholder('submitted_at')},
            {connection.timestamp_placeholder('settled_at')},
            {connection.timestamp_placeholder('released_at')},
            {connection.timestamp_placeholder('disputed_at')}
        ) ON CONFLICT (intent_id) DO NOTHING
        """,  # noqa: S608
        intent.dict(),
    )
    created = await get_arkade_outgoing_intent(intent.intent_id, conn=connection)
    if not created:
        raise RuntimeError("ARKADE_INTENT_UNAVAILABLE")
    if not _same_immutable_fields(created, intent):
        raise ValueError("ARKADE_INTENT_IDEMPOTENCY_CONFLICT")
    return created


async def mark_arkade_outgoing_intent_quote_ready(
    intent_id: str,
    *,
    bolt11: str,
    payment_hash: str,
    quote_pair: str,
    quote_from_amount_sat: int,
    quote_to_amount_sat: int,
    quote_valid_until: datetime,
    refund_locktime: int,
    solver_pubkey: str,
    swap_rfq_id: str,
    lockup_address: str,
    conn: Connection,
) -> bool:
    """Bind an accepted browser quote to a still-unfunded reservation."""
    database = _require_active_transaction(conn)
    result = await database.execute(
        f"""
        UPDATE arkade_outgoing_intents
        SET status = 'quote_ready', bolt11 = :bolt11,
            payment_hash = :payment_hash, quote_pair = :quote_pair,
            quote_from_amount_sat = :quote_from_amount_sat,
            quote_to_amount_sat = :quote_to_amount_sat,
            quote_valid_until = {database.timestamp_placeholder('quote_valid_until')},
            refund_locktime = :refund_locktime, solver_pubkey = :solver_pubkey,
            swap_rfq_id = :swap_rfq_id, lockup_address = :lockup_address,
            updated_at = {database.timestamp_placeholder('updated_at')}
        WHERE intent_id = :intent_id AND status = 'reserved'
        """,  # noqa: S608
        {
            "intent_id": intent_id,
            "bolt11": bolt11,
            "payment_hash": payment_hash,
            "quote_pair": quote_pair,
            "quote_from_amount_sat": quote_from_amount_sat,
            "quote_to_amount_sat": quote_to_amount_sat,
            "quote_valid_until": quote_valid_until,
            "refund_locktime": refund_locktime,
            "solver_pubkey": solver_pubkey,
            "swap_rfq_id": swap_rfq_id,
            "lockup_address": lockup_address,
            "updated_at": datetime.now(timezone.utc),
        },
    )
    return bool(result.rowcount)


async def claim_arkade_outgoing_inputs(
    inputs: list[ArkadeOutgoingIntentInput], conn: Connection
) -> list[ArkadeOutgoingIntentInput]:
    connection = _require_active_transaction(conn)
    if not inputs:
        return []
    if any(item.intent_id != inputs[0].intent_id for item in inputs):
        raise ValueError("ARKADE_INTENT_MISMATCH")
    if len({(item.txid, item.vout) for item in inputs}) != len(inputs):
        raise ValueError("ARKADE_INPUT_ALREADY_CLAIMED")

    await connection.execute("SAVEPOINT arkade_outgoing_input_claims")
    try:
        result = await _claim_arkade_outgoing_inputs(inputs, connection)
    except BaseException:
        await connection.execute("ROLLBACK TO SAVEPOINT arkade_outgoing_input_claims")
        await connection.execute("RELEASE SAVEPOINT arkade_outgoing_input_claims")
        raise
    await connection.execute("RELEASE SAVEPOINT arkade_outgoing_input_claims")
    return result


async def authorize_arkade_outgoing_intent(
    inputs: list[ArkadeOutgoingIntentInput],
    conn: Connection,
    *,
    destination_script: str,
    change_index: int | None = None,
    change_script: str | None = None,
    change_amount_sat: int | None = None,
) -> ArkadeOutgoingIntent:
    database = _require_active_transaction(conn)
    await claim_arkade_outgoing_inputs(inputs, conn=database)
    if destination_script is not None:
        result = await database.execute(
            "UPDATE arkade_outgoing_intents SET "
            "destination_script = :destination_script, "
            "change_index = :change_index, change_script = :change_script, "
            "change_amount_sat = :change_amount_sat "
            "WHERE intent_id = :intent_id AND status = 'reserved'",
            {
                "intent_id": inputs[0].intent_id,
                "destination_script": destination_script,
                "change_index": change_index,
                "change_script": change_script,
                "change_amount_sat": change_amount_sat,
            },
        )
        if not result.rowcount:
            raise ValueError("ARKADE_INTENT_INVALID_TRANSITION")
    transitioned = await _transition_arkade_outgoing_intent(
        inputs[0].intent_id,
        "reserved",
        "submitted",
        conn=database,
    )
    if not transitioned:
        raise ValueError("ARKADE_INTENT_INVALID_TRANSITION")
    intent = await get_arkade_outgoing_intent(inputs[0].intent_id, conn=database)
    if not intent:
        raise ValueError("ARKADE_INTENT_UNAVAILABLE")
    return intent


async def _claim_arkade_outgoing_inputs(
    inputs: list[ArkadeOutgoingIntentInput], conn: Connection
) -> list[ArkadeOutgoingIntentInput]:
    await conn.execute(
        "UPDATE arkade_outgoing_intents SET intent_id = intent_id "
        "WHERE intent_id = :intent_id",
        {"intent_id": inputs[0].intent_id},
    )
    intent = await get_arkade_outgoing_intent(inputs[0].intent_id, conn=conn)
    if not intent:
        raise ValueError("ARKADE_INTENT_NOT_FOUND")
    if intent.status != "reserved":
        raise ValueError("ARKADE_INTENT_NOT_RESERVED")

    existing_by_outpoint: dict[tuple[str, int], dict] = {}
    for item in inputs:
        existing = await conn.fetchone(
            "SELECT intent_id, amount_sat FROM arkade_outgoing_intent_inputs "
            "WHERE txid = :txid AND vout = :vout",
            {"txid": item.txid, "vout": item.vout},
        )
        if existing:
            if (
                existing["intent_id"] != item.intent_id
                or int(existing["amount_sat"]) != item.amount_sat
            ):
                raise ValueError("ARKADE_INPUT_ALREADY_CLAIMED")
            existing_by_outpoint[(item.txid, item.vout)] = existing

    for item in inputs:
        if (item.txid, item.vout) in existing_by_outpoint:
            continue
        result = await conn.execute(
            f"""
            INSERT INTO arkade_outgoing_intent_inputs
                (intent_id, txid, vout, amount_sat, claimed_at)
            VALUES (:intent_id, :txid, :vout, :amount_sat,
                {conn.timestamp_placeholder('claimed_at')})
            ON CONFLICT DO NOTHING
            """,  # noqa: S608
            item.dict(),
        )
        if not result.rowcount:
            existing = await conn.fetchone(
                "SELECT intent_id, amount_sat FROM arkade_outgoing_intent_inputs "
                "WHERE txid = :txid AND vout = :vout",
                {"txid": item.txid, "vout": item.vout},
            )
            if not existing or (
                existing["intent_id"] != item.intent_id
                or int(existing["amount_sat"]) != item.amount_sat
            ):
                raise ValueError("ARKADE_INPUT_ALREADY_CLAIMED")
    return await get_arkade_outgoing_intent_inputs(inputs[0].intent_id, conn=conn)


async def _transition_arkade_outgoing_intent(  # noqa: C901
    intent_id: str,
    from_status: str,
    to_status: str,
    *,
    arkade_txid: str | None = None,
    actual_fee_msat: int | None = None,
    conn: Connection,
) -> bool:
    database = _require_active_transaction(conn)
    if (from_status, to_status) not in _TRANSITIONS:
        raise ValueError("ARKADE_INTENT_INVALID_TRANSITION")
    if to_status == "settled" and actual_fee_msat is None:
        raise ValueError("ARKADE_SETTLEMENT_FEE_REQUIRED")
    if actual_fee_msat is not None and actual_fee_msat < 0:
        raise ValueError("ARKADE_SETTLEMENT_FEE_INVALID")

    current = await get_arkade_outgoing_intent(intent_id, conn=database)
    if not current:
        raise ValueError("ARKADE_INTENT_NOT_FOUND")
    if current.status != from_status:
        raise ValueError("ARKADE_INTENT_INVALID_TRANSITION")
    if actual_fee_msat is not None and actual_fee_msat > current.max_fee_msat:
        raise ValueError("ARKADE_SETTLEMENT_FEE_EXCEEDED")

    now = datetime.now(timezone.utc)
    values = {
        "intent_id": intent_id,
        "from_status": from_status,
        "to_status": to_status,
        "arkade_txid": arkade_txid,
        "actual_fee_msat": actual_fee_msat,
        "now": now,
    }
    columns = [
        "status = :to_status",
        "updated_at = " + database.timestamp_placeholder("now"),
    ]
    if to_status == "submitted":
        columns.extend(
            [
                "arkade_txid = :arkade_txid",
                "submitted_at = " + database.timestamp_placeholder("now"),
            ]
        )
    elif to_status == "quote_ready":
        pass
    elif to_status == "settled":
        columns.extend(
            [
                "actual_fee_msat = :actual_fee_msat",
                "settled_at = " + database.timestamp_placeholder("now"),
            ]
        )
    elif to_status == "released":
        columns.append("released_at = " + database.timestamp_placeholder("now"))
    else:
        columns.append("disputed_at = " + database.timestamp_placeholder("now"))
    result = await database.execute(
        f"UPDATE arkade_outgoing_intents SET {', '.join(columns)} "  # noqa: S608
        "WHERE intent_id = :intent_id AND status = :from_status",
        values,
    )
    return bool(result.rowcount)


async def submit_arkade_outgoing_intent(
    intent_id: str, arkade_txid: str, conn: Connection
) -> bool:
    if not re.fullmatch(r"[0-9a-f]{64}", arkade_txid):
        raise ValueError("ARKADE_TRANSACTION_ID_INVALID")
    database = _require_active_transaction(conn)
    intent = await get_arkade_outgoing_intent(intent_id, conn=database)
    if not intent:
        raise ValueError("ARKADE_INTENT_NOT_FOUND")
    inputs = await database.fetchone(
        "SELECT COUNT(*) AS count, COALESCE(SUM(amount_sat), 0) AS amount_sat "
        "FROM arkade_outgoing_intent_inputs WHERE intent_id = :intent_id",
        {"intent_id": intent_id},
    )
    if not inputs or not int(inputs["count"]):
        raise ValueError("ARKADE_SUBMISSION_INPUTS_REQUIRED")
    if int(inputs["amount_sat"]) * 1000 < intent.amount_msat:
        raise ValueError("ARKADE_SUBMISSION_INPUTS_INSUFFICIENT")
    return await _transition_arkade_outgoing_intent(
        intent_id,
        "reserved",
        "submitted",
        arkade_txid=arkade_txid,
        conn=database,
    )


async def submit_arkade_lightning_intent(
    intent_id: str,
    arkade_txid: str,
    *,
    lockup_address: str,
    swap_rfq_id: str,
    solver_pubkey: str,
    sender_pubkey: str,
    refund_pk_script: str,
    conn: Connection,
) -> bool:
    """CAS a funded Lightning lockup from quote-ready to submitted."""
    if not re.fullmatch(r"[0-9a-f]{64}", arkade_txid):
        raise ValueError("ARKADE_TRANSACTION_ID_INVALID")
    if not re.fullmatch(r"[0-9a-f]{64}", sender_pubkey) or not re.fullmatch(
        r"[0-9a-fA-F]+", refund_pk_script
    ):
        raise ValueError("ARKADE_OUTGOING_REFUND_BINDING_INVALID")
    database = _require_active_transaction(conn)
    intent = await get_arkade_outgoing_intent(intent_id, conn=database)
    if not intent:
        raise ValueError("ARKADE_INTENT_NOT_FOUND")
    if intent.destination_kind != "lightning":
        raise ValueError("ARKADE_INTENT_INVALID_TRANSITION")
    if (
        intent.lockup_address != lockup_address
        or intent.swap_rfq_id != swap_rfq_id
        or intent.solver_pubkey != solver_pubkey
    ):
        raise ValueError("ARKADE_OUTGOING_OUTPUT_CONFLICT")
    if intent.sender_pubkey and intent.sender_pubkey != sender_pubkey:
        raise ValueError("ARKADE_OUTGOING_REFUND_BINDING_CONFLICT")
    if intent.refund_pk_script and intent.refund_pk_script != refund_pk_script:
        raise ValueError("ARKADE_OUTGOING_REFUND_BINDING_CONFLICT")
    await database.execute(
        """
        UPDATE arkade_outgoing_intents
        SET sender_pubkey = :sender_pubkey, refund_pk_script = :refund_pk_script
        WHERE intent_id = :intent_id AND status = 'quote_ready'
        """,
        {
            "intent_id": intent_id,
            "sender_pubkey": sender_pubkey,
            "refund_pk_script": refund_pk_script,
        },
    )
    return await _transition_arkade_outgoing_intent(
        intent_id,
        "quote_ready",
        "submitted",
        arkade_txid=arkade_txid,
        conn=database,
    )


async def record_arkade_lightning_funding_input(
    intent_id: str, funding_input: ArkadeOutgoingIntentInput, conn: Connection
) -> None:
    """Persist the exact lockup outpoint funded by a Lightning intent."""
    database = _require_active_transaction(conn)
    intent = await get_arkade_outgoing_intent(intent_id, conn=database)
    if (
        not intent
        or intent.intent_id != funding_input.intent_id
        or intent.destination_kind != "lightning"
        or intent.status not in {"quote_ready", "submitted"}
        or intent.arkade_txid != funding_input.txid
    ):
        raise ValueError("ARKADE_LIGHTNING_FUNDING_OUTPOINT_INVALID")
    await database.execute(
        f"""
        INSERT INTO arkade_outgoing_intent_inputs
            (intent_id, txid, vout, amount_sat, claimed_at)
        VALUES (:intent_id, :txid, :vout, :amount_sat,
            {database.timestamp_placeholder('claimed_at')})
        ON CONFLICT DO NOTHING
        """,  # noqa: S608
        funding_input.dict(),
    )
    recorded: dict | None = await database.fetchone(
        "SELECT intent_id, amount_sat FROM arkade_outgoing_intent_inputs "
        "WHERE txid = :txid AND vout = :vout",
        {"txid": funding_input.txid, "vout": funding_input.vout},
    )
    if (
        not recorded
        or recorded["intent_id"] != intent_id
        or int(recorded["amount_sat"]) != funding_input.amount_sat
    ):
        raise ValueError("ARKADE_LIGHTNING_FUNDING_OUTPOINT_CONFLICT")


async def release_arkade_outgoing_intent(
    intent_id: str, conn: Connection, *, from_status: str = "reserved"
) -> bool:
    """Release an unfunded intent.

    Defaults to a plain reservation; the service caller passes the observed
    status explicitly after proving the swap carries no funding evidence.
    """
    database = _require_active_transaction(conn)
    released = await _transition_arkade_outgoing_intent(
        intent_id, from_status, "released", conn=conn
    )
    if released:
        await database.execute(
            "DELETE FROM arkade_outgoing_intent_inputs " "WHERE intent_id = :intent_id",
            {"intent_id": intent_id},
        )
    return released


async def settle_arkade_outgoing_intent(
    intent_id: str, actual_fee_msat: int, conn: Connection
) -> bool:
    return await _transition_arkade_outgoing_intent(
        intent_id,
        "submitted",
        "settled",
        actual_fee_msat=actual_fee_msat,
        conn=conn,
    )


async def _get_lightning_terminal_intent(
    intent_id: str, account_id: str, wallet_id: str, conn: Connection
) -> ArkadeOutgoingIntent:
    database = _require_active_transaction(conn)
    intent = await get_arkade_outgoing_intent(intent_id, conn=database)
    if not intent:
        raise ValueError("ARKADE_INTENT_NOT_FOUND")
    if (
        intent.destination_kind != "lightning"
        or intent.account_id != account_id
        or intent.wallet_id != wallet_id
    ):
        raise ValueError("ARKADE_OUTGOING_BINDING_MISMATCH")
    await _check_wallet_account(database, intent)
    if not intent.arkade_txid:
        raise ValueError("ARKADE_LIGHTNING_FUNDING_REQUIRED")
    if intent.settlement_ark_txid and intent.refund_ark_txid:
        raise ValueError("ARKADE_LIGHTNING_TERMINAL_CONFLICT")
    return intent


def _lightning_quote_fee_msat(intent: ArkadeOutgoingIntent) -> int:
    if (
        intent.quote_from_amount_sat is None
        or intent.quote_to_amount_sat is None
        or intent.quote_from_amount_sat < intent.quote_to_amount_sat
        or intent.quote_to_amount_sat * 1000 != intent.amount_msat
    ):
        raise ValueError("ARKADE_LIGHTNING_QUOTE_INVALID")
    fee_msat = (intent.quote_from_amount_sat - intent.quote_to_amount_sat) * 1000
    if fee_msat > intent.max_fee_msat:
        raise ValueError("ARKADE_LIGHTNING_FEE_EXCEEDED")
    return fee_msat


async def settle_arkade_lightning_intent(
    intent_id: str,
    settlement_ark_txid: str,
    *,
    account_id: str,
    wallet_id: str,
    conn: Connection,
) -> bool:
    """CAS a submitted Lightning intent to settled inside its caller's transaction."""
    if not re.fullmatch(r"[0-9a-f]{64}", settlement_ark_txid):
        raise ValueError("ARKADE_TRANSACTION_ID_INVALID")
    database = _require_active_transaction(conn)
    intent = await _get_lightning_terminal_intent(
        intent_id, account_id, wallet_id, database
    )
    fee_msat = _lightning_quote_fee_msat(intent)
    if intent.status == "settled":
        if (
            intent.settlement_ark_txid == settlement_ark_txid
            and intent.actual_fee_msat == fee_msat
            and intent.refund_ark_txid is None
        ):
            return False
        raise ValueError("ARKADE_LIGHTNING_TERMINAL_CONFLICT")
    if intent.status != "submitted" or intent.refund_ark_txid:
        raise ValueError("ARKADE_INTENT_INVALID_TRANSITION")
    now = datetime.now(timezone.utc)
    result = await database.execute(
        f"""
        UPDATE arkade_outgoing_intents
        SET status = 'settled', settlement_ark_txid = :settlement_ark_txid,
            actual_fee_msat = :actual_fee_msat,
            settled_at = {database.timestamp_placeholder('settled_at')},
            updated_at = {database.timestamp_placeholder('updated_at')}
        WHERE intent_id = :intent_id AND account_id = :account_id
          AND wallet_id = :wallet_id AND destination_kind = 'lightning'
          AND status = 'submitted' AND settlement_ark_txid IS NULL
          AND refund_ark_txid IS NULL
        """,  # noqa: S608
        {
            "intent_id": intent_id,
            "account_id": account_id,
            "wallet_id": wallet_id,
            "settlement_ark_txid": settlement_ark_txid,
            "actual_fee_msat": fee_msat,
            "settled_at": now,
            "updated_at": now,
        },
    )
    return bool(result.rowcount)


async def refund_arkade_lightning_intent(
    intent_id: str,
    refund_ark_txid: str,
    *,
    account_id: str,
    wallet_id: str,
    conn: Connection,
) -> bool:
    """CAS a submitted Lightning intent to refunded inside its caller's transaction."""
    if not re.fullmatch(r"[0-9a-f]{64}", refund_ark_txid):
        raise ValueError("ARKADE_TRANSACTION_ID_INVALID")
    database = _require_active_transaction(conn)
    intent = await _get_lightning_terminal_intent(
        intent_id, account_id, wallet_id, database
    )
    if intent.status == "refunded":
        if (
            intent.refund_ark_txid == refund_ark_txid
            and intent.actual_fee_msat == 0
            and intent.settlement_ark_txid is None
        ):
            return False
        raise ValueError("ARKADE_LIGHTNING_TERMINAL_CONFLICT")
    if intent.status != "submitted" or intent.settlement_ark_txid:
        raise ValueError("ARKADE_INTENT_INVALID_TRANSITION")
    now = datetime.now(timezone.utc)
    result = await database.execute(
        f"""
        UPDATE arkade_outgoing_intents
        SET status = 'refunded', refund_ark_txid = :refund_ark_txid,
            actual_fee_msat = 0,
            updated_at = {database.timestamp_placeholder('updated_at')}
        WHERE intent_id = :intent_id AND account_id = :account_id
          AND wallet_id = :wallet_id AND destination_kind = 'lightning'
          AND status = 'submitted' AND settlement_ark_txid IS NULL
          AND refund_ark_txid IS NULL
        """,  # noqa: S608
        {
            "intent_id": intent_id,
            "account_id": account_id,
            "wallet_id": wallet_id,
            "refund_ark_txid": refund_ark_txid,
            "updated_at": now,
        },
    )
    return bool(result.rowcount)


async def fail_arkade_lightning_intent(
    intent_id: str,
    reason: str,
    *,
    account_id: str,
    wallet_id: str,
    conn: Connection,
) -> bool:
    """CAS a submitted Lightning intent to failed(reason) in the caller's tx."""
    database = _require_active_transaction(conn)
    intent = await _get_lightning_terminal_intent(
        intent_id, account_id, wallet_id, database
    )
    if intent.status == "failed":
        if (
            intent.failure_reason == reason
            and intent.actual_fee_msat is None
            and intent.settlement_ark_txid is None
            and intent.refund_ark_txid is None
        ):
            return False
        raise ValueError("ARKADE_LIGHTNING_TERMINAL_CONFLICT")
    if (
        intent.status != "submitted"
        or intent.settlement_ark_txid
        or intent.refund_ark_txid
    ):
        raise ValueError("ARKADE_INTENT_INVALID_TRANSITION")
    now = datetime.now(timezone.utc)
    result = await database.execute(
        f"""
        UPDATE arkade_outgoing_intents
        SET status = 'failed', failure_reason = :reason,
            failed_at = {database.timestamp_placeholder('failed_at')},
            updated_at = {database.timestamp_placeholder('updated_at')}
        WHERE intent_id = :intent_id AND account_id = :account_id
          AND wallet_id = :wallet_id AND destination_kind = 'lightning'
          AND status = 'submitted' AND settlement_ark_txid IS NULL
          AND refund_ark_txid IS NULL
        """,  # noqa: S608
        {
            "intent_id": intent_id,
            "account_id": account_id,
            "wallet_id": wallet_id,
            "reason": reason,
            "failed_at": now,
            "updated_at": now,
        },
    )
    return bool(result.rowcount)


async def settle_arkade_outgoing_intent_verified(
    intent_id: str, arkade_txid: str, conn: Connection
) -> bool:
    database = _require_active_transaction(conn)
    if not re.fullmatch(r"[0-9a-f]{64}", arkade_txid):
        raise ValueError("ARKADE_TRANSACTION_ID_INVALID")
    result = await database.execute(
        f"""
        UPDATE arkade_outgoing_intents
        SET status = 'settled', arkade_txid = :arkade_txid,
            actual_fee_msat = 0,
            settled_at = {database.timestamp_placeholder('settled_at')},
            updated_at = {database.timestamp_placeholder('updated_at')}
        WHERE intent_id = :intent_id AND status = 'submitted'
        """,  # noqa: S608
        {
            "intent_id": intent_id,
            "arkade_txid": arkade_txid,
            "settled_at": datetime.now(timezone.utc),
            "updated_at": datetime.now(timezone.utc),
        },
    )
    return bool(result.rowcount)


async def dispute_arkade_outgoing_intent(intent_id: str, conn: Connection) -> bool:
    database = _require_active_transaction(conn)
    result = await database.execute(
        f"""
        UPDATE arkade_outgoing_intents
        SET status = 'disputed', arkade_txid = NULL, actual_fee_msat = NULL,
            disputed_at = {database.timestamp_placeholder('disputed_at')},
            updated_at = {database.timestamp_placeholder('updated_at')}
        WHERE intent_id = :intent_id AND status = 'submitted'
        """,  # noqa: S608
        {
            "intent_id": intent_id,
            "disputed_at": datetime.now(timezone.utc),
            "updated_at": datetime.now(timezone.utc),
        },
    )
    return bool(result.rowcount)
