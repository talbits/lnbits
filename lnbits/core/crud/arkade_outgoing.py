import re
from datetime import datetime, timezone

from lnbits.core.db import db
from lnbits.core.models.arkade import (
    ArkadeOutgoingIntent,
    ArkadeOutgoingIntentInput,
)
from lnbits.db import Connection

_TRANSITIONS = {
    ("reserved", "submitted"),
    ("reserved", "released"),
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
            destination, destination_kind, status, arkade_txid,
            actual_fee_msat, expires_at, created_at, updated_at, reserved_at,
            submitted_at, settled_at, released_at, disputed_at
        ) VALUES (
            :intent_id, :account_id, :wallet_id, :amount_msat, :max_fee_msat,
            :destination, :destination_kind, :status, :arkade_txid,
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


async def _transition_arkade_outgoing_intent(
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


async def release_arkade_outgoing_intent(intent_id: str, conn: Connection) -> bool:
    database = _require_active_transaction(conn)
    released = await _transition_arkade_outgoing_intent(
        intent_id, "reserved", "released", conn=conn
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


async def dispute_arkade_outgoing_intent(intent_id: str, conn: Connection) -> bool:
    return await _transition_arkade_outgoing_intent(
        intent_id, "submitted", "disputed", conn=conn
    )
