from datetime import datetime, timezone
from uuid import uuid4

from lnbits.core.db import db
from lnbits.core.models import (
    ArkadeAccountBinding,
    ArkadeIndexerVtxo,
    ArkadeReceiveRequest,
    ArkadeReconciliation,
)
from lnbits.db import Connection
from lnbits.settings import settings


async def create_arkade_binding(
    account_id: str, conn: Connection | None = None
) -> ArkadeAccountBinding:
    now = datetime.now(timezone.utc)
    from lnbits.core.helpers import get_arkade_configuration

    network, server_url, server_pubkey = get_arkade_configuration()
    binding = ArkadeAccountBinding(
        account_id=account_id,
        enrollment_id=uuid4().hex,
        idempotency_key=None,
        network=network,
        server_url=server_url,
        server_pubkey=server_pubkey,
        created_at=now,
        updated_at=now,
    )
    await (conn or db).insert("arkade_account_bindings", binding)
    return binding


async def get_arkade_binding(
    account_id: str, conn: Connection | None = None
) -> ArkadeAccountBinding | None:
    return await (conn or db).fetchone(
        "SELECT * FROM arkade_account_bindings WHERE account_id = :account_id",
        {"account_id": account_id},
        ArkadeAccountBinding,
    )


async def get_arkade_ready_account_ids(
    conn: Connection | None = None,
) -> list[str]:
    rows = await (conn or db).fetchall(
        "SELECT account_id FROM arkade_account_bindings WHERE state = 'ready'"
    )
    return [row["account_id"] for row in rows]


async def get_arkade_receive_request(
    native_request_id: str, conn: Connection | None = None
) -> ArkadeReceiveRequest | None:
    return await (conn or db).fetchone(
        "SELECT * FROM arkade_receive_requests "
        "WHERE native_request_id = :native_request_id",
        {"native_request_id": native_request_id},
        ArkadeReceiveRequest,
    )


async def get_arkade_receive_request_by_idempotency(
    account_id: str, idempotency_key: str, conn: Connection | None = None
) -> ArkadeReceiveRequest | None:
    return await (conn or db).fetchone(
        "SELECT * FROM arkade_receive_requests "
        "WHERE account_id = :account_id AND idempotency_key = :idempotency_key",
        {"account_id": account_id, "idempotency_key": idempotency_key},
        ArkadeReceiveRequest,
    )


async def get_arkade_receive_request_by_script(
    account_id: str, script: str, conn: Connection | None = None
) -> ArkadeReceiveRequest | None:
    return await (conn or db).fetchone(
        "SELECT * FROM arkade_receive_requests "
        "WHERE account_id = :account_id AND script = :script",
        {"account_id": account_id, "script": script},
        ArkadeReceiveRequest,
    )


async def get_arkade_receive_requests(
    account_id: str, conn: Connection | None = None
) -> list[ArkadeReceiveRequest]:
    return await (conn or db).fetchall(
        "SELECT * FROM arkade_receive_requests "
        "WHERE account_id = :account_id AND script IS NOT NULL",
        {"account_id": account_id},
        ArkadeReceiveRequest,
    )


async def create_arkade_receive_request(
    request: ArkadeReceiveRequest, conn: Connection | None = None
) -> bool:
    database = conn or db
    result = await database.execute(
        f"""
        INSERT INTO arkade_receive_requests (
            native_request_id, account_id, wallet_id, idempotency_key, amount_sat,
            network, server_url, server_pubkey, expires_at, state,
            created_at, updated_at
        ) VALUES (
            :native_request_id, :account_id, :wallet_id, :idempotency_key,
            :amount_sat, :network, :server_url, :server_pubkey,
            {database.timestamp_placeholder('expires_at')}, 'pending',
            {database.timestamp_placeholder('created_at')},
            {database.timestamp_placeholder('updated_at')}
        ) ON CONFLICT DO NOTHING
        """,  # noqa: S608
        {
            "native_request_id": request.native_request_id,
            "account_id": request.account_id,
            "wallet_id": request.wallet_id,
            "idempotency_key": request.idempotency_key,
            "amount_sat": request.amount_sat,
            "network": request.network,
            "server_url": request.server_url,
            "server_pubkey": request.server_pubkey,
            "expires_at": request.expires_at,
            "created_at": request.created_at,
            "updated_at": request.updated_at,
        },
    )
    return bool(result.rowcount)


async def update_arkade_receive_acknowledgement(
    request: ArkadeReceiveRequest,
    *,
    index: int,
    address: str,
    script: str,
    child_xonly_pubkey: str,
    state: str = "acknowledged",
    conn: Connection | None = None,
) -> bool:
    database = conn or db
    now = datetime.now(timezone.utc)
    result = await database.execute(
        f"""
        UPDATE arkade_receive_requests SET
            "index" = :index,
            address = :address,
            script = :script,
            child_xonly_pubkey = :child_xonly_pubkey,
            state = :state,
            updated_at = {database.timestamp_placeholder('updated_at')}
        WHERE native_request_id = :native_request_id AND state = 'pending'
        """,  # noqa: S608
        {
            "index": index,
            "address": address,
            "script": script,
            "child_xonly_pubkey": child_xonly_pubkey,
            "state": state,
            "native_request_id": request.native_request_id,
            "updated_at": now,
        },
    )
    return bool(result.rowcount)


async def mark_arkade_receive_request_reconciliation_required(
    native_request_id: str, conn: Connection | None = None
) -> None:
    await (conn or db).execute(
        "UPDATE arkade_receive_requests "
        "SET state = 'reconciliation_required' "
        "WHERE native_request_id = :native_request_id AND state <> 'settled'",
        {"native_request_id": native_request_id},
    )


async def settle_arkade_receive_request(
    native_request_id: str, settled_at: datetime, conn: Connection | None = None
) -> None:
    database = conn or db
    await database.execute(
        f"""
        UPDATE arkade_receive_requests
        SET state = 'settled',
            settled_at = {database.timestamp_placeholder('settled_at')},
            updated_at = {database.timestamp_placeholder('updated_at')}
        WHERE native_request_id = :native_request_id
        """,  # noqa: S608
        {
            "native_request_id": native_request_id,
            "settled_at": settled_at,
            "updated_at": settled_at,
        },
    )


async def get_arkade_receive_outpoint(
    txid: str, vout: int, conn: Connection | None = None
) -> dict | None:
    return await (conn or db).fetchone(
        "SELECT * FROM arkade_receive_outpoints WHERE txid = :txid AND vout = :vout",
        {"txid": txid, "vout": vout},
    )


async def create_arkade_receive_outpoint(
    *,
    account_id: str,
    native_request_id: str | None,
    vtxo: ArkadeIndexerVtxo,
    status: str,
    conn: Connection | None = None,
) -> bool:
    result = await (conn or db).execute(
        """
        INSERT INTO arkade_receive_outpoints (
            account_id, native_request_id, txid, vout, amount_sat, script,
            status, is_preconfirmed, is_spent, is_swept, spent_by
        ) VALUES (
            :account_id, :native_request_id, :txid, :vout, :amount_sat, :script,
            :status, :is_preconfirmed, :is_spent, :is_swept, :spent_by
        ) ON CONFLICT (txid, vout) DO NOTHING
        """,
        {
            "account_id": account_id,
            "native_request_id": native_request_id,
            "txid": vtxo.txid,
            "vout": vtxo.vout,
            "amount_sat": vtxo.amount_sat,
            "script": vtxo.script,
            "status": status,
            "is_preconfirmed": vtxo.is_preconfirmed,
            "is_spent": vtxo.is_spent,
            "is_swept": vtxo.is_swept,
            "spent_by": vtxo.spent_by,
        },
    )
    return bool(result.rowcount)


async def update_arkade_receive_outpoint_attribution(
    txid: str,
    vout: int,
    native_request_id: str,
    conn: Connection | None = None,
) -> None:
    await (conn or db).execute(
        "UPDATE arkade_receive_outpoints SET "
        "native_request_id = :request_id, status = 'valid' "
        "WHERE txid = :txid AND vout = :vout",
        {"request_id": native_request_id, "txid": txid, "vout": vout},
    )


async def mark_arkade_receive_outpoints_conflict(
    native_request_id: str, conn: Connection | None = None
) -> None:
    await (conn or db).execute(
        "UPDATE arkade_receive_outpoints SET status = 'conflict' "
        "WHERE native_request_id = :native_request_id AND status = 'valid'",
        {"native_request_id": native_request_id},
    )


async def get_arkade_receive_request_total(
    native_request_id: str, conn: Connection | None = None
) -> int:
    row = await (conn or db).fetchone(
        "SELECT COALESCE(SUM(amount_sat), 0) AS total "
        "FROM arkade_receive_outpoints "
        "WHERE native_request_id = :request_id AND status = 'valid'",
        {"request_id": native_request_id},
    )
    return int(row["total"])


async def update_arkade_receive_outpoint(
    vtxo: ArkadeIndexerVtxo, conn: Connection | None = None
) -> None:
    await (conn or db).execute(
        """
        UPDATE arkade_receive_outpoints SET
            is_preconfirmed = :is_preconfirmed,
            is_spent = CASE WHEN is_spent OR :is_spent
                            THEN true ELSE false END,
            is_swept = CASE WHEN is_swept OR :is_swept
                            THEN true ELSE false END,
            spent_by = COALESCE(spent_by, :spent_by)
        WHERE txid = :txid AND vout = :vout
        """,
        {
            "txid": vtxo.txid,
            "vout": vtxo.vout,
            "is_preconfirmed": vtxo.is_preconfirmed,
            "is_spent": vtxo.is_spent,
            "is_swept": vtxo.is_swept,
            "spent_by": vtxo.spent_by,
        },
    )


async def mark_arkade_receive_outpoint_conflict(
    txid: str,
    vout: int,
    account_id: str,
    conn: Connection | None = None,
) -> None:
    await (conn or db).execute(
        "UPDATE arkade_receive_outpoints SET status = 'conflict' "
        "WHERE txid = :txid AND vout = :vout AND account_id = :account_id",
        {"txid": txid, "vout": vout, "account_id": account_id},
    )


async def get_arkade_reconciliation(
    account_id: str, conn: Connection | None = None
) -> ArkadeReconciliation | None:
    return await (conn or db).fetchone(
        "SELECT * FROM arkade_reconciliation_state WHERE account_id = :account_id",
        {"account_id": account_id},
        ArkadeReconciliation,
    )


async def update_arkade_reconciliation(
    account_id: str,
    *,
    state: str,
    last_error: str | None = None,
    observed_at: datetime | None = None,
    conn: Connection | None = None,
) -> ArkadeReconciliation:
    database = conn or db
    now = datetime.now(timezone.utc)
    observed_at = observed_at or now
    await database.execute(
        f"""
        INSERT INTO arkade_reconciliation_state
            (account_id, state, last_error, observed_at, updated_at)
        VALUES (:account_id, :state, :last_error,
                {database.timestamp_placeholder('observed_at')},
                {database.timestamp_placeholder('updated_at')})
        ON CONFLICT (account_id) DO UPDATE SET
            state = excluded.state,
            last_error = excluded.last_error,
            observed_at = excluded.observed_at,
            updated_at = excluded.updated_at
        """,  # noqa: S608
        {
            "account_id": account_id,
            "state": state,
            "last_error": last_error,
            "observed_at": observed_at,
            "updated_at": now,
        },
    )
    result = await get_arkade_reconciliation(account_id, conn=conn)
    if not result:
        raise RuntimeError("ARKADE_RECONCILIATION_UNAVAILABLE")
    return result


async def update_arkade_challenge(
    binding: ArkadeAccountBinding,
    *,
    enrollment_id: str,
    idempotency_key: str,
    nonce: str,
    expires_at: datetime,
    old_idempotency_key: str | None,
    old_nonce: str | None,
    old_expires_at: datetime | None,
    conn: Connection | None = None,
) -> bool:
    database = conn or db
    updated_at = datetime.now(timezone.utc)
    old_key_clause = (
        "idempotency_key IS NULL"
        if old_idempotency_key is None
        else "idempotency_key = :old_idempotency_key"
    )
    old_nonce_clause = (
        "challenge_nonce IS NULL"
        if old_nonce is None
        else "challenge_nonce = :old_nonce"
    )
    old_expiry_clause = (
        "challenge_expires_at IS NULL"
        if old_expires_at is None
        else (
            "challenge_expires_at = "
            f"{database.timestamp_placeholder('old_expires_at')}"
        )
    )
    result = await database.execute(
        # Timestamp placeholders are generated by the trusted DB adapter.
        f"""
        UPDATE arkade_account_bindings SET
            enrollment_id = :enrollment_id,
            idempotency_key = :idempotency_key,
            challenge_nonce = :challenge_nonce,
            challenge_expires_at = {database.timestamp_placeholder('expires_at')},
            updated_at = {database.timestamp_placeholder('updated_at')}
        WHERE account_id = :account_id AND state = 'pending'
          AND enrollment_id = :old_enrollment_id
          AND {old_key_clause}
          AND {old_nonce_clause}
          AND {old_expiry_clause}
        """,  # noqa: S608
        {
            "account_id": binding.account_id,
            "old_enrollment_id": binding.enrollment_id,
            "old_idempotency_key": old_idempotency_key,
            "old_nonce": old_nonce,
            "old_expires_at": old_expires_at,
            "enrollment_id": enrollment_id,
            "idempotency_key": idempotency_key,
            "challenge_nonce": nonce,
            "expires_at": expires_at,
            "updated_at": updated_at,
        },
    )
    return bool(result.rowcount)


async def complete_arkade_binding(
    *,
    account_id: str,
    enrollment_id: str,
    idempotency_key: str,
    nonce: str,
    expires_at: datetime,
    server_utc_now: datetime,
    identity_xonly_pubkey: str,
    identity_descriptor: str,
    acknowledged_at: datetime,
    conn: Connection | None = None,
) -> bool:
    database = conn or db
    now = datetime.now(timezone.utc)
    result = await database.execute(
        # Timestamp placeholders are generated by the trusted DB adapter.
        f"""
        UPDATE arkade_account_bindings SET
            state = 'ready',
            identity_xonly_pubkey = :identity_xonly_pubkey,
            identity_descriptor = :identity_descriptor,
            backup_acknowledged_at = {
                database.timestamp_placeholder('acknowledged_at')
            },
            ready_at = {database.timestamp_placeholder('ready_at')},
            updated_at = {database.timestamp_placeholder('updated_at')},
            challenge_nonce = NULL,
            challenge_expires_at = NULL
        WHERE account_id = :account_id
          AND state = 'pending'
          AND enrollment_id = :enrollment_id
          AND idempotency_key = :idempotency_key
          AND challenge_nonce = :nonce
          AND challenge_expires_at = {database.timestamp_placeholder('expires_at')}
          AND challenge_expires_at > {database.timestamp_placeholder('server_utc_now')}
        """,  # noqa: S608
        {
            "account_id": account_id,
            "enrollment_id": enrollment_id,
            "idempotency_key": idempotency_key,
            "nonce": nonce,
            "expires_at": expires_at,
            "server_utc_now": server_utc_now,
            "identity_xonly_pubkey": identity_xonly_pubkey,
            "identity_descriptor": identity_descriptor,
            "acknowledged_at": acknowledged_at,
            "ready_at": now,
            "updated_at": now,
        },
    )
    return bool(result.rowcount)


async def ensure_arkade_account_deletion_allowed(
    account_id: str, conn: Connection | None = None
) -> None:
    if settings.lnbits_effective_installation_mode == "arkade_noncustodial":
        raise ValueError("ARKADE_ACCOUNT_DELETION_BLOCKED")


async def ensure_arkade_wallet_creation_allowed(
    user_id: str,
    wallet_type: str,
    allow_pending: bool = False,
    conn: Connection | None = None,
) -> None:
    if settings.lnbits_effective_installation_mode != "arkade_noncustodial":
        return
    if wallet_type == "lightning-shared":
        raise ValueError("ARKADE_SHARED_WALLET_UNSUPPORTED")
    binding = await get_arkade_binding(user_id, conn=conn)
    if allow_pending and binding and binding.state == "pending":
        return
    if not binding or binding.state != "ready":
        raise ValueError("ARKADE_ENROLLMENT_REQUIRED")


async def ensure_arkade_wallet_deletion_allowed(
    wallet_id: str, deleted: bool = True, conn: Connection | None = None
) -> None:
    if settings.lnbits_effective_installation_mode != "arkade_noncustodial":
        return
    wallet = await (conn or db).fetchone(
        'SELECT "user", deleted FROM wallets WHERE id = :wallet',
        {"wallet": wallet_id},
    )
    if not wallet:
        return
    binding = await get_arkade_binding(wallet["user"], conn=conn)
    if not binding:
        raise ValueError("ARKADE_WALLET_DELETION_BLOCKED")
    if binding.state != "ready":
        raise ValueError("ARKADE_ENROLLMENT_REQUIRED")
    # Reactivation and removal of an already inactive row cannot remove the
    # final active logical wallet.
    if not deleted or wallet["deleted"]:
        return
    row = await (conn or db).fetchone(
        "SELECT COUNT(*) AS count FROM wallets "
        'WHERE "user" = :user AND deleted = false',
        {"user": wallet["user"]},
    )
    if int(row["count"]) <= 1:
        raise ValueError("ARKADE_FINAL_WALLET_DELETION_BLOCKED")
