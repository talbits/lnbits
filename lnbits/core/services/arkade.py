from __future__ import annotations

import base64
import hashlib
import json
import re
from datetime import datetime, timedelta, timezone
from secrets import token_hex
from typing import TYPE_CHECKING
from uuid import uuid4

import httpx
from bech32 import CHARSET, bech32_hrp_expand, bech32_polymod, convertbits
from coincurve import PublicKeyXOnly
from embit.base import EmbitError
from embit.descriptor import Descriptor
from embit.psbt import PSBT
from loguru import logger
from sqlalchemy.exc import IntegrityError, OperationalError

from lnbits import bolt11
from lnbits.core.crud.arkade import (
    complete_arkade_binding,
    create_arkade_receive_outpoint,
    create_arkade_receive_request,
    ensure_arkade_binding_for_existing_account,
    get_arkade_binding,
    get_arkade_receive_outpoint,
    get_arkade_receive_request,
    get_arkade_receive_request_by_destination,
    get_arkade_receive_request_by_idempotency,
    get_arkade_receive_request_by_script,
    get_arkade_receive_request_total,
    get_arkade_receive_requests,
    get_arkade_reconciliation,
    mark_arkade_receive_outpoint_conflict,
    mark_arkade_receive_outpoints_conflict,
    mark_arkade_receive_request_reconciliation_required,
    settle_arkade_receive_request,
    update_arkade_challenge,
    update_arkade_receive_acknowledgement,
    update_arkade_receive_outpoint,
    update_arkade_receive_outpoint_attribution,
    update_arkade_reconciliation,
)
from lnbits.core.crud.arkade_lightning_events import (
    TerminalState,
    create_arkade_lightning_terminal_event,
)
from lnbits.core.crud.arkade_maintenance import (
    maintenance_rows,
    reconcile_maintenance,
    store_maintenance,
)
from lnbits.core.crud.arkade_outgoing import (
    authorize_arkade_outgoing_intent,
    create_arkade_outgoing_intent,
    dispute_arkade_outgoing_intent,
    get_arkade_outgoing_intent,
    get_arkade_outgoing_intent_inputs,
    get_arkade_submitted_outgoing_intents,
    get_expired_arkade_outgoing_reservations,
    mark_arkade_outgoing_intent_quote_ready,
    record_arkade_lightning_funding_input,
    refund_arkade_lightning_intent,
    release_arkade_outgoing_intent,
    settle_arkade_lightning_intent,
    settle_arkade_outgoing_intent_verified,
)
from lnbits.core.crud.arkade_outgoing import (
    fail_arkade_lightning_intent as fail_arkade_lightning_intent_crud,
)
from lnbits.core.crud.arkade_outgoing import (
    submit_arkade_lightning_intent as submit_arkade_lightning_intent_crud,
)
from lnbits.core.crud.audit import create_audit_entry
from lnbits.core.crud.payments import (
    compare_and_set_arkade_payment_failed,
    compare_and_set_payment_success,
    create_payment,
    fail_arkade_lightning_payment,
    get_payment_by_native_id,
    refund_arkade_lightning_payment,
    settle_arkade_lightning_payment,
    settle_arkade_outgoing_payment,
    update_payment,
)
from lnbits.core.crud.wallets import get_wallet
from lnbits.core.db import db
from lnbits.core.models import (
    ArkadeAccountBinding,
    ArkadeEnrollmentBindingResponse,
    ArkadeEnrollmentChallenge,
    ArkadeEnrollmentCompletion,
    ArkadeIndexerVtxo,
    ArkadeLightningFundingEvidence,
    ArkadeOutgoingChangeCommitment,
    ArkadeOutgoingEvidenceResult,
    ArkadeOutgoingEvidenceStatus,
    ArkadeOutgoingIntent,
    ArkadeOutgoingIntentInput,
    ArkadeOutgoingIntentResponse,
    ArkadeOutgoingSelectedInput,
    ArkadeReceiveAcknowledgement,
    ArkadeReceiveRequest,
    ArkadeReconciliation,
    AuditEntry,
    Payment,
    PaymentState,
)
from lnbits.core.models.arkade import (
    ArkadeBackingStatus,
    ArkadeLightningQuoteInput,
    ArkadeMaintenancePlan,
)
from lnbits.core.models.payments import CreatePayment
from lnbits.core.models.users import Account
from lnbits.db import SQLITE, Connection
from lnbits.settings import settings
from lnbits.task_manager import task_manager

from .notifications import send_payment_notification_for_wallet

if TYPE_CHECKING:
    from .arkade_evidence import ArkadeLightningEvidenceVerdict

ENROLLMENT_ACTION = "lnbits-arkade-enrollment-v1"
IDENTITY_KIND = "mnemonic_hd"
CHALLENGE_TTL_SECONDS = 10 * 60
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_ID = re.compile(r"^[0-9a-f]{32}$")
_IDEMPOTENCY = re.compile(r"^[0-9a-f]{32}$")
_IDENTITY_DESCRIPTOR = re.compile(
    r"^tr\(\[[0-9a-f]{8}/86'/(0|1)'/0'\](xpub|tpub)" r"[1-9A-HJ-NP-Za-km-z]+/0/\*\)$"
)
_TXID = re.compile(r"^[0-9a-f]{64}$")
_SCRIPT = re.compile(r"^[0-9a-fA-F]+$")
RECEIVE_ACTION = "lnbits-arkade-receive-v1"
MAX_AMOUNT_SAT = 2_100_000_000_000_000
MAX_VOUT = 4_294_967_295
_INDEXER_TIMESTAMP_BOUNDARY_MS = 1_735_689_600_000
_MAX_INDEXER_PSBT_BYTES = 4 * 1024 * 1024
_MAX_INDEXER_PSBT_BASE64_LENGTH = 4 * ((_MAX_INDEXER_PSBT_BYTES + 2) // 3)
LIGHTNING_MIN_QUOTE_AMOUNT_SAT = 500
LIGHTNING_MAX_QUOTE_AMOUNT_SAT = 50_000
LIGHTNING_REFUND_HEADROOM_SECONDS = 10_800
LIGHTNING_QUOTE_PAIR = "arkade:BTC->lightning:BTC"
_TAPROOT_UNSPENDABLE_KEY = bytes.fromhex(
    "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0"
)
ARKADE_HRPS = {
    "bitcoin": "ark",
    "testnet": "tark",
    "signet": "tark",
    "mutinynet": "tark",
    "regtest": "tark",
}


class ArkadeEnrollmentError(ValueError):
    pass


class ArkadeEnrollmentMigrationRequiredError(ArkadeEnrollmentError):
    pass


class ArkadeReceiveError(ValueError):
    pass


class ArkadeOutgoingError(ValueError):
    pass


class ArkadeReconciliationError(ValueError):
    pass


def arkade_internal_transfer_id(native_request_id: str) -> str:
    return hashlib.sha256(
        f"lnbits-arkade-transfer-v1:{native_request_id}".encode()
    ).hexdigest()[:32]


async def settle_arkade_same_account_transfer(  # noqa: C901
    account_id: str,
    wallet_id: str,
    destination: str,
    amount_msat: int,
    *,
    memo: str | None = None,
    extra: dict | None = None,
    labels: list[str] | None = None,
    external_id: str | None = None,
    conn: Connection | None = None,
) -> tuple[Payment, Payment]:
    """Atomically reallocate a registered Arkade receive request locally."""
    if settings.lnbits_effective_installation_mode != "arkade_noncustodial":
        raise ArkadeOutgoingError("ARKADE_OUTGOING_UNAVAILABLE")
    if amount_msat <= 0 or amount_msat % 1000:
        raise ArkadeOutgoingError("ARKADE_OUTGOING_AMOUNT_INVALID")
    request = await get_arkade_receive_request_by_destination(destination, conn=conn)
    if not request:
        raise ArkadeOutgoingError("ARKADE_TRANSFER_DESTINATION_NOT_FOUND")
    if request.account_id != account_id:
        raise ArkadeOutgoingError("ARKADE_TRANSFER_CROSS_ACCOUNT_REQUIRED")
    transfer_id = arkade_internal_transfer_id(request.native_request_id)
    now = datetime.now(timezone.utc)

    try:
        async with db.reuse_conn(conn) if conn else db.connect() as database:
            async with database.transaction():
                await database.execute(
                    "UPDATE arkade_account_bindings SET account_id = account_id "
                    "WHERE account_id = :account_id AND state = 'ready'",
                    {"account_id": account_id},
                )
                binding = await get_arkade_binding(account_id, conn=database)
                if not binding or binding.state != "ready":
                    raise ArkadeOutgoingError("ARKADE_ENROLLMENT_REQUIRED")

                sender_wallet = await get_wallet(wallet_id, conn=database)
                receiver_wallet = await get_wallet(request.wallet_id, conn=database)
                if (
                    not sender_wallet
                    or sender_wallet.id != wallet_id
                    or sender_wallet.user != account_id
                    or sender_wallet.deleted
                    or not sender_wallet.can_send_payments
                ):
                    raise ArkadeOutgoingError("ARKADE_OUTGOING_NOT_ALLOWED")
                if (
                    not receiver_wallet
                    or receiver_wallet.id != request.wallet_id
                    or receiver_wallet.user != account_id
                    or receiver_wallet.deleted
                    or not receiver_wallet.can_receive_payments
                ):
                    raise ArkadeOutgoingError("ARKADE_TRANSFER_RECEIVER_NOT_ALLOWED")
                if sender_wallet.id == receiver_wallet.id:
                    raise ArkadeOutgoingError("ARKADE_TRANSFER_SAME_WALLET")

                receiver_payment = await get_payment_by_native_id(
                    request.native_request_id, conn=database
                )
                sender_payment = await get_payment_by_native_id(
                    transfer_id, conn=database
                )
                expected_amount = request.amount_sat * 1000
                if amount_msat != expected_amount:
                    raise ArkadeOutgoingError("ARKADE_TRANSFER_AMOUNT_CONFLICT")

                if sender_payment:
                    if (
                        request.state != "settled"
                        or not receiver_payment
                        or sender_payment.protocol != "arkade"
                        or sender_payment.native_id != transfer_id
                        or sender_payment.wallet_id != sender_wallet.id
                        or sender_payment.amount != -expected_amount
                        or sender_payment.fee != 0
                        or sender_payment.arkade_address != request.address
                        or sender_payment.status != PaymentState.SUCCESS.value
                        or receiver_payment.protocol != "arkade"
                        or receiver_payment.wallet_id != receiver_wallet.id
                        or receiver_payment.amount != expected_amount
                        or receiver_payment.arkade_address != request.address
                        or receiver_payment.status != PaymentState.SUCCESS.value
                    ):
                        raise ArkadeOutgoingError("ARKADE_TRANSFER_CORRUPT")
                    return sender_payment, receiver_payment

                if request.state != "acknowledged":
                    raise ArkadeOutgoingError("ARKADE_TRANSFER_MAPPING_NOT_READY")
                if request.expires_at <= now:
                    raise ArkadeOutgoingError("ARKADE_TRANSFER_EXPIRED")
                if (
                    not request.address
                    or not request.script
                    or not receiver_payment
                    or receiver_payment.protocol != "arkade"
                    or receiver_payment.native_id != request.native_request_id
                    or receiver_payment.wallet_id != receiver_wallet.id
                    or receiver_payment.amount != expected_amount
                    or receiver_payment.arkade_address != request.address
                    or receiver_payment.fee != 0
                    or receiver_payment.status != PaymentState.PENDING.value
                ):
                    raise ArkadeOutgoingError("ARKADE_TRANSFER_RECEIVER_INVALID")
                if sender_wallet.balance_msat < expected_amount:
                    raise ArkadeOutgoingError("ARKADE_INSUFFICIENT_FUNDS")

                sender_payment = await create_payment(
                    checking_id=None,
                    data=CreatePayment(
                        wallet_id=sender_wallet.id,
                        amount_msat=-expected_amount,
                        memo=memo or "Arkade internal transfer",
                        extra=extra,
                        labels=labels,
                        external_id=external_id,
                        protocol="arkade",
                        native_id=transfer_id,
                        arkade_address=request.address,
                    ),
                    status=PaymentState.SUCCESS,
                    conn=database,
                )
                receiver_update = await database.execute(
                    f"""
                    UPDATE apipayments
                    SET status = 'success',
                        updated_at = {database.timestamp_placeholder('updated_at')}
                    WHERE protocol = 'arkade' AND native_id = :native_id
                      AND wallet_id = :wallet_id AND amount = :amount
                      AND fee = 0 AND arkade_address = :address
                      AND status = 'pending'
                    """,  # noqa: S608
                    {
                        "native_id": request.native_request_id,
                        "wallet_id": receiver_wallet.id,
                        "amount": expected_amount,
                        "address": request.address,
                        "updated_at": now,
                    },
                )
                mapping_update = await database.execute(
                    f"""
                    UPDATE arkade_receive_requests
                    SET state = 'settled',
                        settled_at = {database.timestamp_placeholder('settled_at')},
                        updated_at = {database.timestamp_placeholder('updated_at')}
                    WHERE native_request_id = :native_id
                      AND account_id = :account_id
                      AND wallet_id = :wallet_id
                      AND amount_sat = :amount_sat
                      AND address = :address AND script = :script
                      AND state = 'acknowledged'
                      AND expires_at > {database.timestamp_placeholder('now')}
                    """,  # noqa: S608
                    {
                        "native_id": request.native_request_id,
                        "account_id": account_id,
                        "wallet_id": receiver_wallet.id,
                        "amount_sat": request.amount_sat,
                        "address": request.address,
                        "script": request.script,
                        "settled_at": now,
                        "updated_at": now,
                        "now": now,
                    },
                )
                if receiver_update.rowcount != 1 or mapping_update.rowcount != 1:
                    raise ArkadeOutgoingError("ARKADE_TRANSFER_CORRUPT")
                receiver_payment = await get_payment_by_native_id(
                    request.native_request_id, conn=database
                )
                if not receiver_payment:
                    raise ArkadeOutgoingError("ARKADE_TRANSFER_CORRUPT")
    except OperationalError as exc:
        if _is_database_busy(exc):
            raise ArkadeOutgoingError("ARKADE_OUTGOING_BUSY") from None
        raise

    await send_payment_notification_for_wallet(wallet_id, sender_payment, conn=conn)
    await send_payment_notification_for_wallet(
        request.wallet_id, receiver_payment, conn=conn
    )
    task_manager.internal_invoice_queue.put_nowait(receiver_payment)
    return sender_payment, receiver_payment


def _is_database_busy(exc: OperationalError) -> bool:
    original = getattr(exc, "orig", None)
    states = {
        str(getattr(original, "sqlstate", "")),
        str(getattr(original, "pgcode", "")),
    }
    return bool(states & {"40001", "40P01", "55P03"}) or any(
        word in str(exc).lower() for word in ("locked", "busy")
    )


async def _arkade_backing_msat(account_id: str) -> int:
    """Read public spendable backing before entering the reservation transaction."""
    evidence = await fetch_arkade_indexer_vtxos(account_id, spendable_only=True)
    unique_vtxos: dict[tuple[str, int], ArkadeIndexerVtxo] = {}
    for vtxo in evidence:
        key = (vtxo.txid, vtxo.vout)
        if key in unique_vtxos and unique_vtxos[key] != vtxo:
            raise ArkadeOutgoingError("ARKADE_INDEXER_INVALID_RESPONSE")
        unique_vtxos[key] = vtxo
    return sum(
        vtxo.amount_sat * 1000
        for vtxo in unique_vtxos.values()
        if _is_spendable_vtxo(vtxo)
    )


async def reserve_arkade_outgoing_intent(  # noqa: C901
    account_id: str,
    intent: ArkadeOutgoingIntent,
    conn: Connection | None = None,
    *,
    receiver_account_id: str | None = None,
    receiver_native_request_id: str | None = None,
) -> tuple[ArkadeOutgoingIntent, Payment]:
    """Reserve one logical-wallet Arkade outgoing payment atomically."""
    if settings.lnbits_effective_installation_mode != "arkade_noncustodial":
        raise ArkadeOutgoingError("ARKADE_OUTGOING_UNAVAILABLE")
    if intent.account_id != account_id:
        raise ArkadeOutgoingError("ARKADE_OUTGOING_ACCOUNT_MISMATCH")
    if (
        intent.status != "reserved"
        or intent.destination_kind != "arkade_address"
        or intent.max_fee_msat != 0
    ):
        raise ArkadeOutgoingError("ARKADE_OUTGOING_INVALID_REQUEST")
    if (conn or db).type == SQLITE:
        intent = intent.copy(
            update={"expires_at": intent.expires_at.replace(microsecond=0)}
        )
    if (receiver_account_id is None) != (receiver_native_request_id is None):
        raise ArkadeOutgoingError("ARKADE_TRANSFER_RECEIVER_INVALID")
    if receiver_account_id == account_id:
        raise ArkadeOutgoingError("ARKADE_TRANSFER_RECEIVER_INVALID")
    binding = await get_arkade_binding(account_id, conn=conn)
    if not binding or binding.state != "ready":
        raise ArkadeOutgoingError("ARKADE_ENROLLMENT_REQUIRED")
    if intent.destination_kind == "arkade_address":
        try:
            decode_arkade_address_script(
                intent.destination,
                binding.server_pubkey,
                ARKADE_HRPS[binding.network],
            )
        except (ArkadeReceiveError, KeyError):
            raise ArkadeOutgoingError("ARKADE_OUTGOING_OUTPUT_INVALID") from None

    try:
        existing_intent = await get_arkade_outgoing_intent(intent.intent_id, conn=conn)
        existing_payment = await get_payment_by_native_id(intent.intent_id, conn=conn)
    except OperationalError as exc:
        if _is_database_busy(exc):
            raise ArkadeOutgoingError("ARKADE_OUTGOING_BUSY") from None
        raise
    if existing_intent or existing_payment:
        return _existing_outgoing_pair(intent, existing_intent, existing_payment)

    # The public observation must not share the reservation transaction.
    backing_msat = await _arkade_backing_msat(account_id)

    try:
        async with db.reuse_conn(conn) if conn else db.connect() as database:
            async with database.transaction():
                return await _reserve_arkade_outgoing_intent(
                    account_id,
                    intent,
                    backing_msat,
                    database,
                    receiver_account_id=receiver_account_id,
                    receiver_native_request_id=receiver_native_request_id,
                )
    except OperationalError as exc:
        if _is_database_busy(exc):
            raise ArkadeOutgoingError("ARKADE_OUTGOING_BUSY") from None
        raise


async def _reserve_arkade_outgoing_intent(  # noqa: C901
    account_id: str,
    intent: ArkadeOutgoingIntent,
    backing_msat: int,
    conn: Connection,
    *,
    receiver_account_id: str | None = None,
    receiver_native_request_id: str | None = None,
) -> tuple[ArkadeOutgoingIntent, Payment]:
    binding_accounts = {account_id}
    if receiver_account_id:
        binding_accounts.add(receiver_account_id)
    for binding_account_id in sorted(binding_accounts):
        await conn.execute(
            "UPDATE arkade_account_bindings SET account_id = account_id "
            "WHERE account_id = :account_id",
            {"account_id": binding_account_id},
        )
    binding = await get_arkade_binding(account_id, conn=conn)
    if not binding or binding.state != "ready":
        raise ArkadeOutgoingError("ARKADE_ENROLLMENT_REQUIRED")
    receiver_request = None
    if receiver_account_id and receiver_native_request_id:
        receiver_binding = await get_arkade_binding(receiver_account_id, conn=conn)
        if not receiver_binding or receiver_binding.state != "ready":
            raise ArkadeOutgoingError("ARKADE_TRANSFER_RECEIVER_INVALID")
        await conn.execute(
            "UPDATE arkade_receive_requests "
            "SET native_request_id = native_request_id "
            "WHERE native_request_id = :native_request_id "
            "AND account_id = :account_id",
            {
                "native_request_id": receiver_native_request_id,
                "account_id": receiver_account_id,
            },
        )
        receiver_request = await get_arkade_receive_request(
            receiver_native_request_id, conn=conn
        )
        if (
            not receiver_request
            or receiver_request.account_id != receiver_account_id
            or receiver_request.native_request_id != receiver_native_request_id
        ):
            raise ArkadeOutgoingError("ARKADE_TRANSFER_RECEIVER_INVALID")
    # Deliberately not gated on the account's reconciliation flag: solvency is
    # enforced by the backing-deficit check below, so a flagged account whose
    # spendable VTXOs still cover its obligations must stay able to pay.
    wallet = await get_wallet(intent.wallet_id, conn=conn)
    if not wallet or wallet.id != intent.wallet_id or wallet.user != account_id:
        raise ArkadeOutgoingError("ARKADE_WALLET_NOT_OWNED")
    if not wallet.can_send_payments:
        raise ArkadeOutgoingError("ARKADE_OUTGOING_NOT_ALLOWED")

    existing_intent = await get_arkade_outgoing_intent(intent.intent_id, conn=conn)
    existing_payment = await get_payment_by_native_id(intent.intent_id, conn=conn)
    if existing_intent:
        return _existing_outgoing_pair(intent, existing_intent, existing_payment)
    if existing_payment:
        raise ArkadeOutgoingError("ARKADE_OUTGOING_CORRUPT")

    if receiver_request:
        receiver_payment = await get_payment_by_native_id(
            receiver_request.native_request_id, conn=conn
        )
        expected_amount = receiver_request.amount_sat * 1000
        if (
            receiver_request.state != "acknowledged"
            or receiver_request.expires_at <= datetime.now(timezone.utc)
            or not receiver_request.address
            or receiver_request.address != intent.destination
            or intent.amount_msat != expected_amount
            or not receiver_payment
            or receiver_payment.protocol != "arkade"
            or receiver_payment.native_id != receiver_request.native_request_id
            or receiver_payment.wallet_id != receiver_request.wallet_id
            or receiver_payment.amount != expected_amount
            or receiver_payment.fee != 0
            or receiver_payment.arkade_address != receiver_request.address
            or receiver_payment.status != PaymentState.PENDING.value
        ):
            raise ArkadeOutgoingError("ARKADE_TRANSFER_RECEIVER_INVALID")

    # A Lightning intent is funded with invoice amount + solver spread and the
    # spread is charged to the linked payment on settlement, so a wallet must
    # hold the whole funded amount of this intent on top of the fee reserves it
    # already committed. The balances view (m025/m054) debits the principals of
    # its open intents but not their fee caps, so subtracting those reserves is
    # what stops one coin pool from backing two sends at once.
    obligations = await conn.fetchone(
        "SELECT COALESCE(SUM(max_fee_msat), 0) AS fees_msat "
        "FROM arkade_outgoing_intents "
        "WHERE wallet_id = :wallet_id "
        "AND status IN ('reserved', 'quote_ready', 'submitted', 'disputed')",
        {"wallet_id": intent.wallet_id},
    )
    obligation_msat = intent.amount_msat + intent.max_fee_msat
    settleable_msat = wallet.balance_msat - int(obligations["fees_msat"])
    if settleable_msat < obligation_msat:
        raise ArkadeOutgoingError("ARKADE_INSUFFICIENT_FUNDS")
    balances = await conn.fetchone(
        "SELECT COALESCE(SUM(b.balance), 0) AS balance_msat "
        "FROM wallets w LEFT JOIN balances b ON b.wallet_id = w.id "
        'WHERE w."user" = :account_id',
        {"account_id": account_id},
    )
    reservations = await conn.fetchone(
        "SELECT COALESCE(SUM(max_fee_msat), 0) AS fees_msat "
        "FROM arkade_outgoing_intents "
        "WHERE account_id = :account_id "
        "AND status IN ('reserved', 'quote_ready', 'submitted', 'disputed')",
        {"account_id": account_id},
    )
    # The balances view already nets every open intent's principal, so adding
    # principals again - including this intent's - would count them twice and
    # refuse every exactly backed account, which is the L5 blocker. Only the
    # outstanding fee reserves are still unspent, and the per-wallet check above
    # already proved this wallet holds its own principal and fee.
    gross_obligations_msat = int(balances["balance_msat"]) + int(
        reservations["fees_msat"]
    )
    if gross_obligations_msat > backing_msat:
        raise ArkadeOutgoingError("ARKADE_BACKING_DEFICIT")

    created_intent = await create_arkade_outgoing_intent(intent, conn=conn)
    payment = await create_payment(
        None,
        CreatePayment(
            wallet_id=intent.wallet_id,
            amount_msat=-intent.amount_msat,
            memo="Arkade outgoing payment",
            protocol="arkade",
            native_id=intent.intent_id,
            arkade_address=intent.destination,
        ),
        status=PaymentState.PENDING,
        conn=conn,
    )
    return created_intent, payment


async def reserve_arkade_lightning_intent(  # noqa: C901
    account_id: str,
    wallet_id: str,
    quote: ArkadeLightningQuoteInput,
    conn: Connection | None = None,
    *,
    idempotency_key: str,
) -> tuple[ArkadeOutgoingIntent, Payment]:
    """Validate a browser quote and atomically reserve its quote-ready intent."""
    if settings.lnbits_effective_installation_mode != "arkade_noncustodial":
        raise ArkadeOutgoingError("ARKADE_OUTGOING_UNAVAILABLE")

    now = datetime.now(timezone.utc)
    try:
        invoice = bolt11.decode(quote.bolt11)
        invoice_amount_msat = int(invoice.amount_msat or 0)
        invoice_payment_hash = invoice.payment_hash.lower()
    except Exception:
        raise ArkadeOutgoingError("ARKADE_OUTGOING_INVALID_REQUEST") from None
    if invoice_amount_msat <= 0 or invoice_amount_msat % 1000:
        raise ArkadeOutgoingError("ARKADE_OUTGOING_AMOUNT_INVALID")
    invoice_amount_sat = invoice_amount_msat // 1000
    if not (
        LIGHTNING_MIN_QUOTE_AMOUNT_SAT
        <= invoice_amount_sat
        <= LIGHTNING_MAX_QUOTE_AMOUNT_SAT
    ):
        raise ArkadeOutgoingError("ARKADE_OUTGOING_AMOUNT_INVALID")
    if quote.payment_hash != invoice_payment_hash:
        raise ArkadeOutgoingError("ARKADE_OUTGOING_OUTPUT_INVALID")
    if quote.amount_msat is not None and quote.amount_msat != invoice_amount_msat:
        raise ArkadeOutgoingError("ARKADE_TRANSFER_AMOUNT_CONFLICT")
    if quote.quote_pair != LIGHTNING_QUOTE_PAIR:
        raise ArkadeOutgoingError("ARKADE_OUTGOING_OUTPUT_INVALID")
    if quote.quote_to_amount_sat != invoice_amount_sat:
        raise ArkadeOutgoingError("ARKADE_TRANSFER_AMOUNT_CONFLICT")
    if quote.quote_from_amount_sat < quote.quote_to_amount_sat:
        raise ArkadeOutgoingError("ARKADE_OUTGOING_INVALID_REQUEST")
    quote_fee_msat = (quote.quote_from_amount_sat - quote.quote_to_amount_sat) * 1000
    # The authenticated caller chooses the fee cap; reserve it in full.
    if (
        quote.max_fee_msat > LIGHTNING_MAX_QUOTE_AMOUNT_SAT * 1000
        or quote_fee_msat > quote.max_fee_msat
    ):
        raise ArkadeOutgoingError("ARKADE_OUTGOING_INVALID_REQUEST")

    quote_valid_until = quote.quote_valid_until
    if quote_valid_until.tzinfo is None:
        quote_valid_until = quote_valid_until.replace(tzinfo=timezone.utc)
    else:
        quote_valid_until = quote_valid_until.astimezone(timezone.utc)
    if (conn or db).type == SQLITE:
        quote_valid_until = quote_valid_until.replace(microsecond=0)

    if not re.fullmatch(r"[0-9a-f]{32}", idempotency_key):
        raise ArkadeOutgoingError("ARKADE_OUTGOING_INVALID_REQUEST")
    intent_id = hashlib.sha256(
        f"lnbits-arkade-lightning-v1:{account_id}:{idempotency_key}".encode()
    ).hexdigest()[:32]
    existing = await get_arkade_outgoing_intent(intent_id, conn=conn)
    expires_at = existing.expires_at if existing else now + timedelta(minutes=10)
    intent = ArkadeOutgoingIntent(
        intent_id=intent_id,
        account_id=account_id,
        wallet_id=wallet_id,
        amount_msat=invoice_amount_msat,
        max_fee_msat=quote.max_fee_msat,
        destination=quote.bolt11,
        destination_kind="lightning",
        bolt11=quote.bolt11,
        payment_hash=quote.payment_hash,
        quote_pair=quote.quote_pair,
        quote_from_amount_sat=quote.quote_from_amount_sat,
        quote_to_amount_sat=quote.quote_to_amount_sat,
        quote_valid_until=quote_valid_until,
        refund_locktime=quote.refund_locktime,
        solver_pubkey=quote.solver_pubkey,
        swap_rfq_id=quote.swap_rfq_id,
        lockup_address=quote.lockup_address,
        expires_at=expires_at,
    )
    if existing:
        # A replay returns its recorded pair. The ~30 s solver quote window and
        # the invoice expiry gate new reservations only; re-validating them here
        # refused every replay after the window, and a settled send could never
        # be replayed at all.
        return _existing_outgoing_pair(
            intent,
            existing,
            await get_payment_by_native_id(intent_id, conn=conn),
        )
    if invoice.expiry_time <= int(now.timestamp()):
        raise ArkadeOutgoingError("ARKADE_OUTGOING_EXPIRED")
    if quote_valid_until <= now:
        raise ArkadeOutgoingError("ARKADE_OUTGOING_EXPIRED")
    if quote.refund_locktime < int(now.timestamp()) + LIGHTNING_REFUND_HEADROOM_SECONDS:
        raise ArkadeOutgoingError("ARKADE_OUTGOING_OUTPUT_INVALID")
    try:
        backing_msat = await _arkade_backing_msat(account_id)
        async with db.reuse_conn(conn) if conn else db.connect() as database:
            async with database.transaction():
                reserved, payment = await _reserve_arkade_outgoing_intent(
                    account_id, intent, backing_msat, database
                )
                if reserved.status == "reserved":
                    marked = await mark_arkade_outgoing_intent_quote_ready(
                        intent_id,
                        bolt11=quote.bolt11,
                        payment_hash=quote.payment_hash,
                        quote_pair=quote.quote_pair,
                        quote_from_amount_sat=quote.quote_from_amount_sat,
                        quote_to_amount_sat=quote.quote_to_amount_sat,
                        quote_valid_until=quote_valid_until,
                        refund_locktime=quote.refund_locktime,
                        solver_pubkey=quote.solver_pubkey,
                        swap_rfq_id=quote.swap_rfq_id,
                        lockup_address=quote.lockup_address,
                        conn=database,
                    )
                    if not marked:
                        raise ArkadeOutgoingError(
                            "ARKADE_OUTGOING_IDEMPOTENCY_CONFLICT"
                        )
                    accepted = await get_arkade_outgoing_intent(
                        intent_id, conn=database
                    )
                    if not accepted:
                        raise ArkadeOutgoingError("ARKADE_OUTGOING_CORRUPT")
                    reserved = accepted
                return reserved, payment
    except IntegrityError:
        raise ArkadeOutgoingError("ARKADE_OUTGOING_IDEMPOTENCY_CONFLICT") from None
    except OperationalError as exc:
        if _is_database_busy(exc):
            raise ArkadeOutgoingError("ARKADE_OUTGOING_BUSY") from None
        raise


async def submit_arkade_lightning_intent(  # noqa: C901
    account_id: str,
    intent_id: str,
    funding: ArkadeLightningFundingEvidence,
    conn: Connection | None = None,
) -> ArkadeOutgoingIntentResponse:
    """Record browser funding and CAS a Lightning intent to submitted."""
    if settings.lnbits_effective_installation_mode != "arkade_noncustodial":
        raise ArkadeOutgoingError("ARKADE_OUTGOING_UNAVAILABLE")
    if not funding.sender_pubkey or not funding.refund_pk_script:
        raise ArkadeOutgoingError("ARKADE_OUTGOING_REFUND_BINDING_REQUIRED")

    try:
        intent = await get_arkade_outgoing_intent(intent_id, conn=conn)
        if not intent or intent.account_id != account_id:
            raise ArkadeOutgoingError("ARKADE_OUTGOING_NOT_FOUND")
        binding = await get_arkade_binding(account_id, conn=conn)
        if not binding or binding.state != "ready":
            raise ArkadeOutgoingError("ARKADE_ENROLLMENT_REQUIRED")
        if intent.destination_kind != "lightning":
            raise ArkadeOutgoingError("ARKADE_INTENT_INVALID_TRANSITION")
        if intent.status == "submitted":
            if (
                intent.arkade_txid != funding.ark_txid
                or intent.lockup_address != funding.lockup_address
                or intent.swap_rfq_id != funding.swap_rfq_id
                or intent.solver_pubkey != funding.solver_pubkey
                or intent.sender_pubkey != funding.sender_pubkey
                or intent.refund_pk_script != funding.refund_pk_script
            ):
                raise ArkadeOutgoingError("ARKADE_OUTGOING_IDEMPOTENCY_CONFLICT")
            return _outgoing_response(
                intent,
                binding,
                await get_arkade_outgoing_intent_inputs(intent_id, conn=conn),
            )
        if intent.status != "quote_ready":
            raise ArkadeOutgoingError("ARKADE_INTENT_INVALID_TRANSITION")
        payment = await get_payment_by_native_id(intent_id, conn=conn)
        if (
            not payment
            or not _outgoing_payment_matches(payment, intent)
            or payment.status != PaymentState.PENDING.value
        ):
            raise ArkadeOutgoingError("ARKADE_OUTGOING_CORRUPT")
        lockup_address = intent.lockup_address
        if (
            lockup_address is None
            or lockup_address != funding.lockup_address
            or intent.swap_rfq_id != funding.swap_rfq_id
            or intent.solver_pubkey != funding.solver_pubkey
        ):
            raise ArkadeOutgoingError("ARKADE_OUTGOING_OUTPUT_CONFLICT")
        try:
            lockup_script = decode_arkade_address_script(
                lockup_address,
                binding.server_pubkey,
                ARKADE_HRPS[binding.network],
            )
        except (ArkadeReceiveError, KeyError):
            raise ArkadeOutgoingError("ARKADE_OUTGOING_OUTPUT_INVALID") from None
        try:
            lockup_evidence = await fetch_arkade_indexer_vtxos(
                account_id,
                conn=conn,
                spendable_only=False,
                scripts=[lockup_script],
            )
        except ArkadeReceiveError as exc:
            raise _authorize_indexer_error(exc) from None
        # The lockup's SPEND state does not gate recording the funding. A
        # browser can die between funding and submit, and by the time it
        # retries the solver may already have claimed the lockup; a claimed
        # VTXO is spent, so requiring it to be spendable made that funding
        # unreportable for good. The outpoint, script and amount are the
        # identity here; what the spend MEANS is decided from public evidence
        # by `reconcile_arkade_lightning_intent`, which is what turns a
        # claimed lockup into `settled` and a returned one into `refunded`.
        matching_lockups = [
            vtxo
            for vtxo in lockup_evidence
            if vtxo.txid == funding.ark_txid
            and vtxo.script.lower() == lockup_script
            and vtxo.amount_sat == intent.quote_from_amount_sat
        ]
        if len(matching_lockups) != 1:
            raise ArkadeOutgoingError("ARKADE_OUTGOING_INDEXER_UNAVAILABLE")
        async with db.reuse_conn(conn) if conn else db.connect() as database:
            async with database.transaction():
                intent = await get_arkade_outgoing_intent(intent_id, conn=database)
                if not intent or intent.account_id != account_id:
                    raise ArkadeOutgoingError("ARKADE_OUTGOING_NOT_FOUND")
                binding = await get_arkade_binding(account_id, conn=database)
                if not binding or binding.state != "ready":
                    raise ArkadeOutgoingError("ARKADE_ENROLLMENT_REQUIRED")
                if intent.destination_kind != "lightning":
                    raise ArkadeOutgoingError("ARKADE_INTENT_INVALID_TRANSITION")
                if intent.status == "submitted":
                    if (
                        intent.arkade_txid != funding.ark_txid
                        or intent.lockup_address != funding.lockup_address
                        or intent.swap_rfq_id != funding.swap_rfq_id
                        or intent.solver_pubkey != funding.solver_pubkey
                        or intent.sender_pubkey != funding.sender_pubkey
                        or intent.refund_pk_script != funding.refund_pk_script
                    ):
                        raise ArkadeOutgoingError(
                            "ARKADE_OUTGOING_IDEMPOTENCY_CONFLICT"
                        )
                    return _outgoing_response(
                        intent,
                        binding,
                        await get_arkade_outgoing_intent_inputs(
                            intent_id, conn=database
                        ),
                    )
                if intent.status != "quote_ready":
                    raise ArkadeOutgoingError("ARKADE_INTENT_INVALID_TRANSITION")
                payment = await get_payment_by_native_id(intent_id, conn=database)
                if (
                    not payment
                    or not _outgoing_payment_matches(payment, intent)
                    or payment.status != PaymentState.PENDING.value
                ):
                    raise ArkadeOutgoingError("ARKADE_OUTGOING_CORRUPT")
                try:
                    submitted = await submit_arkade_lightning_intent_crud(
                        intent_id,
                        funding.ark_txid,
                        lockup_address=funding.lockup_address,
                        swap_rfq_id=funding.swap_rfq_id,
                        solver_pubkey=funding.solver_pubkey,
                        sender_pubkey=funding.sender_pubkey,
                        refund_pk_script=funding.refund_pk_script,
                        conn=database,
                    )
                except ValueError as exc:
                    code = str(exc)
                    if code in {
                        "ARKADE_OUTGOING_OUTPUT_CONFLICT",
                        "ARKADE_INTENT_INVALID_TRANSITION",
                        "ARKADE_TRANSACTION_ID_INVALID",
                    }:
                        raise ArkadeOutgoingError(code) from None
                    raise ArkadeOutgoingError("ARKADE_OUTGOING_CORRUPT") from None
                if not submitted:
                    raise ArkadeOutgoingError("ARKADE_INTENT_INVALID_TRANSITION")
                try:
                    await record_arkade_lightning_funding_input(
                        intent_id,
                        ArkadeOutgoingIntentInput(
                            intent_id=intent_id,
                            txid=matching_lockups[0].txid,
                            vout=matching_lockups[0].vout,
                            amount_sat=matching_lockups[0].amount_sat,
                        ),
                        database,
                    )
                except ValueError as exc:
                    raise ArkadeOutgoingError(str(exc)) from None
                intent = await get_arkade_outgoing_intent(intent_id, conn=database)
                if not intent or intent.status != "submitted":
                    raise ArkadeOutgoingError("ARKADE_OUTGOING_CORRUPT")
                return _outgoing_response(
                    intent,
                    binding,
                    await get_arkade_outgoing_intent_inputs(intent_id, conn=database),
                )
    except OperationalError as exc:
        if _is_database_busy(exc):
            raise ArkadeOutgoingError("ARKADE_OUTGOING_BUSY") from None
        raise


def _outgoing_intent_matches(
    current: ArkadeOutgoingIntent, requested: ArkadeOutgoingIntent
) -> bool:
    return all(
        getattr(current, field) == getattr(requested, field)
        for field in (
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
    )


def _existing_outgoing_pair(
    intent: ArkadeOutgoingIntent,
    existing_intent: ArkadeOutgoingIntent | None,
    existing_payment: Payment | None,
) -> tuple[ArkadeOutgoingIntent, Payment]:
    if not existing_intent:
        raise ArkadeOutgoingError("ARKADE_OUTGOING_CORRUPT")
    if not _outgoing_intent_matches(existing_intent, intent):
        raise ArkadeOutgoingError("ARKADE_OUTGOING_IDEMPOTENCY_CONFLICT")
    # A settled Lightning payment carries the solver spread as its fee; every
    # other open state still holds the pending zero.
    expected_fee_msat = 0
    if existing_intent.status == "settled":
        if existing_intent.actual_fee_msat is None:
            raise ArkadeOutgoingError("ARKADE_OUTGOING_CORRUPT")
        expected_fee_msat = -existing_intent.actual_fee_msat
    if not existing_payment or not _outgoing_payment_matches(
        existing_payment, intent, expected_fee_msat=expected_fee_msat
    ):
        raise ArkadeOutgoingError("ARKADE_OUTGOING_CORRUPT")
    expected_status = {
        "reserved": PaymentState.PENDING.value,
        "quote_ready": PaymentState.PENDING.value,
        "submitted": PaymentState.PENDING.value,
        "disputed": PaymentState.PENDING.value,
        "released": PaymentState.FAILED.value,
        "settled": PaymentState.SUCCESS.value,
        "refunded": PaymentState.FAILED.value,
        "failed": PaymentState.FAILED.value,
    }[existing_intent.status]
    if existing_payment.status != expected_status:
        raise ArkadeOutgoingError("ARKADE_OUTGOING_CORRUPT")
    return existing_intent, existing_payment


def _outgoing_payment_matches(
    payment: Payment, intent: ArkadeOutgoingIntent, *, expected_fee_msat: int = 0
) -> bool:
    return (
        payment.protocol == "arkade"
        and payment.native_id == intent.intent_id
        and payment.wallet_id == intent.wallet_id
        and payment.amount == -intent.amount_msat
        and payment.fee == expected_fee_msat
        and payment.arkade_address == intent.destination
        and payment.checking_id is None
        and payment.payment_hash is None
        and payment.bolt11 is None
    )


async def release_arkade_outgoing_payment(
    account_id: str, intent_id: str, conn: Connection | None = None
) -> bool:
    """Release a reserved intent and refund its linked pending payment."""
    try:
        async with db.reuse_conn(conn) if conn else db.connect() as database:
            async with database.transaction():
                intent = await get_arkade_outgoing_intent(intent_id, conn=database)
                if not intent or intent.account_id != account_id:
                    raise ArkadeOutgoingError("ARKADE_OUTGOING_NOT_FOUND")
                payment = await get_payment_by_native_id(intent_id, conn=database)
                if not payment:
                    raise ArkadeOutgoingError("ARKADE_OUTGOING_CORRUPT")
                if not _outgoing_payment_matches(payment, intent):
                    raise ArkadeOutgoingError("ARKADE_OUTGOING_CORRUPT")
                if (
                    intent.status == "released"
                    and payment.status == PaymentState.FAILED.value
                ):
                    return False
                # A quote-ready intent is prepared but not funded, exactly like a
                # reservation, so both can still be released. A swap that already
                # carries funding evidence must never be released: its coins are
                # committed and only settlement, refund or dispute may resolve it.
                funded = bool(
                    intent.arkade_txid
                    or intent.submitted_at
                    or intent.change_script
                    or intent.change_amount_sat
                )
                if (
                    intent.status not in {"reserved", "quote_ready"}
                    or funded
                    or payment.status != PaymentState.PENDING.value
                ):
                    raise ArkadeOutgoingError("ARKADE_INTENT_INVALID_TRANSITION")
                released = await release_arkade_outgoing_intent(
                    intent_id, database, from_status=intent.status
                )
                if released:
                    payment.status = PaymentState.FAILED.value
                    await update_payment(payment, conn=database)
                return released
    except OperationalError as exc:
        if _is_database_busy(exc):
            raise ArkadeOutgoingError("ARKADE_OUTGOING_BUSY") from None
        raise


async def expire_arkade_outgoing_reservations(conn: Connection) -> int:
    """Release unfunded reservations past their TTL.

    A funded swap owns its lockup and is settled, refunded or disputed from
    evidence; only an intent that never reported funding can be released.
    Requires an active transaction.
    """
    released_count = 0
    for intent in await get_expired_arkade_outgoing_reservations(conn=conn):
        released = await release_arkade_outgoing_intent(
            intent.intent_id, conn, from_status=intent.status
        )
        if not released:
            continue
        released_count += 1
        payment = await get_payment_by_native_id(intent.intent_id, conn=conn)
        if payment:
            await compare_and_set_arkade_payment_failed(payment, conn=conn)
    return released_count


def _outgoing_response(
    intent: ArkadeOutgoingIntent,
    binding: ArkadeAccountBinding,
    inputs: list[ArkadeOutgoingIntentInput],
) -> ArkadeOutgoingIntentResponse:
    return ArkadeOutgoingIntentResponse(
        intent_id=intent.intent_id,
        account_id=intent.account_id,
        wallet_id=intent.wallet_id,
        amount_msat=intent.amount_msat,
        max_fee_msat=intent.max_fee_msat,
        destination=intent.destination,
        bolt11=intent.bolt11,
        payment_hash=intent.payment_hash,
        quote_pair=intent.quote_pair,
        quote_from_amount_sat=intent.quote_from_amount_sat,
        quote_to_amount_sat=intent.quote_to_amount_sat,
        quote_valid_until=intent.quote_valid_until,
        refund_locktime=intent.refund_locktime,
        solver_pubkey=intent.solver_pubkey,
        swap_rfq_id=intent.swap_rfq_id,
        lockup_address=intent.lockup_address,
        arkade_txid=intent.arkade_txid,
        destination_kind=intent.destination_kind,
        status=intent.status,
        expires_at=intent.expires_at,
        network=binding.network,
        server_url=binding.server_url,
        server_pubkey=binding.server_pubkey,
        inputs=sorted(inputs, key=lambda item: (item.txid, item.vout)),
        destination_script=intent.destination_script,
        change_index=intent.change_index,
        change_script=intent.change_script,
        change_amount_sat=intent.change_amount_sat,
        failed_at=intent.failed_at,
        failure_reason=intent.failure_reason,
    )


async def get_arkade_outgoing_intent_for_account(
    account_id: str, intent_id: str, conn: Connection | None = None
) -> ArkadeOutgoingIntentResponse:
    if settings.lnbits_effective_installation_mode != "arkade_noncustodial":
        raise ArkadeOutgoingError("ARKADE_OUTGOING_UNAVAILABLE")
    intent = await get_arkade_outgoing_intent(intent_id, conn=conn)
    if not intent or intent.account_id != account_id:
        raise ArkadeOutgoingError("ARKADE_OUTGOING_NOT_FOUND")
    binding = await get_arkade_binding(account_id, conn=conn)
    if not binding or binding.state != "ready":
        raise ArkadeOutgoingError("ARKADE_ENROLLMENT_REQUIRED")
    inputs = await get_arkade_outgoing_intent_inputs(intent_id, conn=conn)
    return _outgoing_response(intent, binding, inputs)


async def list_arkade_submitted_outgoing_intents(
    account_id: str, limit: int = 32
) -> list[ArkadeOutgoingIntentResponse]:
    if settings.lnbits_effective_installation_mode != "arkade_noncustodial":
        raise ArkadeOutgoingError("ARKADE_OUTGOING_UNAVAILABLE")
    binding = await get_arkade_binding(account_id)
    if not binding or binding.state != "ready":
        raise ArkadeOutgoingError("ARKADE_ENROLLMENT_REQUIRED")
    intents = await get_arkade_submitted_outgoing_intents(
        limit=limit, account_id=account_id
    )
    return [
        _outgoing_response(
            intent,
            binding,
            await get_arkade_outgoing_intent_inputs(intent.intent_id),
        )
        for intent in intents
        if intent.destination_kind != "lightning"
    ]


def _outgoing_input_key(item: ArkadeOutgoingSelectedInput) -> tuple[str, int]:
    return item.txid, item.vout


def _outgoing_claim_key(item: ArkadeOutgoingIntentInput) -> tuple[str, int]:
    return item.txid, item.vout


def _authorize_indexer_error(exc: ArkadeReceiveError) -> ArkadeOutgoingError:
    code = str(exc)
    if code == "ARKADE_INDEXER_INVALID_RESPONSE":
        return ArkadeOutgoingError("ARKADE_OUTGOING_INDEXER_INVALID")
    return ArkadeOutgoingError("ARKADE_OUTGOING_INDEXER_UNAVAILABLE")


def _is_spendable_vtxo(vtxo: ArkadeIndexerVtxo) -> bool:
    return not (
        vtxo.is_spent
        or vtxo.is_swept
        or vtxo.is_unrolled
        or vtxo.settled_by
        or vtxo.expires_at_height is not None
        or (
            vtxo.expires_at is not None
            and vtxo.expires_at <= datetime.now(timezone.utc)
        )
    )


def _validate_outgoing_evidence(  # noqa: C901
    selected: list[ArkadeOutgoingSelectedInput],
    evidence: list[ArkadeIndexerVtxo],
    scripts: set[str],
    amount_msat: int,
    change_amount_sat: int | None = None,
) -> None:
    selected_by_key: dict[tuple[str, int], ArkadeOutgoingSelectedInput] = {}
    for item in selected:
        key = _outgoing_input_key(item)
        if key in selected_by_key:
            raise ArkadeOutgoingError("ARKADE_OUTGOING_INPUTS_INVALID")
        selected_by_key[key] = item

    observed: dict[tuple[str, int], ArkadeIndexerVtxo] = {}
    for vtxo in evidence:
        key = (vtxo.txid, vtxo.vout)
        if key in observed and observed[key] != vtxo:
            raise ArkadeOutgoingError("ARKADE_OUTGOING_INDEXER_INVALID")
        observed[key] = vtxo
    if set(selected_by_key) - set(observed):
        raise ArkadeOutgoingError("ARKADE_OUTGOING_INPUTS_MISSING")
    if set(observed) - set(selected_by_key):
        raise ArkadeOutgoingError("ARKADE_OUTGOING_INDEXER_INVALID")

    total_sat = 0
    for item in selected:
        vtxo = observed.get(_outgoing_input_key(item))
        if not vtxo:
            raise ArkadeOutgoingError("ARKADE_OUTGOING_INPUTS_MISSING")
        if vtxo.amount_sat != item.amount_sat:
            raise ArkadeOutgoingError("ARKADE_OUTGOING_INPUT_VALUE_MISMATCH")
        if not _is_spendable_vtxo(vtxo):
            raise ArkadeOutgoingError("ARKADE_OUTGOING_INPUT_UNAVAILABLE")
        if vtxo.script.lower() not in scripts:
            raise ArkadeOutgoingError("ARKADE_OUTGOING_INPUT_UNREGISTERED")
        total_sat += vtxo.amount_sat
    expected_sat = amount_msat // 1000 + (change_amount_sat or 0)
    if total_sat < expected_sat:
        raise ArkadeOutgoingError("ARKADE_INSUFFICIENT_FUNDS")
    if total_sat > expected_sat:
        raise ArkadeOutgoingError("ARKADE_OUTGOING_OUTPUT_INVALID")


def _same_outgoing_outputs(
    intent: ArkadeOutgoingIntent,
    destination_script: str,
    change: ArkadeOutgoingChangeCommitment | None,
) -> bool:
    return intent.destination_script == destination_script and (
        (
            change is None
            and intent.change_index is None
            and intent.change_script is None
            and intent.change_amount_sat is None
        )
        or (
            change is not None
            and intent.change_index == change.index
            and intent.change_script == change.script.lower()
            and intent.change_amount_sat == change.amount_sat
        )
    )


def _validate_outgoing_outputs(
    intent: ArkadeOutgoingIntent,
    binding: ArkadeAccountBinding,
    destination_script: str,
    change: ArkadeOutgoingChangeCommitment | None,
) -> None:
    if not binding.identity_descriptor or not binding.identity_xonly_pubkey:
        raise ArkadeOutgoingError("ARKADE_DESCRIPTOR_REENROLLMENT_REQUIRED")
    try:
        validate_arkade_identity_descriptor(
            binding.identity_descriptor,
            binding.identity_xonly_pubkey,
            binding.network,
        )
        validate_arkade_address_script(
            intent.destination,
            destination_script.lower(),
            binding.server_pubkey,
            ARKADE_HRPS[binding.network],
        )
    except (ArkadeEnrollmentError, ArkadeReceiveError, KeyError):
        raise ArkadeOutgoingError("ARKADE_OUTGOING_OUTPUT_INVALID") from None
    if not change:
        return
    _validate_owned_change(binding, change)


def _validate_owned_change(
    binding: ArkadeAccountBinding, change: ArkadeOutgoingChangeCommitment
) -> None:
    try:
        if not binding.identity_descriptor:
            raise ValueError
        derived = (
            Descriptor.from_string(binding.identity_descriptor).derive(change.index).key
        )
        if not derived or derived.xonly().hex() != change.child_xonly_pubkey:
            raise ValueError
        validate_arkade_address_script(
            change.address,
            change.script.lower(),
            binding.server_pubkey,
            ARKADE_HRPS[binding.network],
        )
        verify_receive_exit_membership(
            ArkadeReceiveAcknowledgement.construct(
                child_xonly_pubkey=change.child_xonly_pubkey,
                script=change.script.lower(),
                exit_tapleaf=change.exit_tapleaf,
                exit_control_block=change.exit_control_block,
            )
        )
    except (AttributeError, EmbitError, TypeError, ValueError, ArkadeReceiveError):
        raise ArkadeOutgoingError("ARKADE_OUTGOING_OUTPUT_INVALID") from None


def _same_outgoing_inputs(
    requested: list[ArkadeOutgoingSelectedInput],
    claimed: list[ArkadeOutgoingIntentInput],
) -> bool:
    return sorted(
        (_outgoing_input_key(item), item.amount_sat) for item in requested
    ) == sorted((_outgoing_claim_key(item), item.amount_sat) for item in claimed)


async def authorize_arkade_outgoing(  # noqa: C901
    account_id: str,
    intent_id: str,
    selected: list[ArkadeOutgoingSelectedInput],
    conn: Connection | None = None,
    destination_script: str | None = None,
    change: ArkadeOutgoingChangeCommitment | None = None,
) -> ArkadeOutgoingIntentResponse:
    """Validate public VTXO evidence and CAS a reservation to submitted."""
    if settings.lnbits_effective_installation_mode != "arkade_noncustodial":
        raise ArkadeOutgoingError("ARKADE_OUTGOING_UNAVAILABLE")
    if not 1 <= len(selected) <= 100:
        raise ArkadeOutgoingError("ARKADE_OUTGOING_INPUTS_INVALID")

    try:
        intent = await get_arkade_outgoing_intent(intent_id, conn=conn)
        if not intent or intent.account_id != account_id:
            raise ArkadeOutgoingError("ARKADE_OUTGOING_NOT_FOUND")
        binding = await get_arkade_binding(account_id, conn=conn)
        if not binding or binding.state != "ready":
            raise ArkadeOutgoingError("ARKADE_ENROLLMENT_REQUIRED")
        if destination_script is None:
            raise ArkadeOutgoingError("ARKADE_OUTGOING_OUTPUT_INVALID")
        destination_script = destination_script.lower()
        _validate_outgoing_outputs(intent, binding, destination_script, change)
        payment = await get_payment_by_native_id(intent_id, conn=conn)
        claims = await get_arkade_outgoing_intent_inputs(intent_id, conn=conn)
        if intent.status == "submitted":
            if not payment or not _outgoing_payment_matches(payment, intent):
                raise ArkadeOutgoingError("ARKADE_OUTGOING_CORRUPT")
            if payment.status != PaymentState.PENDING.value:
                raise ArkadeOutgoingError("ARKADE_OUTGOING_CORRUPT")
            if not _same_outgoing_inputs(
                selected, claims
            ) or not _same_outgoing_outputs(intent, destination_script, change):
                raise ArkadeOutgoingError("ARKADE_OUTGOING_IDEMPOTENCY_CONFLICT")
            return _outgoing_response(intent, binding, claims)
        if intent.status != "reserved":
            raise ArkadeOutgoingError("ARKADE_INTENT_INVALID_TRANSITION")
        if intent.expires_at <= datetime.now(timezone.utc):
            raise ArkadeOutgoingError("ARKADE_OUTGOING_EXPIRED")
        if claims and not _same_outgoing_inputs(selected, claims):
            raise ArkadeOutgoingError("ARKADE_OUTGOING_IDEMPOTENCY_CONFLICT")
        if len({_outgoing_input_key(item) for item in selected}) != len(selected):
            raise ArkadeOutgoingError("ARKADE_OUTGOING_INPUTS_INVALID")

        receive_requests = await get_arkade_receive_requests(account_id, conn=conn)
        scripts = {
            request.script.lower() for request in receive_requests if request.script
        }
        # Verified change remains owned by this account after a native send.
        changes: list[dict[str, str]] = await (conn or db).fetchall(
            "SELECT change_script FROM arkade_outgoing_intents "
            "WHERE account_id = :account_id AND status = 'settled' "
            "AND change_script IS NOT NULL",
            {"account_id": account_id},
        )
        scripts.update(row["change_script"].lower() for row in changes)
        scripts.update(
            row["script"]
            for row in await maintenance_rows(account_id, conn)
            if row["state"] == "verified"
        )
        if not scripts:
            raise ArkadeOutgoingError("ARKADE_OUTGOING_INPUT_UNREGISTERED")
        try:
            evidence = await fetch_arkade_indexer_vtxos_for_outpoints(
                account_id, [_outgoing_input_key(item) for item in selected]
            )
        except ArkadeReceiveError as exc:
            raise _authorize_indexer_error(exc) from None
        _validate_outgoing_evidence(
            selected,
            evidence,
            scripts,
            intent.amount_msat,
            change.amount_sat if change else None,
        )

        async with db.reuse_conn(conn) if conn else db.connect() as database:
            async with database.transaction():
                await database.execute(
                    "UPDATE arkade_account_bindings SET account_id = account_id "
                    "WHERE account_id = :account_id AND state = 'ready'",
                    {"account_id": account_id},
                )
                current = await get_arkade_outgoing_intent(intent_id, conn=database)
                if not current or current.account_id != account_id:
                    raise ArkadeOutgoingError("ARKADE_OUTGOING_NOT_FOUND")
                current_binding = await get_arkade_binding(account_id, conn=database)
                if not current_binding or current_binding.state != "ready":
                    raise ArkadeOutgoingError("ARKADE_ENROLLMENT_REQUIRED")
                current_claims = await get_arkade_outgoing_intent_inputs(
                    intent_id, conn=database
                )
                current_payment = await get_payment_by_native_id(
                    intent_id, conn=database
                )
                if current.status == "submitted":
                    if not current_payment or not _outgoing_payment_matches(
                        current_payment, current
                    ):
                        raise ArkadeOutgoingError("ARKADE_OUTGOING_CORRUPT")
                    if current_payment.status != PaymentState.PENDING.value:
                        raise ArkadeOutgoingError("ARKADE_OUTGOING_CORRUPT")
                    if not _same_outgoing_inputs(
                        selected, current_claims
                    ) or not _same_outgoing_outputs(
                        current, destination_script, change
                    ):
                        raise ArkadeOutgoingError(
                            "ARKADE_OUTGOING_IDEMPOTENCY_CONFLICT"
                        )
                    return _outgoing_response(current, current_binding, current_claims)
                if current.status != "reserved":
                    raise ArkadeOutgoingError("ARKADE_INTENT_INVALID_TRANSITION")
                if current.expires_at <= datetime.now(timezone.utc):
                    raise ArkadeOutgoingError("ARKADE_OUTGOING_EXPIRED")
                if (
                    not current_payment
                    or not _outgoing_payment_matches(current_payment, current)
                    or current_payment.status != PaymentState.PENDING.value
                ):
                    raise ArkadeOutgoingError("ARKADE_OUTGOING_CORRUPT")
                if change:
                    collision = await database.fetchone(
                        "SELECT 1 FROM arkade_receive_requests "
                        "WHERE account_id = :account_id AND "
                        '(("index" = :change_index) OR script = :change_script) '
                        "AND script IS NOT NULL",
                        {
                            "account_id": account_id,
                            "change_index": change.index,
                            "change_script": change.script.lower(),
                        },
                    )
                    if collision:
                        raise ArkadeOutgoingError("ARKADE_OUTGOING_OUTPUT_CONFLICT")
                input_rows = [
                    ArkadeOutgoingIntentInput(
                        intent_id=intent_id,
                        txid=item.txid,
                        vout=item.vout,
                        amount_sat=item.amount_sat,
                    )
                    for item in selected
                ]
                try:
                    await authorize_arkade_outgoing_intent(
                        input_rows,
                        database,
                        destination_script=destination_script.lower(),
                        change_index=change.index if change else None,
                        change_script=change.script.lower() if change else None,
                        change_amount_sat=change.amount_sat if change else None,
                    )
                except ValueError as exc:
                    code = str(exc)
                    if code in {
                        "ARKADE_INPUT_ALREADY_CLAIMED",
                        "ARKADE_INTENT_MISMATCH",
                    }:
                        raise ArkadeOutgoingError(
                            "ARKADE_OUTGOING_INPUT_CONFLICT"
                        ) from None
                    if code == "ARKADE_INTENT_INVALID_TRANSITION":
                        raise ArkadeOutgoingError(code) from None
                    raise ArkadeOutgoingError("ARKADE_OUTGOING_CORRUPT") from None
                except IntegrityError:
                    raise ArkadeOutgoingError(
                        "ARKADE_OUTGOING_OUTPUT_CONFLICT"
                    ) from None
                submitted = await get_arkade_outgoing_intent(intent_id, conn=database)
                submitted_claims = await get_arkade_outgoing_intent_inputs(
                    intent_id, conn=database
                )
                if not submitted or submitted.status != "submitted":
                    raise ArkadeOutgoingError("ARKADE_INTENT_INVALID_TRANSITION")
                return _outgoing_response(submitted, current_binding, submitted_claims)
    except OperationalError as exc:
        if _is_database_busy(exc):
            raise ArkadeOutgoingError("ARKADE_OUTGOING_BUSY") from None
        raise


def canonical_enrollment_statement(
    *,
    account_id: str,
    enrollment_id: str,
    idempotency_key: str,
    nonce: str,
    expires_at: int,
    network: str,
    server_url: str,
    server_pubkey: str,
    identity_xonly_pubkey: str,
    identity_descriptor: str,
) -> str:
    values = {
        "account_id": account_id,
        "enrollment_id": enrollment_id,
        "idempotency_key": idempotency_key,
        "nonce": nonce,
        "expires_at": str(expires_at),
        "network": network,
        "server_url": server_url,
        "server_pubkey": server_pubkey,
        "identity_kind": IDENTITY_KIND,
        "identity_descriptor": identity_descriptor,
        "identity_xonly_pubkey": identity_xonly_pubkey,
        "backup_acknowledged": "1",
    }
    if not _ID.fullmatch(account_id) or not _ID.fullmatch(enrollment_id):
        raise ArkadeEnrollmentError("Invalid enrollment identifier.")
    if not _IDEMPOTENCY.fullmatch(idempotency_key):
        raise ArkadeEnrollmentError("Invalid idempotency key.")
    if not _HEX64.fullmatch(nonce) or not _HEX64.fullmatch(server_pubkey):
        raise ArkadeEnrollmentError("Invalid enrollment challenge.")
    if not _HEX64.fullmatch(identity_xonly_pubkey):
        raise ArkadeEnrollmentError("Invalid identity key.")
    if not isinstance(identity_descriptor, str) or not _IDENTITY_DESCRIPTOR.fullmatch(
        identity_descriptor
    ):
        raise ArkadeEnrollmentError("Invalid enrollment descriptor.")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,31}", network):
        raise ArkadeEnrollmentError("Invalid Arkade network.")
    if any("\n" in value or "\r" in value for value in values.values()):
        raise ArkadeEnrollmentError("Invalid enrollment statement.")
    try:
        "\n".join(values.values()).encode("ascii")
    except UnicodeEncodeError as exc:
        raise ArkadeEnrollmentError("Invalid enrollment statement.") from exc
    return "\n".join(
        [f"action={ENROLLMENT_ACTION}"] + [f"{k}={v}" for k, v in values.items()]
    )


def validate_arkade_identity_descriptor(
    identity_descriptor: str, identity_xonly_pubkey: str, network: str
) -> None:
    """Require the SDK's canonical BIP86 /0 wildcard and bind index zero."""
    match = _IDENTITY_DESCRIPTOR.fullmatch(identity_descriptor)
    expected_prefix = "xpub" if network == "bitcoin" else "tpub"
    expected_coin_type = "0" if network == "bitcoin" else "1"
    if (
        not match
        or match.group(1) != expected_coin_type
        or match.group(2) != expected_prefix
    ):
        raise ArkadeEnrollmentError("Invalid enrollment descriptor.")
    try:
        parsed = Descriptor.from_string(identity_descriptor)
        key = parsed.key
        expected_origin = [
            86 | 0x80000000,
            int(expected_coin_type) | 0x80000000,
            0x80000000,
        ]
        if (
            not parsed.is_taproot
            or parsed.miniscript is not None
            or parsed.taptree
            or key is None
            or not key.is_extended
            or key.is_private
            or key.key.depth != 3
            or key.origin is None
            or key.origin.derivation != expected_origin
            or str(key.allowed_derivation) != "/0/*"
        ):
            raise ArkadeEnrollmentError("Invalid enrollment descriptor.")
        derived_key = parsed.derive(0).key
        if derived_key is None:
            raise ArkadeEnrollmentError("Invalid enrollment descriptor.")
        derived = derived_key.xonly().hex()
    except (AttributeError, EmbitError, TypeError, ValueError):
        raise ArkadeEnrollmentError("Invalid enrollment descriptor.") from None
    if derived != identity_xonly_pubkey:
        raise ArkadeEnrollmentError("Invalid enrollment descriptor.")


def verify_enrollment_proof(
    statement: str, identity_xonly_pubkey: str, signature: str
) -> None:
    if not _HEX64.fullmatch(identity_xonly_pubkey) or not re.fullmatch(
        r"^[0-9a-f]{128}$", signature
    ):
        raise ArkadeEnrollmentError("Invalid enrollment proof.")
    try:
        public_key = PublicKeyXOnly(bytes.fromhex(identity_xonly_pubkey))
        valid = public_key.verify(
            bytes.fromhex(signature), hashlib.sha256(statement.encode("ascii")).digest()
        )
    except (ValueError, TypeError):
        valid = False
    if not valid:
        raise ArkadeEnrollmentError("Invalid enrollment proof.")


def _response(binding: ArkadeAccountBinding) -> ArkadeEnrollmentBindingResponse:
    if binding.idempotency_key is None:
        raise ArkadeEnrollmentError("Enrollment binding unavailable.")
    return ArkadeEnrollmentBindingResponse(
        account_id=binding.account_id,
        state=binding.state,
        enrollment_id=binding.enrollment_id,
        idempotency_key=binding.idempotency_key,
        network=binding.network,
        server_url=binding.server_url,
        server_pubkey=binding.server_pubkey,
        identity_xonly_pubkey=binding.identity_xonly_pubkey,
        identity_descriptor=binding.identity_descriptor,
        backup_acknowledged_at=binding.backup_acknowledged_at,
        created_at=binding.created_at,
        updated_at=binding.updated_at,
        ready_at=binding.ready_at,
    )


async def create_enrollment_challenge(  # noqa: C901
    account: Account, idempotency_key: str | None, conn: Connection | None = None
) -> ArkadeEnrollmentChallenge | ArkadeEnrollmentBindingResponse:
    if settings.lnbits_effective_installation_mode != "arkade_noncustodial":
        raise ArkadeEnrollmentError("Arkade enrollment is unavailable.")
    if not isinstance(idempotency_key, str) or not _IDEMPOTENCY.fullmatch(
        idempotency_key
    ):
        raise ArkadeEnrollmentError("Invalid idempotency key.")
    binding = await get_arkade_binding(account.id, conn=conn)
    if not binding:
        binding = await ensure_arkade_binding_for_existing_account(
            account.id, conn=conn
        )
    if not binding:
        raise ArkadeEnrollmentMigrationRequiredError(
            "Existing wallet requires explicit migration."
        )
    if binding.state == "ready":
        return _response(binding)

    now = datetime.now(timezone.utc)
    if (
        binding.idempotency_key == idempotency_key
        and binding.challenge_nonce
        and binding.challenge_expires_at
        and binding.challenge_expires_at > now
    ):
        return _challenge(binding)

    if (
        binding.challenge_expires_at
        and binding.challenge_expires_at > now
        and binding.idempotency_key != idempotency_key
    ):
        raise ArkadeEnrollmentError("Enrollment challenge already active.")

    enrollment_id = token_hex(16)
    expires_at = now + timedelta(seconds=CHALLENGE_TTL_SECONDS)
    nonce = token_hex(32)
    try:
        updated = await update_arkade_challenge(
            binding,
            enrollment_id=enrollment_id,
            idempotency_key=idempotency_key,
            nonce=nonce,
            expires_at=expires_at,
            old_idempotency_key=binding.idempotency_key,
            old_nonce=binding.challenge_nonce,
            old_expires_at=binding.challenge_expires_at,
            conn=conn,
        )
    except IntegrityError as exc:
        winner = await get_arkade_binding(account.id, conn=conn)
        if (
            winner
            and winner.state == "pending"
            and winner.idempotency_key == idempotency_key
            and winner.challenge_nonce
            and winner.challenge_expires_at
            and winner.challenge_expires_at > datetime.now(timezone.utc)
        ):
            return _challenge(winner)
        raise ArkadeEnrollmentError("Enrollment challenge already active.") from exc
    if not updated:
        winner = await get_arkade_binding(account.id, conn=conn)
        if (
            winner
            and winner.state == "pending"
            and winner.idempotency_key == idempotency_key
            and winner.challenge_nonce
            and winner.challenge_expires_at
            and winner.challenge_expires_at > datetime.now(timezone.utc)
        ):
            return _challenge(winner)
        raise ArkadeEnrollmentError("Enrollment challenge already active.")
    winner = await get_arkade_binding(account.id, conn=conn)
    if not winner:
        raise ArkadeEnrollmentError("Enrollment unavailable.")
    return _challenge(winner)


def _challenge(binding: ArkadeAccountBinding) -> ArkadeEnrollmentChallenge:
    if (
        binding.idempotency_key is None
        or not binding.challenge_nonce
        or not binding.challenge_expires_at
    ):
        raise ArkadeEnrollmentError("Enrollment challenge unavailable.")
    expires_at = int(binding.challenge_expires_at.timestamp())
    return ArkadeEnrollmentChallenge(
        account_id=binding.account_id,
        state="pending",
        enrollment_id=binding.enrollment_id,
        idempotency_key=binding.idempotency_key,
        nonce=binding.challenge_nonce,
        expires_at=expires_at,
        network=binding.network,
        server_url=binding.server_url,
        server_pubkey=binding.server_pubkey,
    )


async def complete_enrollment(
    account: Account,
    data: ArkadeEnrollmentCompletion,
    conn: Connection | None = None,
) -> ArkadeEnrollmentBindingResponse:
    if settings.lnbits_effective_installation_mode != "arkade_noncustodial":
        raise ArkadeEnrollmentError("Arkade enrollment is unavailable.")
    binding = await get_arkade_binding(account.id, conn=conn)
    if not binding:
        raise ArkadeEnrollmentError("Arkade enrollment is unavailable.")
    if binding.state == "ready":
        if (
            binding.enrollment_id != data.enrollment_id
            or binding.idempotency_key != data.idempotency_key
            or binding.identity_xonly_pubkey != data.identity_xonly_pubkey
            or not binding.identity_descriptor
            or binding.identity_descriptor != data.identity_descriptor
        ):
            raise ArkadeEnrollmentError("Enrollment binding mismatch.")
        return _response(binding)
    if (
        binding.enrollment_id != data.enrollment_id
        or binding.idempotency_key != data.idempotency_key
        or binding.idempotency_key is None
        or not binding.challenge_nonce
        or not binding.challenge_expires_at
    ):
        raise ArkadeEnrollmentError("Enrollment challenge mismatch.")

    now = datetime.now(timezone.utc)
    if binding.challenge_expires_at <= now:
        raise ArkadeEnrollmentError("Enrollment challenge expired.")
    validate_arkade_identity_descriptor(
        data.identity_descriptor, data.identity_xonly_pubkey, binding.network
    )
    statement = canonical_enrollment_statement(
        account_id=account.id,
        enrollment_id=binding.enrollment_id,
        idempotency_key=binding.idempotency_key,
        nonce=binding.challenge_nonce,
        expires_at=int(binding.challenge_expires_at.timestamp()),
        network=binding.network,
        server_url=binding.server_url,
        server_pubkey=binding.server_pubkey,
        identity_xonly_pubkey=data.identity_xonly_pubkey,
        identity_descriptor=data.identity_descriptor,
    )
    verify_enrollment_proof(statement, data.identity_xonly_pubkey, data.signature)
    try:
        completed = await complete_arkade_binding(
            account_id=account.id,
            enrollment_id=binding.enrollment_id,
            idempotency_key=binding.idempotency_key,
            nonce=binding.challenge_nonce,
            expires_at=binding.challenge_expires_at,
            identity_xonly_pubkey=data.identity_xonly_pubkey,
            identity_descriptor=data.identity_descriptor,
            acknowledged_at=now,
            server_utc_now=now,
            conn=conn,
        )
    except IntegrityError as exc:
        raise ArkadeEnrollmentError("Enrollment binding mismatch.") from exc
    if not completed:
        raise ArkadeEnrollmentError("Enrollment challenge mismatch.")
    ready = await get_arkade_binding(account.id, conn=conn)
    if not ready:
        raise ArkadeEnrollmentError("Enrollment unavailable.")
    return _response(ready)


async def require_arkade_ready(account_id: str, conn: Connection | None = None) -> None:
    if settings.lnbits_effective_installation_mode != "arkade_noncustodial":
        return
    binding = await get_arkade_binding(account_id, conn=conn)
    if not binding or binding.state != "ready":
        raise ArkadeEnrollmentError("ARKADE_ENROLLMENT_REQUIRED")


async def require_arkade_payments_unavailable(
    account_id: str, conn: Connection | None = None
) -> None:
    await require_arkade_ready(account_id, conn=conn)
    if settings.lnbits_effective_installation_mode == "arkade_noncustodial":
        raise ArkadeEnrollmentError("ARKADE_PAYMENTS_UNAVAILABLE")


def canonical_receive_statement(data: ArkadeReceiveAcknowledgement) -> str:
    """The browser signs this exact public allocation statement."""
    values = (
        ("account_id", data.account_id),
        ("wallet_id", data.wallet_id),
        ("native_request_id", data.native_request_id),
        ("idempotency_key", data.idempotency_key),
        ("amount_sat", str(data.amount_sat)),
        ("index", str(data.index)),
        ("address", data.address),
        ("script", data.script),
        ("child_xonly_pubkey", data.child_xonly_pubkey),
        ("network", data.network),
        ("server_url", data.server_url),
        ("server_pubkey", data.server_pubkey),
        ("expires_at", str(data.expires_at)),
    )
    if any("\n" in value or "\r" in value for _, value in values):
        raise ArkadeReceiveError("ARKADE_RECEIVE_INVALID_STATEMENT")
    try:
        statement = "\n".join(
            [f"action={RECEIVE_ACTION}"] + [f"{key}={value}" for key, value in values]
        )
        statement.encode("ascii")
    except UnicodeEncodeError as exc:
        raise ArkadeReceiveError("ARKADE_RECEIVE_INVALID_STATEMENT") from exc
    return statement


def verify_receive_proof(data: ArkadeReceiveAcknowledgement) -> None:
    if len(data.script) % 2 or not _SCRIPT.fullmatch(data.script):
        raise ArkadeReceiveError("ARKADE_RECEIVE_INVALID_MAPPING")
    try:
        public_key = PublicKeyXOnly(bytes.fromhex(data.child_xonly_pubkey))
        digest = hashlib.sha256(
            canonical_receive_statement(data).encode("ascii")
        ).digest()
        valid = public_key.verify(bytes.fromhex(data.signature), digest)
    except (ValueError, TypeError):
        valid = False
    if not valid:
        raise ArkadeReceiveError("ARKADE_RECEIVE_INVALID_PROOF")


def _tagged_hash(tag: str, payload: bytes) -> bytes:
    tag_hash = hashlib.sha256(tag.encode("ascii")).digest()
    return hashlib.sha256(tag_hash + tag_hash + payload).digest()


def verify_receive_exit_membership(  # noqa: C901
    data: ArkadeReceiveAcknowledgement,
) -> None:
    """Bind the SDK-provided DefaultVtxo exit leaf to the submitted output.

    This checks only the two-leaf membership witness; it deliberately does not
    recreate the Ark tree or infer HD lineage from the child key.
    """
    try:
        tapleaf = bytes.fromhex(data.exit_tapleaf)
        control = bytes.fromhex(data.exit_control_block)
    except ValueError as exc:
        raise ArkadeReceiveError("ARKADE_RECEIVE_INVALID_MAPPING") from exc
    if len(control) != 65 or len(tapleaf) < 38 or len(tapleaf) > 43:
        raise ArkadeReceiveError("ARKADE_RECEIVE_INVALID_MAPPING")
    if control[0] & 0xFE != 0xC0 or tapleaf[-1] != 0xC0:
        raise ArkadeReceiveError("ARKADE_RECEIVE_INVALID_MAPPING")
    body = tapleaf[:-1]
    if not 37 <= len(body) <= 42:
        raise ArkadeReceiveError("ARKADE_RECEIVE_INVALID_MAPPING")
    opcode = body[0]
    if opcode == 0:
        sequence = 0
        offset = 1
    elif 0x51 <= opcode <= 0x60:
        sequence = opcode - 0x50
        offset = 1
    elif 1 <= opcode <= 5:
        offset = 1 + opcode
        number = body[1:offset]
        if len(number) != opcode or number[-1] & 0x80:
            raise ArkadeReceiveError("ARKADE_RECEIVE_INVALID_MAPPING")
        if opcode == 1 and number[0] <= 16:
            raise ArkadeReceiveError("ARKADE_RECEIVE_INVALID_MAPPING")
        if int.from_bytes(number, "little") == 0 or (
            opcode > 1 and number[-1] == 0 and not number[-2] & 0x80
        ):
            raise ArkadeReceiveError("ARKADE_RECEIVE_INVALID_MAPPING")
        sequence = int.from_bytes(number, "little")
    else:
        raise ArkadeReceiveError("ARKADE_RECEIVE_INVALID_MAPPING")
    if sequence > 0xFFFFFFFF:
        raise ArkadeReceiveError("ARKADE_RECEIVE_INVALID_MAPPING")
    try:
        child = bytes.fromhex(data.child_xonly_pubkey)
        output = bytes.fromhex(data.script)
        internal = PublicKeyXOnly(control[1:33])
    except (TypeError, ValueError) as exc:
        raise ArkadeReceiveError("ARKADE_RECEIVE_INVALID_MAPPING") from exc
    if body[offset:] != b"\xb2\x75\x20" + child + b"\xac":
        raise ArkadeReceiveError("ARKADE_RECEIVE_INVALID_MAPPING")
    if control[1:33] != _TAPROOT_UNSPENDABLE_KEY:
        raise ArkadeReceiveError("ARKADE_RECEIVE_INVALID_MAPPING")
    leaf_hash = _tagged_hash("TapLeaf", b"\xc0" + bytes([len(body)]) + body)
    sibling = control[33:]
    branch = _tagged_hash(
        "TapBranch", min(leaf_hash, sibling) + max(leaf_hash, sibling)
    )
    try:
        internal.tweak_add(_tagged_hash("TapTweak", internal.format() + branch))
    except ValueError as exc:
        raise ArkadeReceiveError("ARKADE_RECEIVE_INVALID_MAPPING") from exc
    if internal.format() != output[2:]:
        raise ArkadeReceiveError("ARKADE_RECEIVE_INVALID_MAPPING")
    if internal.parity != bool(control[0] & 1):
        raise ArkadeReceiveError("ARKADE_RECEIVE_INVALID_MAPPING")


def decode_arkade_address_script(
    address: str,
    server_pubkey: str,
    expected_hrp: str,
) -> str:
    """Validate only the generic ArkAddress envelope and v1 pkScript.

    The pinned SDK's ArkAddress format is bech32m(version || server key ||
    taproot output key).  The ACK path additionally checks the SDK canonical
    exit leaf and BIP341 membership against that output key; full Ark tree and
    HD lineage validation remain outside this generic envelope parser.
    """
    if address != address.lower() or len(address) > 1023:
        raise ArkadeReceiveError("ARKADE_RECEIVE_INVALID_MAPPING")
    separator = address.rfind("1")
    if separator < 1 or separator + 7 > len(address):
        raise ArkadeReceiveError("ARKADE_RECEIVE_INVALID_MAPPING")
    hrp = address[:separator]
    if hrp != expected_hrp or any(
        ord(char) < 33 or ord(char) > 126 for char in address
    ):
        raise ArkadeReceiveError("ARKADE_RECEIVE_INVALID_MAPPING")
    try:
        words = [CHARSET.index(char) for char in address[separator + 1 :]]
    except ValueError as exc:
        raise ArkadeReceiveError("ARKADE_RECEIVE_INVALID_MAPPING") from exc
    if bech32_polymod(bech32_hrp_expand(hrp) + words) != 0x2BC830A3:
        raise ArkadeReceiveError("ARKADE_RECEIVE_INVALID_MAPPING")
    payload = convertbits(words[:-6], 5, 8, False)
    if payload is None or len(payload) != 65 or payload[0] != 0:
        raise ArkadeReceiveError("ARKADE_RECEIVE_INVALID_MAPPING")
    if bytes(payload[1:33]).hex() != server_pubkey:
        raise ArkadeReceiveError("ARKADE_RECEIVE_INVALID_MAPPING")
    return "5120" + bytes(payload[33:]).hex()


def validate_arkade_address_script(
    address: str,
    script: str,
    server_pubkey: str,
    expected_hrp: str,
) -> None:
    expected_script = decode_arkade_address_script(address, server_pubkey, expected_hrp)
    if script != expected_script:
        raise ArkadeReceiveError("ARKADE_RECEIVE_INVALID_MAPPING")


def _request_mapping_matches(
    request: ArkadeReceiveRequest, data: ArkadeReceiveAcknowledgement
) -> bool:
    return all(
        (
            request.account_id == data.account_id,
            request.wallet_id == data.wallet_id,
            request.native_request_id == data.native_request_id,
            request.idempotency_key == data.idempotency_key,
            request.amount_sat == data.amount_sat,
            request.index == data.index,
            request.address == data.address,
            request.script == data.script,
            request.child_xonly_pubkey == data.child_xonly_pubkey,
            request.network == data.network,
            request.server_url == data.server_url,
            request.server_pubkey == data.server_pubkey,
            int(request.expires_at.timestamp()) == data.expires_at,
        )
    )


def _outpoint_matches(
    row: dict,
    account_id: str,
    request_id: str | None,
    vtxo: ArkadeIndexerVtxo,
) -> bool:
    return (
        row["account_id"] == account_id
        and row["native_request_id"] == request_id
        and row["script"] == vtxo.script
        and int(row["amount_sat"]) == vtxo.amount_sat
    )


async def create_arkade_receive_request_for_account(
    account_id: str,
    *,
    wallet_id: str,
    amount_sat: int,
    idempotency_key: str,
    expires_at: datetime,
    conn: Connection | None = None,
) -> ArkadeReceiveRequest:
    if settings.lnbits_effective_installation_mode != "arkade_noncustodial":
        raise ArkadeReceiveError("ARKADE_RECEIVE_UNAVAILABLE")
    await require_arkade_ready(account_id, conn=conn)
    if not isinstance(idempotency_key, str) or not _IDEMPOTENCY.fullmatch(
        idempotency_key
    ):
        raise ArkadeReceiveError("ARKADE_RECEIVE_INVALID_IDEMPOTENCY")
    if amount_sat < 1 or amount_sat > MAX_AMOUNT_SAT:
        raise ArkadeReceiveError("ARKADE_RECEIVE_INVALID_AMOUNT")
    wallet = await get_wallet(wallet_id, conn=conn)
    if not wallet or wallet.id != wallet_id or wallet.user != account_id:
        raise ArkadeReceiveError("ARKADE_WALLET_NOT_OWNED")
    existing = await get_arkade_receive_request_by_idempotency(
        account_id, idempotency_key, conn=conn
    )
    if existing:
        if existing.wallet_id != wallet_id or existing.amount_sat != amount_sat:
            raise ArkadeReceiveError("ARKADE_RECEIVE_IDEMPOTENCY_CONFLICT")
        return existing
    binding = await get_arkade_binding(account_id, conn=conn)
    if not binding or binding.state != "ready":
        raise ArkadeReceiveError("ARKADE_ENROLLMENT_REQUIRED")
    now = datetime.now(timezone.utc)
    request = ArkadeReceiveRequest(
        account_id=account_id,
        wallet_id=wallet_id,
        native_request_id=uuid4().hex,
        idempotency_key=idempotency_key,
        amount_sat=amount_sat,
        network=binding.network,
        server_url=binding.server_url,
        server_pubkey=binding.server_pubkey,
        expires_at=expires_at,
        created_at=now,
        updated_at=now,
    )
    created = await create_arkade_receive_request(request, conn=conn)
    if not created:
        winner = await get_arkade_receive_request_by_idempotency(
            account_id, idempotency_key, conn=conn
        )
        if winner and winner.wallet_id == wallet_id and winner.amount_sat == amount_sat:
            return winner
        raise ArkadeReceiveError("ARKADE_RECEIVE_IDEMPOTENCY_CONFLICT")
    return request


async def get_arkade_receive_request_for_account(
    account_id: str,
    native_request_id: str,
    conn: Connection | None = None,
) -> ArkadeReceiveRequest:
    if settings.lnbits_effective_installation_mode != "arkade_noncustodial":
        raise ArkadeReceiveError("ARKADE_RECEIVE_UNAVAILABLE")
    await require_arkade_ready(account_id, conn=conn)
    request = await get_arkade_receive_request(native_request_id, conn=conn)
    if not request or request.account_id != account_id:
        raise ArkadeReceiveError("ARKADE_RECEIVE_NOT_FOUND")
    return request


async def acknowledge_arkade_receive(
    account_id: str,
    data: ArkadeReceiveAcknowledgement,
    conn: Connection | None = None,
) -> ArkadeReceiveRequest:
    async with db.reuse_conn(conn) if conn else db.connect() as new_conn:
        async with new_conn.transaction():
            return await _acknowledge_arkade_receive(account_id, data, conn=new_conn)


async def _acknowledge_arkade_receive(  # noqa: C901
    account_id: str,
    data: ArkadeReceiveAcknowledgement,
    conn: Connection | None = None,
) -> ArkadeReceiveRequest:
    if settings.lnbits_effective_installation_mode != "arkade_noncustodial":
        raise ArkadeReceiveError("ARKADE_RECEIVE_UNAVAILABLE")
    await require_arkade_ready(account_id, conn=conn)
    if conn is None:
        raise RuntimeError("ARKADE_MUTATION_REQUIRES_TRANSACTION")
    await conn.execute(
        "UPDATE arkade_account_bindings SET account_id = account_id "
        "WHERE account_id = :account_id AND state = 'ready'",
        {"account_id": account_id},
    )
    if data.account_id != account_id:
        raise ArkadeReceiveError("ARKADE_RECEIVE_ACCOUNT_MISMATCH")
    request = await get_arkade_receive_request(data.native_request_id, conn=conn)
    if not request or request.account_id != account_id:
        raise ArkadeReceiveError("ARKADE_RECEIVE_NOT_FOUND")
    mapping = request
    if request.state == "pending":
        mapping = request.copy(
            update={
                "index": data.index,
                "address": data.address,
                "script": data.script,
                "child_xonly_pubkey": data.child_xonly_pubkey,
            }
        )
    if not _request_mapping_matches(mapping, data):
        raise ArkadeReceiveError("ARKADE_RECEIVE_MAPPING_CONFLICT")
    if data.script != data.script.lower():
        raise ArkadeReceiveError("ARKADE_RECEIVE_INVALID_MAPPING")
    if data.expires_at != int(request.expires_at.timestamp()):
        raise ArkadeReceiveError("ARKADE_RECEIVE_MAPPING_CONFLICT")
    expected_hrp = ARKADE_HRPS.get(request.network)
    if not expected_hrp:
        raise ArkadeReceiveError("ARKADE_RECEIVE_INVALID_MAPPING")
    validate_arkade_address_script(
        data.address, data.script, request.server_pubkey, expected_hrp
    )
    verify_receive_proof(data)
    verify_receive_exit_membership(data)
    result = request
    if request.state == "pending":
        collision = await conn.fetchone(
            "SELECT 1 FROM arkade_outgoing_intents "
            "WHERE account_id = :account_id AND "
            "((change_index = :index) OR change_script = :script)",
            {"account_id": account_id, "index": data.index, "script": data.script},
        )
        if collision:
            raise ArkadeReceiveError("ARKADE_RECEIVE_MAPPING_CONFLICT")
        try:
            updated = await update_arkade_receive_acknowledgement(
                request,
                index=data.index,
                address=data.address,
                script=data.script.lower(),
                child_xonly_pubkey=data.child_xonly_pubkey,
                conn=conn,
            )
        except IntegrityError as exc:
            raise ArkadeReceiveError("ARKADE_RECEIVE_MAPPING_CONFLICT") from exc
        if not updated:
            result = await get_arkade_receive_request(data.native_request_id, conn=conn)
            if not result or not _request_mapping_matches(result, data):
                raise ArkadeReceiveError("ARKADE_RECEIVE_MAPPING_CONFLICT")
        else:
            result = await get_arkade_receive_request(data.native_request_id, conn=conn)
            if not result:
                raise ArkadeReceiveError("ARKADE_RECEIVE_UNAVAILABLE")
    payment = await get_payment_by_native_id(result.native_request_id, conn=conn)
    if payment:
        if (
            payment.protocol != "arkade"
            or payment.wallet_id != result.wallet_id
            or payment.amount != result.amount_sat * 1000
            or payment.native_id != result.native_request_id
        ):
            raise ArkadeReceiveError("ARKADE_RECEIVE_MAPPING_CONFLICT")
        if payment.arkade_address not in (None, result.address):
            raise ArkadeReceiveError("ARKADE_RECEIVE_MAPPING_CONFLICT")
        if payment.arkade_address is None:
            payment.arkade_address = result.address
            await update_payment(payment, conn=conn)
    return result


def _positive_decimal(value: object) -> int | None:
    if not isinstance(value, str) or not value.isdecimal():
        return None
    try:
        number = int(value)
    except (OverflowError, ValueError):
        return None
    return number if number > 0 else None


def parse_indexer_vtxos(body: object) -> list[ArkadeIndexerVtxo]:  # noqa: C901
    if not isinstance(body, dict) or not isinstance(body.get("vtxos"), list):
        raise ArkadeReceiveError("ARKADE_INDEXER_INVALID_RESPONSE")
    _validate_indexer_page(body.get("page"), allow_empty_first_page=not body["vtxos"])
    parsed: list[ArkadeIndexerVtxo] = []
    for raw in body["vtxos"]:
        if not isinstance(raw, dict) or not isinstance(raw.get("outpoint"), dict):
            raise ArkadeReceiveError("ARKADE_INDEXER_INVALID_RESPONSE")
        outpoint = raw["outpoint"]
        txid, vout, amount, script = (
            outpoint.get("txid"),
            outpoint.get("vout"),
            raw.get("amount"),
            raw.get("script"),
        )
        amount_sat = _positive_decimal(amount)
        if (
            not isinstance(txid, str)
            or not _TXID.fullmatch(txid)
            or isinstance(vout, bool)
            or not isinstance(vout, int)
            or vout < 0
            or vout > MAX_VOUT
            or amount_sat is None
            or amount_sat > MAX_AMOUNT_SAT
            or not isinstance(script, str)
            or len(script) % 2
            or not _SCRIPT.fullmatch(script)
        ):
            raise ArkadeReceiveError("ARKADE_INDEXER_INVALID_RESPONSE")
        status_keys = ("isPreconfirmed", "isSpent", "isSwept", "isUnrolled")
        if any(key not in raw for key in status_keys):
            raise ArkadeReceiveError("ARKADE_INDEXER_INVALID_RESPONSE")
        flags = {key: raw[key] for key in status_keys}
        if any(not isinstance(value, bool) for value in flags.values()):
            raise ArkadeReceiveError("ARKADE_INDEXER_INVALID_RESPONSE")
        raw_created_at = raw.get("createdAt")
        created_timestamp = _positive_decimal(raw_created_at)
        if created_timestamp is None:
            raise ArkadeReceiveError("ARKADE_INDEXER_INVALID_RESPONSE")
        try:
            created_at = datetime.fromtimestamp(created_timestamp, timezone.utc)
        except (OverflowError, OSError, ValueError) as exc:
            raise ArkadeReceiveError("ARKADE_INDEXER_INVALID_RESPONSE") from exc
        raw_expires_at = raw.get("expiresAt")
        expires_at = None
        expires_at_height = None
        if "expiresAt" not in raw:
            raise ArkadeReceiveError("ARKADE_INDEXER_INVALID_RESPONSE")
        if raw_expires_at is not None:
            expiry = _positive_decimal(raw_expires_at)
            if expiry is None:
                raise ArkadeReceiveError("ARKADE_INDEXER_INVALID_RESPONSE")
            if expiry * 1000 >= _INDEXER_TIMESTAMP_BOUNDARY_MS:
                try:
                    expires_at = datetime.fromtimestamp(expiry, timezone.utc)
                except (OverflowError, OSError, ValueError) as exc:
                    raise ArkadeReceiveError("ARKADE_INDEXER_INVALID_RESPONSE") from exc
            else:
                expires_at_height = expiry
        raw_commitment_txids = raw.get("commitmentTxids")
        if not isinstance(raw_commitment_txids, list) or any(
            not isinstance(txid, str) or not _TXID.fullmatch(txid)
            for txid in raw_commitment_txids
        ):
            raise ArkadeReceiveError("ARKADE_INDEXER_INVALID_RESPONSE")
        terminal_ids = {}
        for wire_name, field_name in (
            ("spentBy", "spent_by"),
            ("settledBy", "settled_by"),
            ("arkTxid", "arkade_txid"),
        ):
            value = raw.get(wire_name)
            if value is None or value == "":
                terminal_ids[field_name] = None
            elif isinstance(value, str) and _TXID.fullmatch(value):
                terminal_ids[field_name] = value
            else:
                raise ArkadeReceiveError("ARKADE_INDEXER_INVALID_RESPONSE")
        parsed.append(
            ArkadeIndexerVtxo(
                txid=txid,
                vout=vout,
                amount_sat=amount_sat,
                script=script.lower(),
                is_preconfirmed=flags["isPreconfirmed"],
                is_spent=flags["isSpent"] or bool(terminal_ids["spent_by"]),
                is_swept=flags["isSwept"],
                is_unrolled=flags["isUnrolled"],
                created_at=created_at,
                expires_at=expires_at,
                expires_at_height=expires_at_height,
                commitment_txids=raw_commitment_txids,
                **terminal_ids,
            )
        )
    return parsed


def _validate_indexer_page(
    page: object, *, allow_empty_first_page: bool = False
) -> None:
    if page is None:
        return
    if not isinstance(page, dict):
        raise ArkadeReceiveError("ARKADE_INDEXER_INVALID_RESPONSE")
    current, next_page, total = (
        page.get("current"),
        page.get("next"),
        page.get("total"),
    )
    if (
        not isinstance(current, int)
        or isinstance(current, bool)
        or not isinstance(next_page, int)
        or isinstance(next_page, bool)
        or not isinstance(total, int)
        or isinstance(total, bool)
    ):
        raise ArkadeReceiveError("ARKADE_INDEXER_INVALID_RESPONSE")
    if current < 0 or next_page < 0 or total < 0:
        raise ArkadeReceiveError("ARKADE_INDEXER_INVALID_RESPONSE")
    if current > total and not (
        allow_empty_first_page and current == 1 and next_page == 0 and total == 0
    ):
        raise ArkadeReceiveError("ARKADE_INDEXER_INVALID_RESPONSE")
    if next_page <= current and current < total:
        raise ArkadeReceiveError("ARKADE_INDEXER_INVALID_RESPONSE")
    if next_page > total:
        raise ArkadeReceiveError("ARKADE_INDEXER_INVALID_RESPONSE")


async def fetch_arkade_indexer_vtxos(  # noqa: C901
    account_id: str,
    conn: Connection | None = None,
    spendable_only: bool = False,
    *,
    scripts: list[str] | None = None,
) -> list[ArkadeIndexerVtxo]:
    binding = await get_arkade_binding(account_id, conn=conn)
    if not binding or binding.state != "ready":
        raise ArkadeReceiveError("ARKADE_ENROLLMENT_REQUIRED")
    if scripts is None:
        requests = await get_arkade_receive_requests(account_id, conn=conn)
        scripts = sorted({request.script for request in requests if request.script})
        changes = await (conn or db).fetchall(
            "SELECT change_script AS script FROM arkade_outgoing_intents "
            "WHERE account_id = :account_id "
            "AND status IN ('submitted', 'settled', 'disputed') "
            "AND change_script IS NOT NULL UNION "
            "SELECT refund_pk_script AS script FROM arkade_outgoing_intents "
            "WHERE account_id = :account_id AND refund_pk_script IS NOT NULL",
            {"account_id": account_id},
        )
        scripts = sorted(set(scripts) | {row["script"] for row in changes})
        scripts = sorted(
            set(scripts)
            | {row["script"] for row in await maintenance_rows(account_id, conn)}
        )
    else:
        scripts = sorted(set(scripts))
    if not scripts:
        return []
    result: list[ArkadeIndexerVtxo] = []
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            for offset in range(0, len(scripts), 32):
                chunk = scripts[offset : offset + 32]
                page_index = 0
                seen_pages: set[int] = set()
                while True:
                    if page_index in seen_pages:
                        raise ArkadeReceiveError("ARKADE_INDEXER_INVALID_RESPONSE")
                    seen_pages.add(page_index)
                    params = tuple(
                        [("scripts", script) for script in chunk]
                        + ([("spendableOnly", "true")] if spendable_only else [])
                        + [("page.index", str(page_index)), ("page.size", "500")]
                    )
                    response = await client.get(
                        f"{binding.server_url}/v1/indexer/vtxos", params=params
                    )
                    response.raise_for_status()
                    try:
                        body = response.json()
                    except ValueError as exc:
                        raise ArkadeReceiveError(
                            "ARKADE_INDEXER_INVALID_RESPONSE"
                        ) from exc
                    result.extend(parse_indexer_vtxos(body))
                    page = body.get("page") if isinstance(body, dict) else None
                    if page is None:
                        raise ArkadeReceiveError("ARKADE_INDEXER_INVALID_RESPONSE")
                    _validate_indexer_page(
                        page, allow_empty_first_page=not body["vtxos"]
                    )
                    if page["current"] >= page["total"]:
                        break
                    page_index = page["next"]
    except httpx.HTTPError as exc:
        raise ArkadeReceiveError("ARKADE_INDEXER_UNAVAILABLE") from exc
    except ArkadeReceiveError as exc:
        if str(exc) == "ARKADE_INDEXER_INVALID_RESPONSE":
            await _mark_receive_reconciliation_required(
                account_id, "ARKADE_INDEXER_INVALID_RESPONSE", conn=conn
            )
        raise
    return result


async def fetch_arkade_indexer_vtxos_for_outpoints(  # noqa: C901
    account_id: str,
    outpoints: list[tuple[str, int]],
    spendable_only: bool = True,
) -> list[ArkadeIndexerVtxo]:
    """Fetch only the requested public outpoints from the Arkade indexer."""
    binding = await get_arkade_binding(account_id)
    if not binding or binding.state != "ready":
        raise ArkadeReceiveError("ARKADE_ENROLLMENT_REQUIRED")
    if not 1 <= len(outpoints) <= 100 or len(set(outpoints)) != len(outpoints):
        raise ArkadeReceiveError("ARKADE_INDEXER_INVALID_RESPONSE")
    result: list[ArkadeIndexerVtxo] = []
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            page_index = 0
            seen_pages: set[int] = set()
            while True:
                if page_index in seen_pages:
                    raise ArkadeReceiveError("ARKADE_INDEXER_INVALID_RESPONSE")
                seen_pages.add(page_index)
                if len(seen_pages) > 2:
                    raise ArkadeReceiveError("ARKADE_INDEXER_INVALID_RESPONSE")
                params = tuple(
                    [("outpoints", f"{txid}:{vout}") for txid, vout in outpoints]
                    + [
                        ("spendableOnly", "true" if spendable_only else "false"),
                        ("page.index", str(page_index)),
                        ("page.size", "500"),
                    ]
                )
                response = await client.get(
                    f"{binding.server_url}/v1/indexer/vtxos", params=params
                )
                response.raise_for_status()
                try:
                    body = response.json()
                except ValueError as exc:
                    raise ArkadeReceiveError("ARKADE_INDEXER_INVALID_RESPONSE") from exc
                result.extend(parse_indexer_vtxos(body))
                if len(result) > len(outpoints):
                    raise ArkadeReceiveError("ARKADE_INDEXER_INVALID_RESPONSE")
                page = body.get("page") if isinstance(body, dict) else None
                if page is None:
                    raise ArkadeReceiveError("ARKADE_INDEXER_INVALID_RESPONSE")
                _validate_indexer_page(page, allow_empty_first_page=not body["vtxos"])
                if page["current"] >= page["total"]:
                    return result
                page_index = page["next"]
    except httpx.HTTPError as exc:
        raise ArkadeReceiveError("ARKADE_INDEXER_UNAVAILABLE") from exc


async def fetch_arkade_indexer_virtual_tx(  # noqa: C901
    account_id: str, arkade_txid: str
) -> str | None:
    """Fetch one public Ark virtual transaction PSBT from the pinned indexer."""
    if not _TXID.fullmatch(arkade_txid):
        raise ArkadeReceiveError("ARKADE_INDEXER_INVALID_RESPONSE")
    binding = await get_arkade_binding(account_id)
    if not binding or binding.state != "ready":
        raise ArkadeReceiveError("ARKADE_ENROLLMENT_REQUIRED")
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            page_index = 0
            seen_pages: set[int] = set()
            while True:
                if page_index in seen_pages or len(seen_pages) >= 2:
                    raise ArkadeReceiveError("ARKADE_INDEXER_INVALID_RESPONSE")
                seen_pages.add(page_index)
                response = await client.get(
                    f"{binding.server_url}/v1/indexer/virtualTx/{arkade_txid}",
                    params={"page.index": page_index, "page.size": 2},
                )
                response.raise_for_status()
                try:
                    body = response.json()
                except ValueError as exc:
                    raise ArkadeReceiveError("ARKADE_INDEXER_INVALID_RESPONSE") from exc
                if (
                    not isinstance(body, dict)
                    or not isinstance(body.get("txs"), list)
                    or any(not isinstance(tx, str) for tx in body["txs"])
                ):
                    raise ArkadeReceiveError("ARKADE_INDEXER_INVALID_RESPONSE")
                page = body.get("page")
                if page is not None:
                    _validate_indexer_page(page)
                if len(body["txs"]) > 1:
                    raise ArkadeReceiveError("ARKADE_INDEXER_INVALID_RESPONSE")
                if body["txs"]:
                    tx = body["txs"][0]
                    if len(tx) > _MAX_INDEXER_PSBT_BASE64_LENGTH:
                        raise ArkadeReceiveError("ARKADE_INDEXER_INVALID_RESPONSE")
                    try:
                        raw = base64.b64decode(tx, validate=True)
                    except Exception as exc:
                        raise ArkadeReceiveError(
                            "ARKADE_INDEXER_INVALID_RESPONSE"
                        ) from exc
                    if not 1 <= len(raw) <= _MAX_INDEXER_PSBT_BYTES:
                        raise ArkadeReceiveError("ARKADE_INDEXER_INVALID_RESPONSE")
                    return tx
                if page is None:
                    return None
                if page["current"] >= page["total"]:
                    return None
                page_index = page["next"]
    except httpx.HTTPError as exc:
        raise ArkadeReceiveError("ARKADE_INDEXER_UNAVAILABLE") from exc


def _outgoing_evidence_result(
    status: ArkadeOutgoingEvidenceStatus,
    arkade_txid: str | None = None,
    code: str | None = None,
) -> ArkadeOutgoingEvidenceResult:
    return ArkadeOutgoingEvidenceResult(
        status=status, arkade_txid=arkade_txid, code=code
    )


def classify_arkade_outgoing_evidence(  # noqa: C901
    claims: list[ArkadeOutgoingIntentInput],
    evidence: list[ArkadeIndexerVtxo],
) -> ArkadeOutgoingEvidenceResult:
    """Classify indexer facts before fetching the corresponding virtual tx."""
    expected = {(claim.txid, claim.vout) for claim in claims}
    if len(expected) != len(claims):
        return _outgoing_evidence_result(
            "contradictory", code="ARKADE_OUTGOING_EVIDENCE_DUPLICATE"
        )
    observed: dict[tuple[str, int], ArkadeIndexerVtxo] = {}
    for vtxo in evidence:
        key = (vtxo.txid, vtxo.vout)
        if key in observed:
            return _outgoing_evidence_result(
                "contradictory", code="ARKADE_OUTGOING_EVIDENCE_DUPLICATE"
            )
        observed[key] = vtxo
    if expected - set(observed):
        return _outgoing_evidence_result(
            "pending", code="ARKADE_OUTGOING_EVIDENCE_INCOMPLETE"
        )
    if set(observed) - expected:
        return _outgoing_evidence_result(
            "contradictory", code="ARKADE_OUTGOING_EVIDENCE_EXTRA_INPUT"
        )

    claims_by_outpoint = {(claim.txid, claim.vout): claim for claim in claims}
    ark_txids: set[str] = set()
    checkpoint_ids: list[str] = []
    for vtxo in evidence:
        claim = claims_by_outpoint[(vtxo.txid, vtxo.vout)]
        if vtxo.amount_sat != claim.amount_sat:
            return _outgoing_evidence_result(
                "contradictory", code="ARKADE_OUTGOING_EVIDENCE_INPUT_VALUE_INVALID"
            )
        if (vtxo.spent_by and not _TXID.fullmatch(vtxo.spent_by)) or (
            vtxo.arkade_txid and not _TXID.fullmatch(vtxo.arkade_txid)
        ):
            raise ArkadeReceiveError("ARKADE_INDEXER_INVALID_RESPONSE")
        if vtxo.is_swept or vtxo.is_unrolled or vtxo.settled_by:
            return _outgoing_evidence_result(
                "contradictory", code="ARKADE_OUTGOING_EVIDENCE_TERMINAL_CONFLICT"
            )
        if not vtxo.is_spent or not vtxo.spent_by or not vtxo.arkade_txid:
            return _outgoing_evidence_result(
                "pending", code="ARKADE_OUTGOING_EVIDENCE_NOT_SPENT"
            )
        ark_txids.add(vtxo.arkade_txid)
        checkpoint_ids.append(vtxo.spent_by)
    if len(checkpoint_ids) != len(set(checkpoint_ids)):
        return _outgoing_evidence_result(
            "contradictory", code="ARKADE_OUTGOING_EVIDENCE_DUPLICATE"
        )
    if len(ark_txids) != 1:
        return _outgoing_evidence_result(
            "contradictory", code="ARKADE_OUTGOING_EVIDENCE_ARK_TXID_CONFLICT"
        )
    return _outgoing_evidence_result("verified", arkade_txid=ark_txids.pop())


def verify_arkade_outgoing_virtual_tx(  # noqa: C901
    *,
    arkade_txid: str,
    psbt_base64: str,
    claims: list[ArkadeOutgoingIntentInput],
    evidence: list[ArkadeIndexerVtxo],
    destination_script: str,
    amount_msat: int,
    change_script: str | None = None,
    change_amount_sat: int | None = None,
) -> ArkadeOutgoingEvidenceResult:
    """Independently verify the exact zero-fee virtual transaction."""
    preliminary = classify_arkade_outgoing_evidence(claims, evidence)
    if preliminary.status != "verified":
        return preliminary
    if preliminary.arkade_txid != arkade_txid:
        return _outgoing_evidence_result(
            "contradictory", code="ARKADE_OUTGOING_EVIDENCE_ARK_TXID_CONFLICT"
        )
    if (
        amount_msat <= 0
        or amount_msat % 1000
        or not _SCRIPT.fullmatch(destination_script)
        or len(destination_script) % 2
    ):
        return _outgoing_evidence_result(
            "contradictory", code="ARKADE_OUTGOING_EVIDENCE_OUTPUT_INVALID"
        )
    if (change_script is None) != (change_amount_sat is None) or (
        change_script is not None
        and (
            not _SCRIPT.fullmatch(change_script)
            or len(change_script) % 2
            or not change_amount_sat
        )
    ):
        return _outgoing_evidence_result(
            "contradictory", code="ARKADE_OUTGOING_EVIDENCE_OUTPUT_INVALID"
        )
    try:
        if len(psbt_base64) > _MAX_INDEXER_PSBT_BASE64_LENGTH:
            raise ValueError
        raw = base64.b64decode(psbt_base64, validate=True)
        if not 1 <= len(raw) <= _MAX_INDEXER_PSBT_BYTES:
            raise ValueError
        parsed = PSBT.parse(raw)
    except Exception as exc:
        raise ArkadeReceiveError("ARKADE_INDEXER_INVALID_RESPONSE") from exc

    tx = parsed.tx
    expected_inputs = {(vtxo.spent_by, 0) for vtxo in evidence}
    actual_inputs = {(vin.txid.hex(), vin.vout) for vin in tx.vin}
    if (
        len(tx.vin) != len(expected_inputs)
        or None in {item[0] for item in expected_inputs}
        or actual_inputs != expected_inputs
    ):
        return _outgoing_evidence_result(
            "contradictory", code="ARKADE_OUTGOING_EVIDENCE_INPUT_INVALID"
        )

    claims_by_checkpoint = {
        vtxo.spent_by: vtxo.amount_sat for vtxo in evidence if vtxo.spent_by
    }
    input_total = 0
    try:
        for index, vin in enumerate(tx.vin):
            if vin.txid.hex() not in claims_by_checkpoint:
                return _outgoing_evidence_result(
                    "contradictory", code="ARKADE_OUTGOING_EVIDENCE_INPUT_INVALID"
                )
            utxo = parsed.utxo(index)
            if utxo.value != claims_by_checkpoint[vin.txid.hex()]:
                return _outgoing_evidence_result(
                    "contradictory", code="ARKADE_OUTGOING_EVIDENCE_INPUT_VALUE_INVALID"
                )
            input_total += utxo.value
    except Exception as exc:
        raise ArkadeReceiveError("ARKADE_INDEXER_INVALID_RESPONSE") from exc

    expected_outputs: list[tuple[int, str]] = [
        (amount_msat // 1000, destination_script.lower())
    ]
    if change_script is not None:
        assert change_amount_sat is not None
        expected_outputs.append((change_amount_sat, change_script.lower()))
    expected_outputs.append((0, "51024e73"))
    actual_outputs = [
        (output.value, output.script_pubkey.data.hex()) for output in tx.vout
    ]
    if actual_outputs != expected_outputs:
        return _outgoing_evidence_result(
            "contradictory", code="ARKADE_OUTGOING_EVIDENCE_OUTPUT_INVALID"
        )
    if input_total != sum(value for value, _ in expected_outputs):
        return _outgoing_evidence_result(
            "contradictory", code="ARKADE_OUTGOING_EVIDENCE_FEE_INVALID"
        )
    if tx.txid().hex() != arkade_txid:
        return _outgoing_evidence_result(
            "contradictory", code="ARKADE_OUTGOING_EVIDENCE_TXID_MISMATCH"
        )
    return preliminary


async def verify_arkade_outgoing_evidence(
    account_id: str,
    claims: list[ArkadeOutgoingIntentInput],
    destination_script: str,
    amount_msat: int,
    change_script: str | None = None,
    change_amount_sat: int | None = None,
) -> ArkadeOutgoingEvidenceResult:
    """Fetch and verify public settlement evidence without mutating state."""
    if not 1 <= len(claims) <= 100:
        raise ArkadeReceiveError("ARKADE_INDEXER_INVALID_RESPONSE")
    evidence = await fetch_arkade_indexer_vtxos_for_outpoints(
        account_id,
        [(claim.txid, claim.vout) for claim in claims],
        spendable_only=False,
    )
    preliminary = classify_arkade_outgoing_evidence(claims, evidence)
    if preliminary.status != "verified":
        return preliminary
    assert preliminary.arkade_txid is not None
    psbt_base64 = await fetch_arkade_indexer_virtual_tx(
        account_id, preliminary.arkade_txid
    )
    if psbt_base64 is None:
        return _outgoing_evidence_result(
            "pending",
            arkade_txid=preliminary.arkade_txid,
            code="ARKADE_OUTGOING_EVIDENCE_UNINDEXED",
        )
    return verify_arkade_outgoing_virtual_tx(
        arkade_txid=preliminary.arkade_txid,
        psbt_base64=psbt_base64,
        claims=claims,
        evidence=evidence,
        destination_script=destination_script,
        amount_msat=amount_msat,
        change_script=change_script,
        change_amount_sat=change_amount_sat,
    )


def _same_outgoing_claims(
    left: list[ArkadeOutgoingIntentInput], right: list[ArkadeOutgoingIntentInput]
) -> bool:
    return sorted((item.txid, item.vout, item.amount_sat) for item in left) == sorted(
        (item.txid, item.vout, item.amount_sat) for item in right
    )


def _same_outgoing_reconciliation_fields(
    left: ArkadeOutgoingIntent, right: ArkadeOutgoingIntent
) -> bool:
    return all(
        getattr(left, field) == getattr(right, field)
        for field in (
            "account_id",
            "wallet_id",
            "amount_msat",
            "max_fee_msat",
            "destination",
            "destination_kind",
            "destination_script",
            "change_index",
            "change_script",
            "change_amount_sat",
        )
    )


async def fetch_arkade_operator_pubkey(server_url: str) -> str:
    """Read the current public operator signer used by the lockup address."""
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            response = await client.get(f"{server_url}/v1/info")
            response.raise_for_status()
            body = response.json()
    except (httpx.HTTPError, ValueError) as exc:
        raise ArkadeReceiveError("ARKADE_INDEXER_UNAVAILABLE") from exc
    signer = body.get("signerPubkey") if isinstance(body, dict) else None
    if not isinstance(signer, str) or not re.fullmatch(r"[0-9a-fA-F]{64,66}", signer):
        raise ArkadeReceiveError("ARKADE_INDEXER_INVALID_RESPONSE")
    try:
        raw = bytes.fromhex(signer)
        if len(raw) == 33:
            if raw[0] not in (2, 3):
                raise ValueError("operator key is not compressed")
            raw = raw[1:]
        signer = PublicKeyXOnly(raw).format().hex()
    except (TypeError, ValueError) as exc:
        raise ArkadeReceiveError("ARKADE_INDEXER_INVALID_RESPONSE") from exc
    return signer


async def reconcile_arkade_lightning_intent(  # noqa: C901
    intent_id: str, account_id: str, *, now: int | None = None
) -> ArkadeLightningEvidenceVerdict | None:
    """Reconcile one submitted Lightning intent from public terminal evidence."""
    from lnbits.core.services.arkade_evidence import (
        ArkadeLightningEvidenceIntent,
        ArkadeLightningEvidenceStatus,
        verify_arkade_lightning_terminal_evidence,
    )

    if settings.lnbits_effective_installation_mode != "arkade_noncustodial":
        raise ArkadeOutgoingError("ARKADE_OUTGOING_UNAVAILABLE")
    intent = await get_arkade_outgoing_intent(intent_id)
    if (
        not intent
        or intent.account_id != account_id
        or intent.destination_kind != "lightning"
        or intent.status != "submitted"
    ):
        return None
    binding = await get_arkade_binding(account_id)
    if not binding or binding.state != "ready":
        raise ArkadeReceiveError("ARKADE_ENROLLMENT_REQUIRED")
    if (
        not intent.lockup_address
        or not intent.payment_hash
        or not intent.solver_pubkey
        or not intent.refund_locktime
        or not intent.sender_pubkey
        or not intent.refund_pk_script
    ):
        raise ArkadeReceiveError("ARKADE_OUTGOING_REFUND_BINDING_REQUIRED")
    funding_claims = await get_arkade_outgoing_intent_inputs(intent_id)
    if (
        len(funding_claims) != 1
        or funding_claims[0].txid != intent.arkade_txid
        or funding_claims[0].amount_sat != intent.quote_from_amount_sat
    ):
        raise ArkadeReceiveError("ARKADE_OUTGOING_CORRUPT")
    server_pubkey = await fetch_arkade_operator_pubkey(binding.server_url)
    try:
        lockup_script = decode_arkade_address_script(
            intent.lockup_address,
            server_pubkey,
            ARKADE_HRPS[binding.network],
        )
    except (ArkadeReceiveError, KeyError):
        raise ArkadeReceiveError("ARKADE_OUTGOING_OUTPUT_INVALID") from None
    evidence = await fetch_arkade_indexer_vtxos(
        account_id,
        spendable_only=False,
        scripts=[lockup_script],
    )
    checkpoint_ids = sorted(
        {vtxo.spent_by for vtxo in evidence if vtxo.spent_by is not None}
    )
    checkpoint_psbts: dict[str, str] = {}
    for checkpoint_id in checkpoint_ids:
        psbt = await fetch_arkade_indexer_virtual_tx(account_id, checkpoint_id)
        if psbt is not None:
            checkpoint_psbts[checkpoint_id] = psbt
    terminal_ids = sorted(
        {vtxo.arkade_txid for vtxo in evidence if vtxo.arkade_txid is not None}
    )
    terminal_psbts: dict[str, str] = {}
    for terminal_id in terminal_ids:
        psbt = await fetch_arkade_indexer_virtual_tx(account_id, terminal_id)
        if psbt is not None:
            terminal_psbts[terminal_id] = psbt
    verdict = verify_arkade_lightning_terminal_evidence(
        ArkadeLightningEvidenceIntent(
            payment_hash=intent.payment_hash,
            amount_msat=intent.amount_msat,
            quote_from_amount_sat=intent.quote_from_amount_sat or 0,
            quote_to_amount_sat=intent.quote_to_amount_sat or 0,
            max_fee_msat=intent.max_fee_msat,
            refund_locktime=intent.refund_locktime,
            solver_pubkey=intent.solver_pubkey,
            sender_pubkey=intent.sender_pubkey,
            server_pubkey=server_pubkey,
            lockup_script=lockup_script,
            refund_pk_script=intent.refund_pk_script,
            funding_outpoint=(funding_claims[0].txid, funding_claims[0].vout),
        ),
        evidence,
        checkpoint_psbts,
        terminal_psbts=terminal_psbts,
        now=now or int(datetime.now(timezone.utc).timestamp()),
    )
    if verdict.status == ArkadeLightningEvidenceStatus.PENDING:
        return verdict
    if (
        verdict.status
        in {
            ArkadeLightningEvidenceStatus.CLAIMED,
            ArkadeLightningEvidenceStatus.REFUNDED,
        }
        and not verdict.ark_txid
    ):
        raise ArkadeReceiveError("ARKADE_OUTGOING_CORRUPT")

    async with db.connect() as database:
        async with database.transaction():
            current = await get_arkade_outgoing_intent(intent_id, conn=database)
            payment = await get_payment_by_native_id(intent_id, conn=database)
            if (
                not current
                or current.account_id != account_id
                or current.wallet_id != intent.wallet_id
                or current.destination_kind != "lightning"
                or not payment
                or not _outgoing_payment_matches(payment, current)
            ):
                raise ArkadeReceiveError("ARKADE_OUTGOING_CORRUPT")
            terminal_state: TerminalState
            if verdict.status == ArkadeLightningEvidenceStatus.CLAIMED:
                terminal_state = "settled"
            elif verdict.status == ArkadeLightningEvidenceStatus.REFUNDED:
                terminal_state = "refunded"
            else:
                terminal_state = "disputed"
            if current.status == terminal_state:
                await create_arkade_lightning_terminal_event(
                    intent_id, terminal_state, payment, database
                )
                return verdict
            if current.status != "submitted":
                raise ArkadeReceiveError("ARKADE_LIGHTNING_TERMINAL_CONFLICT")
            if verdict.status == ArkadeLightningEvidenceStatus.CLAIMED:
                assert verdict.ark_txid is not None
                if not await settle_arkade_lightning_intent(
                    intent_id,
                    verdict.ark_txid,
                    account_id=account_id,
                    wallet_id=current.wallet_id,
                    conn=database,
                ):
                    raise ArkadeReceiveError("ARKADE_OUTGOING_CORRUPT")
                if not await settle_arkade_lightning_payment(
                    intent_id,
                    account_id=account_id,
                    wallet_id=current.wallet_id,
                    amount_msat=current.amount_msat,
                    arkade_address=current.destination,
                    conn=database,
                ):
                    raise ArkadeReceiveError("ARKADE_OUTGOING_CORRUPT")
                reconciliation = await get_arkade_reconciliation(
                    account_id, conn=database
                )
                if (
                    not reconciliation
                    or reconciliation.state != "reconciliation_required"
                ):
                    await update_arkade_reconciliation(
                        account_id, state="ok", conn=database
                    )
            elif verdict.status == ArkadeLightningEvidenceStatus.REFUNDED:
                assert verdict.ark_txid is not None
                if not await refund_arkade_lightning_intent(
                    intent_id,
                    verdict.ark_txid,
                    account_id=account_id,
                    wallet_id=current.wallet_id,
                    conn=database,
                ):
                    raise ArkadeReceiveError("ARKADE_OUTGOING_CORRUPT")
                if not await refund_arkade_lightning_payment(
                    intent_id,
                    account_id=account_id,
                    wallet_id=current.wallet_id,
                    amount_msat=current.amount_msat,
                    arkade_address=current.destination,
                    conn=database,
                ):
                    raise ArkadeReceiveError("ARKADE_OUTGOING_CORRUPT")
                if verdict.refund_output:
                    refund_vout, refund_amount_sat, refund_script = (
                        verdict.refund_output
                    )
                    existing = await get_arkade_receive_outpoint(
                        verdict.ark_txid, refund_vout, conn=database
                    )
                    if existing and (
                        existing["account_id"] != account_id
                        or existing["script"].lower() != refund_script
                        or int(existing["amount_sat"]) != refund_amount_sat
                    ):
                        raise ArkadeReceiveError("ARKADE_OUTPOINT_CONFLICT")
                    if not existing:
                        await create_arkade_receive_outpoint(
                            account_id=account_id,
                            native_request_id=None,
                            vtxo=ArkadeIndexerVtxo(
                                txid=verdict.ark_txid,
                                vout=refund_vout,
                                amount_sat=refund_amount_sat,
                                script=refund_script,
                            ),
                            status="valid",
                            conn=database,
                        )
                reconciliation = await get_arkade_reconciliation(
                    account_id, conn=database
                )
                if (
                    not reconciliation
                    or reconciliation.state != "reconciliation_required"
                ):
                    await update_arkade_reconciliation(
                        account_id, state="ok", conn=database
                    )
            else:
                if not await dispute_arkade_outgoing_intent(intent_id, conn=database):
                    raise ArkadeReceiveError("ARKADE_OUTGOING_CORRUPT")
                await update_arkade_reconciliation(
                    account_id,
                    state="reconciliation_required",
                    # The column holds a fixed code set; the evidence prose is
                    # for the log, not for this enum.
                    last_error="ARKADE_LIGHTNING_EVIDENCE_CONTRADICTORY",
                    conn=database,
                )
                logger.warning(
                    f"Arkade Lightning intent {intent_id} disputed: "
                    f"{verdict.reason or 'contradictory evidence'}"
                )
            payment = await get_payment_by_native_id(intent_id, conn=database)
            if not payment:
                raise ArkadeReceiveError("ARKADE_OUTGOING_CORRUPT")
            await create_arkade_lightning_terminal_event(
                intent_id, terminal_state, payment, database
            )
    return verdict


async def fail_arkade_lightning_intent(  # noqa: C901
    account_id: str,
    intent_id: str,
    reason: str,
    conn: Connection | None = None,
) -> ArkadeOutgoingIntentResponse:
    """Record a browser-reported claim failure as a terminal failed(reason) swap.

    The claim callback lives in the user's wallet, so a swap whose claim was
    attempted and kept failing is only observable there; the server refuses a
    contradictory verdict path for it (that stays `disputed`) and keeps the
    account flagged for reconciliation with the same reason.
    """
    if settings.lnbits_effective_installation_mode != "arkade_noncustodial":
        raise ArkadeOutgoingError("ARKADE_OUTGOING_UNAVAILABLE")
    reason = reason.strip()
    if not reason or len(reason) > 200:
        raise ArkadeOutgoingError("ARKADE_LIGHTNING_FAILURE_REASON_INVALID")
    async with db.reuse_conn(conn) if conn else db.connect() as database:
        async with database.transaction():
            intent = await get_arkade_outgoing_intent(intent_id, conn=database)
            if not intent or intent.account_id != account_id:
                raise ArkadeOutgoingError("ARKADE_OUTGOING_NOT_FOUND")
            if intent.destination_kind != "lightning":
                raise ArkadeOutgoingError("ARKADE_INTENT_INVALID_TRANSITION")
            binding = await get_arkade_binding(account_id, conn=database)
            if not binding or binding.state != "ready":
                raise ArkadeOutgoingError("ARKADE_ENROLLMENT_REQUIRED")
            if intent.status == "failed" and intent.failure_reason != reason:
                raise ArkadeOutgoingError("ARKADE_OUTGOING_IDEMPOTENCY_CONFLICT")
            if intent.status not in {"submitted", "failed"}:
                raise ArkadeOutgoingError("ARKADE_INTENT_INVALID_TRANSITION")
            if intent.status == "submitted":
                if not await fail_arkade_lightning_intent_crud(
                    intent_id,
                    reason,
                    account_id=account_id,
                    wallet_id=intent.wallet_id,
                    conn=database,
                ):
                    raise ArkadeOutgoingError("ARKADE_OUTGOING_CORRUPT")
                if not await fail_arkade_lightning_payment(
                    intent_id,
                    account_id=account_id,
                    wallet_id=intent.wallet_id,
                    amount_msat=intent.amount_msat,
                    arkade_address=intent.destination,
                    conn=database,
                ):
                    raise ArkadeOutgoingError("ARKADE_OUTGOING_CORRUPT")
                await update_arkade_reconciliation(
                    account_id,
                    state="reconciliation_required",
                    # Fixed code for the account flag; the reported reason is
                    # kept on the intent itself.
                    last_error="ARKADE_LIGHTNING_SWAP_FAILED",
                    conn=database,
                )
            current = await get_arkade_outgoing_intent(intent_id, conn=database)
            payment = await get_payment_by_native_id(intent_id, conn=database)
            if not current or not payment:
                raise ArkadeOutgoingError("ARKADE_OUTGOING_CORRUPT")
            await create_arkade_lightning_terminal_event(
                intent_id, "failed", payment, database
            )
            inputs = await get_arkade_outgoing_intent_inputs(intent_id, conn=database)
    return _outgoing_response(current, binding, inputs)


async def reconcile_arkade_outgoing_intent(  # noqa: C901
    intent_id: str, account_id: str
) -> ArkadeOutgoingEvidenceResult | None:
    """Reconcile one submitted outgoing intent from public Arkade evidence."""
    intent = await get_arkade_outgoing_intent(intent_id)
    if (
        not intent
        or intent.account_id != account_id
        or intent.status != "submitted"
        or intent.destination_kind == "lightning"
    ):
        return None
    claims = await get_arkade_outgoing_intent_inputs(intent_id)
    if not claims or not intent.destination_script:
        raise ArkadeReceiveError("ARKADE_OUTGOING_CORRUPT")
    evidence = await verify_arkade_outgoing_evidence(
        account_id,
        claims,
        intent.destination_script,
        intent.amount_msat,
        intent.change_script,
        intent.change_amount_sat,
    )
    if evidence.status == "pending":
        return evidence

    async with db.connect() as database:
        async with database.transaction():
            await database.execute(
                "UPDATE arkade_account_bindings SET account_id = account_id "
                "WHERE account_id = :account_id AND state = 'ready'",
                {"account_id": account_id},
            )
            current_binding = await get_arkade_binding(account_id, conn=database)
            if not current_binding or current_binding.state != "ready":
                raise ArkadeReceiveError("ARKADE_OUTGOING_CORRUPT")
            current = await get_arkade_outgoing_intent(intent_id, conn=database)
            if not current or current.account_id != account_id:
                raise ArkadeReceiveError("ARKADE_OUTGOING_CORRUPT")
            current_claims = await get_arkade_outgoing_intent_inputs(
                intent_id, conn=database
            )
            payment = await get_payment_by_native_id(intent_id, conn=database)
            if current.status == "settled":
                if not payment or payment.status != PaymentState.SUCCESS.value:
                    raise ArkadeReceiveError("ARKADE_OUTGOING_CORRUPT")
                return None
            if current.status == "disputed":
                return evidence
            if current.status != "submitted":
                return None
            if (
                not payment
                or not _outgoing_payment_matches(payment, current)
                or payment.status != PaymentState.PENDING.value
                or not _same_outgoing_reconciliation_fields(intent, current)
                or not _same_outgoing_claims(claims, current_claims)
            ):
                raise ArkadeReceiveError("ARKADE_OUTGOING_CORRUPT")
            if evidence.status == "contradictory":
                disputed = await dispute_arkade_outgoing_intent(
                    intent_id, conn=database
                )
                if not disputed:
                    raise ArkadeReceiveError("ARKADE_OUTGOING_CORRUPT")
                return evidence
            if not evidence.arkade_txid:
                raise ArkadeReceiveError("ARKADE_OUTGOING_CORRUPT")
            settled = await settle_arkade_outgoing_intent_verified(
                intent_id, evidence.arkade_txid, conn=database
            )
            if not settled:
                raise ArkadeReceiveError("ARKADE_OUTGOING_CORRUPT")
            paid = await settle_arkade_outgoing_payment(
                intent_id,
                wallet_id=current.wallet_id,
                amount_msat=current.amount_msat,
                arkade_address=current.destination,
                conn=database,
            )
            if not paid:
                raise ArkadeReceiveError("ARKADE_OUTGOING_CORRUPT")
    return evidence


async def _mark_receive_reconciliation_required(
    account_id: str,
    reason: str,
    request_id: str | None = None,
    conn: Connection | None = None,
) -> None:
    if request_id:
        await mark_arkade_receive_request_reconciliation_required(request_id, conn=conn)
    await update_arkade_reconciliation(
        account_id,
        state="reconciliation_required",
        last_error=reason,
        conn=conn,
    )


def maintenance_statement(account_id: str, plan: ArkadeMaintenancePlan) -> str:
    inputs = ",".join(sorted(f"{i.txid}:{i.vout}:{i.amount_sat}" for i in plan.inputs))
    o = plan.output
    return "\n".join(
        [
            "action=lnbits-arkade-maintenance-v1",
            f"account_id={account_id}",
            f"operation_id={plan.operation_id}",
            f"inputs={inputs}",
            f"output={o.index}:{o.script}:{o.amount_sat}:{o.child_xonly_pubkey}",
        ]
    )


async def register_arkade_maintenance(  # noqa: C901
    account_id: str, plan: ArkadeMaintenancePlan
) -> None:
    if settings.lnbits_effective_installation_mode != "arkade_noncustodial":
        raise ArkadeOutgoingError("ARKADE_OUTGOING_UNAVAILABLE")
    await require_arkade_ready(account_id)
    binding = await get_arkade_binding(account_id)
    if not binding:
        raise ArkadeOutgoingError("ARKADE_ENROLLMENT_REQUIRED")
    _validate_owned_change(binding, plan.output)
    try:
        valid = PublicKeyXOnly(
            bytes.fromhex(binding.identity_xonly_pubkey or "")
        ).verify(
            bytes.fromhex(plan.signature),
            hashlib.sha256(
                maintenance_statement(account_id, plan).encode("ascii")
            ).digest(),
        )
    except ValueError:
        valid = False
    if not valid:
        raise ArkadeOutgoingError("ARKADE_RECEIVE_INVALID_PROOF")
    keys = {(i.txid, i.vout) for i in plan.inputs}
    if (
        len(keys) != len(plan.inputs)
        or sum(i.amount_sat for i in plan.inputs) != plan.output.amount_sat
    ):
        raise ArkadeOutgoingError("ARKADE_OUTGOING_INPUTS_INVALID")
    evidence = await fetch_arkade_indexer_vtxos(account_id)
    observed = {(v.txid, v.vout): v for v in evidence}
    async with db.connect() as conn:
        async with conn.transaction():
            await conn.execute(
                "UPDATE arkade_account_bindings SET account_id = account_id "
                "WHERE account_id = :id",
                {"id": account_id},
            )
            rows = await maintenance_rows(account_id, conn)
            existing = next(
                (r for r in rows if r["operation_id"] == plan.operation_id), None
            )
            if existing:
                if ArkadeMaintenancePlan.parse_raw(existing["plan_json"]) != plan:
                    raise ArkadeOutgoingError("ARKADE_OUTGOING_IDEMPOTENCY_CONFLICT")
                return
            state = await get_arkade_reconciliation(account_id, conn)
            if (
                state
                and state.state != "ok"
                and state.last_error != "ARKADE_RECONCILIATION_REQUIRED"
            ):
                raise ArkadeOutgoingError("ARKADE_BACKING_RECONCILIATION_REQUIRED")
            live = await conn.fetchone(
                "SELECT COUNT(*) AS count FROM arkade_outgoing_intents "
                "WHERE account_id = :id "
                "AND status IN ('reserved', 'quote_ready', 'submitted', 'disputed')",
                {"id": account_id},
            )
            if live["count"] or any(r["state"] == "planned" for r in rows):
                raise ArkadeOutgoingError("ARKADE_OUTGOING_BUSY")
            if any(v.script == plan.output.script for v in evidence):
                raise ArkadeOutgoingError("ARKADE_OUTGOING_OUTPUT_CONFLICT")
            for i in plan.inputs:
                v = observed.get((i.txid, i.vout))
                if (
                    not v
                    or v.amount_sat != i.amount_sat
                    or v.is_spent
                    or v.settled_by
                    or v.is_unrolled
                ):
                    raise ArkadeOutgoingError("ARKADE_OUTGOING_INPUT_UNAVAILABLE")
                prior = await conn.fetchone(
                    "SELECT operation_id FROM arkade_maintenance_inputs "
                    "WHERE txid = :txid AND vout = :vout",
                    {"txid": i.txid, "vout": i.vout},
                )
                if prior:
                    raise ArkadeOutgoingError("ARKADE_OUTGOING_INPUT_CONFLICT")
            try:
                await store_maintenance(account_id, plan, conn)
            except IntegrityError as exc:
                raise ArkadeOutgoingError("ARKADE_OUTGOING_INPUT_CONFLICT") from exc
            await update_arkade_reconciliation(
                account_id,
                state="reconciliation_required",
                last_error="ARKADE_RECONCILIATION_REQUIRED",
                conn=conn,
            )


async def get_arkade_backing_status(account_id: str) -> ArkadeBackingStatus:
    if settings.lnbits_effective_installation_mode != "arkade_noncustodial":
        raise ArkadeOutgoingError("ARKADE_OUTGOING_UNAVAILABLE")
    await require_arkade_ready(account_id)
    evidence = await fetch_arkade_indexer_vtxos(account_id)
    async with db.connect() as conn:
        async with conn.transaction():
            payments = await reconcile_arkade_receive(account_id, evidence, conn=conn)
            state = await get_arkade_reconciliation(account_id, conn)
            balances = await conn.fetchone(
                "SELECT COALESCE(SUM(b.balance), 0) AS total FROM balances b "
                'JOIN wallets w ON w.id = b.wallet_id WHERE w."user" = :id',
                {"id": account_id},
            )
            rows = await maintenance_rows(account_id, conn)
    for payment in payments:
        task_manager.invoice_queue.put_nowait(payment)
    # Settlement outputs have settledBy; they are historical, not recoverable.
    owned = [
        v for v in evidence if not v.is_spent and not v.settled_by and not v.is_unrolled
    ]
    now = datetime.now(timezone.utc)
    return ArkadeBackingStatus(
        ledger_msat=int(balances["total"]),
        spendable_sat=sum(v.amount_sat for v in owned if _is_spendable_vtxo(v)),
        recoverable_sat=sum(v.amount_sat for v in owned if not _is_spendable_vtxo(v)),
        expiring_sat=sum(
            v.amount_sat
            for v in owned
            if _is_spendable_vtxo(v)
            and v.expires_at
            and v.expires_at <= now + timedelta(days=3)
        ),
        state=state.state if state else "ok",
        last_error=state.last_error if state else None,
        maintenance=next(
            (
                ArkadeMaintenancePlan.parse_raw(r["plan_json"])
                for r in rows
                if r["state"] == "planned"
            ),
            None,
        ),
        maintenance_inputs=[
            ArkadeOutgoingSelectedInput(
                txid=v.txid, vout=v.vout, amount_sat=v.amount_sat
            )
            for v in owned
            if not _is_spendable_vtxo(v)
            or (v.expires_at and v.expires_at <= now + timedelta(days=3))
        ][:100],
    )


async def resolve_arkade_reconciliation(
    account_id: str,
    reason: str,
    *,
    actor_id: str,
) -> tuple[ArkadeReconciliation, ArkadeReconciliation]:
    """Clear a sticky reconciliation flag as a deliberate operator action.

    Returns the previous and the resulting state; an account that is already
    `ok` (or has no state row yet) is left untouched except for the binding
    check that proves the account is an enrolled one.
    """
    async with db.connect() as conn:
        async with conn.transaction():
            previous = await get_arkade_reconciliation(account_id, conn=conn)
            if not previous:
                if not await get_arkade_binding(account_id, conn=conn):
                    raise ArkadeReconciliationError("ARKADE_RECONCILIATION_NOT_FOUND")
                previous = ArkadeReconciliation(account_id=account_id)
            if previous.state == "ok":
                return previous, previous
            resolved = await update_arkade_reconciliation(
                account_id, state="ok", last_error=None, conn=conn
            )
            await create_audit_entry(
                AuditEntry(
                    component="arkade",
                    user_id=actor_id,
                    path="/api/v1/arkade/reconciliation/resolve",
                    request_method="POST",
                    request_details=json.dumps(
                        {
                            "account_id": account_id,
                            "reason": reason,
                            "previous_state": previous.state,
                            "last_error": previous.last_error,
                        }
                    ),
                    response_code="200",
                    duration=0.0,
                ),
                conn=conn,
            )
            return previous, resolved


def _arkade_backing_diverged(vtxo: ArkadeIndexerVtxo, claim: dict | None) -> bool:
    # A verified spend no longer needs this historical input as backing.
    if vtxo.is_spent and claim and claim["status"] == "settled":
        expected_txid = claim["arkade_txid"]
        if claim["destination_kind"] == "lightning":
            expected_txid = (
                claim["settlement_ark_txid"]
                or claim["refund_ark_txid"]
                or expected_txid
            )
        return (
            int(claim["amount_sat"]) != vtxo.amount_sat
            or expected_txid != vtxo.arkade_txid
        )
    if (
        vtxo.is_swept
        or vtxo.is_unrolled
        or vtxo.settled_by
        or vtxo.expires_at_height is not None
        or (
            vtxo.expires_at is not None
            and vtxo.expires_at <= datetime.now(timezone.utc)
        )
    ):
        return True
    if not vtxo.is_spent:
        return False
    if not claim or int(claim["amount_sat"]) != vtxo.amount_sat:
        return True
    if claim["status"] == "disputed":
        return True
    if claim["status"] != "settled":
        return False
    expected_txid = claim["arkade_txid"]
    if claim["destination_kind"] == "lightning":
        expected_txid = (
            claim["settlement_ark_txid"] or claim["refund_ark_txid"] or expected_txid
        )
    return expected_txid != vtxo.arkade_txid


async def reconcile_arkade_receive(  # noqa: C901
    account_id: str,
    evidence: list[ArkadeIndexerVtxo],
    *,
    conn: Connection | None = None,
) -> list[Payment]:
    if settings.lnbits_effective_installation_mode != "arkade_noncustodial":
        raise ArkadeReceiveError("ARKADE_RECEIVE_UNAVAILABLE")
    await require_arkade_ready(account_id, conn=conn)
    previous_state = await get_arkade_reconciliation(account_id, conn=conn)
    # Every guard below re-derives from the current evidence and rows, so the
    # previous state is not inherited: inheriting it latched transient
    # conditions (an unattributed VTXO seen before its receive request was
    # recorded, for example) and locked the account permanently.
    required = False
    last_error: str | None = None
    observed: dict[tuple[str, int], ArkadeIndexerVtxo] = {}
    for vtxo in evidence:
        key = (vtxo.txid, vtxo.vout)
        if key in observed and observed[key] != vtxo:
            required = True
            last_error = "ARKADE_RECONCILIATION_REQUIRED"
        observed[key] = vtxo
    database = conn or db
    consumed, maintenance_outputs, restored = await reconcile_maintenance(
        account_id, evidence, database
    )
    if (
        restored
        and previous_state
        and previous_state.last_error == "ARKADE_RECONCILIATION_REQUIRED"
    ):
        # Re-run every guard; a completed renewal only permits reconsidering
        # generic backing divergence, never another class of sticky conflict.
        required = False
        last_error = None
    claims = await database.fetchall(
        "SELECT i.txid, i.vout, i.amount_sat, o.status, o.arkade_txid, "
        "o.destination_kind, o.settlement_ark_txid, o.refund_ark_txid "
        "FROM arkade_outgoing_intent_inputs i "
        "JOIN arkade_outgoing_intents o ON o.intent_id = i.intent_id "
        "WHERE o.account_id = :account_id "
        "AND o.status IN ('submitted', 'settled', 'disputed')",
        {"account_id": account_id},
    )
    claims_by_outpoint = {(row["txid"], int(row["vout"])): row for row in claims}
    # A browser-funded swap is funded by the client's own SDK send, not by the
    # authorized outgoing flow, so nothing journals which wallet VTXO that
    # funding spent or where the change went. Attribute both from the observed
    # evidence: a spend by one of our own funding transactions is expected, and
    # output 1 of that funding transaction is this account's change.
    funding_intents = await database.fetchall(
        "SELECT intent_id, arkade_txid, change_script, change_amount_sat "
        "FROM arkade_outgoing_intents "
        "WHERE account_id = :account_id AND arkade_txid IS NOT NULL "
        "AND status IN ('submitted', 'settled', 'disputed')",
        {"account_id": account_id},
    )
    own_funding_txids = {
        row["arkade_txid"]: row
        for row in funding_intents
        if row["arkade_txid"] is not None
    }
    known_outpoints = await database.fetchall(
        "SELECT txid, vout FROM arkade_receive_outpoints "
        "WHERE account_id = :account_id",
        {"account_id": account_id},
    )
    for row in known_outpoints:
        key = (row["txid"], int(row["vout"]))
        if key in consumed:
            continue
        vtxo = observed.get(key)
        claim = claims_by_outpoint.get(key)
        if (
            claim is None
            and vtxo is not None
            and vtxo.is_spent
            and vtxo.arkade_txid in own_funding_txids
        ):
            # Our own browser-funded swap consumed this VTXO.
            continue
        if not vtxo or _arkade_backing_diverged(vtxo, claim):
            required = True
            last_error = "ARKADE_RECONCILIATION_REQUIRED"
    changes = await database.fetchall(
        "SELECT status, arkade_txid, change_script, change_amount_sat "
        "FROM arkade_outgoing_intents "
        "WHERE account_id = :account_id "
        "AND status IN ('submitted', 'settled', 'disputed') "
        "AND arkade_txid IS NOT NULL",
        {"account_id": account_id},
    )
    change_outpoints: set[tuple[str, int]] = set()
    for row in changes:
        recorded = (
            row["change_script"] is not None and row["change_amount_sat"] is not None
        )
        key = (row["arkade_txid"], 1)
        if key in consumed:
            continue
        vtxo = observed.get(key)
        if vtxo is None:
            # Submitted change may not be indexed yet. Outgoing verification
            # owns that pending state; a missing terminal change is divergence.
            if recorded and row["status"] != "submitted":
                required = True
                last_error = "ARKADE_RECONCILIATION_REQUIRED"
            continue
        change_outpoints.add(key)
        if not recorded:
            # Browser-funded swaps do not journal their change, and the change
            # index is the wallet derivation index the client chose (it is
            # unique per account), so it cannot be derived here. Treat output 1
            # of the funding transaction as this account's change: skip it from
            # the unattributed check instead of inventing an index.
            continue
        if vtxo.is_spent and vtxo.arkade_txid in own_funding_txids:
            # Our own later funding spent this change; already explained.
            continue
        if (
            vtxo.script != row["change_script"]
            or vtxo.amount_sat != int(row["change_amount_sat"])
            or _arkade_backing_diverged(vtxo, claims_by_outpoint.get(key))
        ):
            required = True
            last_error = "ARKADE_RECONCILIATION_REQUIRED"
    settled_payments: list[Payment] = []
    for key in maintenance_outputs - consumed:
        vtxo = observed.get(key)
        if not vtxo or _arkade_backing_diverged(vtxo, claims_by_outpoint.get(key)):
            required = True
            last_error = "ARKADE_RECONCILIATION_REQUIRED"
    if any(r["state"] == "planned" for r in await maintenance_rows(account_id, conn)):
        required = True
        last_error = last_error or "ARKADE_RECONCILIATION_REQUIRED"
    # The recorded ledger must never exceed the spendable backing we can prove.
    # Only checked once a renewal has completed, or on an account that is
    # already flagged: while a renewal is in flight the old inputs are spent
    # and the new outputs are not indexed yet, so a healthy account is
    # genuinely over-credit for a pass. Re-checking a flagged account keeps the
    # verdict stable across replays instead of clearing it on the next pass.
    already_flagged = bool(
        previous_state and previous_state.state == "reconciliation_required"
    )
    if restored or already_flagged:
        balances = await database.fetchone(
            "SELECT COALESCE(SUM(b.balance), 0) AS total FROM balances b "
            'JOIN wallets w ON w.id = b.wallet_id WHERE w."user" = :id',
            {"id": account_id},
        )
        if int(balances["total"]) > sum(
            v.amount_sat * 1000 for v in evidence if _is_spendable_vtxo(v)
        ):
            required = True
            last_error = "ARKADE_RECONCILIATION_REQUIRED"
    for vtxo in evidence:
        if (vtxo.txid, vtxo.vout) in change_outpoints | consumed | maintenance_outputs:
            continue
        request = await get_arkade_receive_request_by_script(
            account_id, vtxo.script, conn=conn
        )
        existing = await get_arkade_receive_outpoint(vtxo.txid, vtxo.vout, conn=conn)
        if existing:
            if (
                existing.get("spent_by")
                and vtxo.spent_by
                and existing["spent_by"] != vtxo.spent_by
            ):
                required = True
                last_error = "ARKADE_OUTPOINT_TERMINAL_CONFLICT"
                await mark_arkade_receive_outpoint_conflict(
                    vtxo.txid, vtxo.vout, account_id, conn=conn
                )
                continue
            if (
                existing["account_id"] == account_id
                and existing["native_request_id"] is None
                and existing["status"] != "conflict"
                and request
                and existing["script"] == vtxo.script
                and int(existing["amount_sat"]) == vtxo.amount_sat
            ):
                await update_arkade_receive_outpoint_attribution(
                    vtxo.txid, vtxo.vout, request.native_request_id, conn=conn
                )
                await update_arkade_receive_outpoint(vtxo, conn=conn)
                continue
            if (
                existing["account_id"] != account_id
                or existing["script"] != vtxo.script
                or int(existing["amount_sat"]) != vtxo.amount_sat
                or existing["native_request_id"]
                != (request.native_request_id if request else None)
            ):
                required = True
                last_error = "ARKADE_OUTPOINT_CONFLICT"
                await mark_arkade_receive_outpoint_conflict(
                    vtxo.txid, vtxo.vout, account_id, conn=conn
                )
                continue
            await update_arkade_receive_outpoint(vtxo, conn=conn)
            continue
        if not request:
            required = True
            last_error = "ARKADE_UNATTRIBUTED_VALUE"
            created = await create_arkade_receive_outpoint(
                account_id=account_id,
                native_request_id=None,
                vtxo=vtxo,
                status="unattributed",
                conn=conn,
            )
            if not created:
                winner = await get_arkade_receive_outpoint(
                    vtxo.txid, vtxo.vout, conn=conn
                )
                if winner and _outpoint_matches(winner, account_id, None, vtxo):
                    await update_arkade_receive_outpoint(vtxo, conn=conn)
                else:
                    last_error = "ARKADE_OUTPOINT_CONFLICT"
                    await mark_arkade_receive_outpoint_conflict(
                        vtxo.txid, vtxo.vout, account_id, conn=conn
                    )
            continue
        created = await create_arkade_receive_outpoint(
            account_id=account_id,
            native_request_id=request.native_request_id,
            vtxo=vtxo,
            status="valid",
            conn=conn,
        )
        if not created:
            winner = await get_arkade_receive_outpoint(vtxo.txid, vtxo.vout, conn=conn)
            if winner and _outpoint_matches(
                winner, account_id, request.native_request_id, vtxo
            ):
                await update_arkade_receive_outpoint(vtxo, conn=conn)
            else:
                required = True
                last_error = "ARKADE_OUTPOINT_CONFLICT"
                await mark_arkade_receive_outpoint_conflict(
                    vtxo.txid, vtxo.vout, account_id, conn=conn
                )
    requests = await get_arkade_receive_requests(account_id, conn=conn)
    for request in requests:
        if request.state == "reconciliation_required":
            required = True
            last_error = last_error or "ARKADE_RECONCILIATION_REQUIRED"
            continue
        total = await get_arkade_receive_request_total(
            request.native_request_id, conn=conn
        )
        if total > request.amount_sat:
            required = True
            last_error = "ARKADE_RECEIVE_AMOUNT_CONFLICT"
            await mark_arkade_receive_outpoints_conflict(
                request.native_request_id, conn=conn
            )
            await _mark_receive_reconciliation_required(
                account_id,
                "ARKADE_RECEIVE_AMOUNT_CONFLICT",
                request.native_request_id,
                conn,
            )
        elif total == request.amount_sat and request.state in {
            "acknowledged",
            "settled",
        }:
            address = request.address
            payment = await get_payment_by_native_id(
                request.native_request_id, conn=conn
            )
            if payment:
                if (
                    payment.protocol != "arkade"
                    or payment.native_id != request.native_request_id
                    or payment.wallet_id != request.wallet_id
                    or payment.amount != request.amount_sat * 1000
                    or not address
                    or payment.arkade_address != address
                ):
                    required = True
                    last_error = "ARKADE_RECONCILIATION_REQUIRED"
                    await mark_arkade_receive_outpoints_conflict(
                        request.native_request_id, conn=conn
                    )
                    await _mark_receive_reconciliation_required(
                        account_id,
                        last_error,
                        request.native_request_id,
                        conn,
                    )
                    continue
                if payment.status in {
                    PaymentState.PENDING.value,
                    PaymentState.FAILED.value,
                }:
                    updated = await compare_and_set_payment_success(
                        request.native_request_id,
                        wallet_id=request.wallet_id,
                        amount_msat=request.amount_sat * 1000,
                        arkade_address=address,
                        conn=conn,
                    )
                    if updated:
                        payment.status = PaymentState.SUCCESS.value
                        settled_payments.append(payment)
                    else:
                        current = await get_payment_by_native_id(
                            request.native_request_id, conn=conn
                        )
                        if not current or current.status != PaymentState.SUCCESS.value:
                            required = True
                            last_error = "ARKADE_RECONCILIATION_REQUIRED"
                            await _mark_receive_reconciliation_required(
                                account_id,
                                last_error,
                                request.native_request_id,
                                conn,
                            )
                            continue
                elif payment.status != PaymentState.SUCCESS.value:
                    required = True
                    last_error = "ARKADE_RECONCILIATION_REQUIRED"
                    await _mark_receive_reconciliation_required(
                        account_id,
                        last_error,
                        request.native_request_id,
                        conn,
                    )
                    continue
            if request.state != "settled":
                now = datetime.now(timezone.utc)
                await settle_arkade_receive_request(
                    request.native_request_id, now, conn=conn
                )
    # Recorded conflicts are durable facts that evidence may stop re-reporting
    # once the offending VTXO leaves the indexer, so they are read back rather
    # than re-derived. Everything else clears once its cause is gone. Checked
    # last so the specific terminal reason wins over a generic guard.
    conflicts = await database.fetchone(
        "SELECT COUNT(*) AS count FROM arkade_receive_outpoints "
        "WHERE account_id = :account_id AND status = 'conflict'",
        {"account_id": account_id},
    )
    if conflicts and conflicts["count"]:
        required = True
        last_error = "ARKADE_OUTPOINT_CONFLICT"
    disputed = await database.fetchone(
        "SELECT COUNT(*) AS count FROM arkade_outgoing_intents "
        "WHERE account_id = :account_id AND status = 'disputed'",
        {"account_id": account_id},
    )
    if disputed and disputed["count"]:
        required = True
        last_error = "ARKADE_LIGHTNING_EVIDENCE_CONTRADICTORY"
    state = "reconciliation_required" if required else "ok"
    await update_arkade_reconciliation(
        account_id,
        state=state,
        last_error=last_error if required else None,
        conn=conn,
    )
    return settled_payments
