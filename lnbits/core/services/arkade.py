import hashlib
import re
from datetime import datetime, timedelta, timezone
from secrets import token_hex

from coincurve import PublicKeyXOnly
from sqlalchemy.exc import IntegrityError

from lnbits.core.crud.arkade import (
    complete_arkade_binding,
    get_arkade_binding,
    update_arkade_challenge,
)
from lnbits.core.models import (
    ArkadeAccountBinding,
    ArkadeEnrollmentBindingResponse,
    ArkadeEnrollmentChallenge,
    ArkadeEnrollmentCompletion,
)
from lnbits.core.models.users import Account
from lnbits.db import Connection
from lnbits.settings import settings

ENROLLMENT_ACTION = "lnbits-arkade-enrollment-v1"
IDENTITY_KIND = "mnemonic_hd"
CHALLENGE_TTL_SECONDS = 10 * 60
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_ID = re.compile(r"^[0-9a-f]{32}$")
_IDEMPOTENCY = re.compile(r"^[0-9a-f]{32}$")


class ArkadeEnrollmentError(ValueError):
    pass


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
        raise ArkadeEnrollmentError("Arkade enrollment is unavailable.")
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
