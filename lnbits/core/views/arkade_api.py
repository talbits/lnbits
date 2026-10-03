from http import HTTPStatus

from fastapi import APIRouter, Depends, Header, HTTPException, Query

from lnbits.core.models import (
    Account,
    ArkadeEnrollmentBindingResponse,
    ArkadeEnrollmentChallenge,
    ArkadeEnrollmentCompletion,
    ArkadeLightningFailureReport,
    ArkadeLightningFundingEvidence,
    ArkadeOutgoingAuthorizeRequest,
    ArkadeOutgoingIntentResponse,
    ArkadeReceiveAcknowledgement,
    ArkadeReceiveRequest,
    SimpleStatus,
)
from lnbits.core.models.arkade import ArkadeBackingStatus
from lnbits.core.services.arkade import (
    ArkadeEnrollmentError,
    ArkadeEnrollmentMigrationRequiredError,
    ArkadeOutgoingError,
    ArkadeReceiveError,
    acknowledge_arkade_receive,
    authorize_arkade_outgoing,
    complete_enrollment,
    create_enrollment_challenge,
    fail_arkade_lightning_intent,
    get_arkade_backing_status,
    get_arkade_outgoing_intent_for_account,
    get_arkade_receive_request_for_account,
    list_arkade_submitted_outgoing_intents,
    release_arkade_outgoing_payment,
    submit_arkade_lightning_intent,
)
from lnbits.decorators import check_authenticated_account

arkade_router = APIRouter(prefix="/api/v1/arkade", tags=["Arkade"])


@arkade_router.get("/backing", response_model=ArkadeBackingStatus)
async def api_arkade_backing(account: Account = Depends(check_authenticated_account)):
    try:
        return await get_arkade_backing_status(account.id)
    except ArkadeOutgoingError as exc:
        raise _public_outgoing_error(exc) from exc
    except (ArkadeReceiveError, ArkadeEnrollmentError) as exc:
        raise HTTPException(
            HTTPStatus.BAD_REQUEST, "ARKADE_BACKING_UNAVAILABLE"
        ) from exc


def _public_error(exc: ArkadeEnrollmentError) -> HTTPException:
    if isinstance(exc, ArkadeEnrollmentMigrationRequiredError):
        return HTTPException(
            HTTPStatus.BAD_REQUEST, "ARKADE_ENROLLMENT_MIGRATION_REQUIRED"
        )
    return HTTPException(HTTPStatus.BAD_REQUEST, "ARKADE_ENROLLMENT_ERROR")


def _public_receive_error(exc: ArkadeReceiveError) -> HTTPException:
    code = str(exc)
    if code not in {
        "ARKADE_RECEIVE_ACCOUNT_MISMATCH",
        "ARKADE_RECEIVE_INVALID_MAPPING",
        "ARKADE_RECEIVE_INVALID_PROOF",
        "ARKADE_RECEIVE_MAPPING_CONFLICT",
        "ARKADE_RECEIVE_NOT_FOUND",
        "ARKADE_RECEIVE_UNAVAILABLE",
        "ARKADE_ENROLLMENT_REQUIRED",
    }:
        code = "ARKADE_RECEIVE_ERROR"
    return HTTPException(HTTPStatus.BAD_REQUEST, code)


def _public_outgoing_error(exc: ArkadeOutgoingError) -> HTTPException:
    code = str(exc)
    if code not in {
        "ARKADE_ENROLLMENT_REQUIRED",
        "ARKADE_INTENT_INVALID_TRANSITION",
        "ARKADE_LIGHTNING_FAILURE_REASON_INVALID",
        "ARKADE_OUTGOING_ACCOUNT_MISMATCH",
        "ARKADE_OUTGOING_BUSY",
        "ARKADE_OUTGOING_CORRUPT",
        "ARKADE_OUTGOING_EXPIRED",
        "ARKADE_OUTGOING_IDEMPOTENCY_CONFLICT",
        "ARKADE_OUTGOING_INDEXER_INVALID",
        "ARKADE_OUTGOING_INDEXER_UNAVAILABLE",
        "ARKADE_OUTGOING_INPUTS_INVALID",
        "ARKADE_OUTGOING_NOT_ALLOWED",
        "ARKADE_OUTGOING_NOT_FOUND",
        "ARKADE_OUTGOING_OUTPUT_CONFLICT",
        "ARKADE_OUTGOING_OUTPUT_INVALID",
        "ARKADE_OUTGOING_INVALID_REQUEST",
        "ARKADE_OUTGOING_UNAVAILABLE",
        "ARKADE_DESCRIPTOR_REENROLLMENT_REQUIRED",
        "ARKADE_INSUFFICIENT_FUNDS",
        "ARKADE_WALLET_NOT_OWNED",
        "ARKADE_TRANSFER_DESTINATION_NOT_FOUND",
        "ARKADE_TRANSFER_CROSS_ACCOUNT_REQUIRED",
        "ARKADE_TRANSFER_RECEIVER_NOT_ALLOWED",
        "ARKADE_TRANSFER_SAME_WALLET",
        "ARKADE_TRANSFER_MAPPING_NOT_READY",
        "ARKADE_TRANSFER_EXPIRED",
        "ARKADE_TRANSFER_AMOUNT_CONFLICT",
        "ARKADE_TRANSFER_RECEIVER_INVALID",
        "ARKADE_TRANSFER_CORRUPT",
        "ARKADE_TRANSFER_REQUEST_CONSUMED",
        "ARKADE_TRANSACTION_ID_INVALID",
    }:
        code = "ARKADE_OUTGOING_ERROR"
    return HTTPException(HTTPStatus.BAD_REQUEST, code)


@arkade_router.post(
    "/enrollment/challenge",
    response_model=ArkadeEnrollmentChallenge | ArkadeEnrollmentBindingResponse,
)
async def api_arkade_enrollment_challenge(
    account: Account = Depends(check_authenticated_account),
    idempotency_key: str | None = Header(None, alias="Idempotency-Key"),
):
    try:
        return await create_enrollment_challenge(account, idempotency_key)
    except ArkadeEnrollmentError as exc:
        raise _public_error(exc) from exc


@arkade_router.post(
    "/enrollment/complete",
    response_model=ArkadeEnrollmentBindingResponse,
)
async def api_arkade_enrollment_complete(
    data: ArkadeEnrollmentCompletion,
    account: Account = Depends(check_authenticated_account),
):
    try:
        return await complete_enrollment(account, data)
    except ArkadeEnrollmentError as exc:
        raise _public_error(exc) from exc


@arkade_router.get("/receive/{native_request_id}", response_model=ArkadeReceiveRequest)
async def api_arkade_receive_request(
    native_request_id: str,
    account: Account = Depends(check_authenticated_account),
):
    try:
        return await get_arkade_receive_request_for_account(
            account.id, native_request_id
        )
    except ArkadeEnrollmentError as exc:
        if str(exc) == "ARKADE_ENROLLMENT_REQUIRED":
            raise HTTPException(
                HTTPStatus.BAD_REQUEST, "ARKADE_ENROLLMENT_REQUIRED"
            ) from exc
        raise _public_error(exc) from exc
    except ArkadeReceiveError as exc:
        raise _public_receive_error(exc) from exc


@arkade_router.post("/receive/ack", response_model=ArkadeReceiveRequest)
async def api_arkade_receive_ack(
    data: ArkadeReceiveAcknowledgement,
    account: Account = Depends(check_authenticated_account),
):
    try:
        return await acknowledge_arkade_receive(account.id, data)
    except ArkadeEnrollmentError as exc:
        if str(exc) == "ARKADE_ENROLLMENT_REQUIRED":
            raise HTTPException(
                HTTPStatus.BAD_REQUEST, "ARKADE_ENROLLMENT_REQUIRED"
            ) from exc
        raise _public_error(exc) from exc
    except ArkadeReceiveError as exc:
        raise _public_receive_error(exc) from exc


@arkade_router.get("/outgoing", response_model=list[ArkadeOutgoingIntentResponse])
async def api_arkade_submitted_outgoing_intents(
    limit: int = Query(32, ge=1, le=32),
    account: Account = Depends(check_authenticated_account),
):
    try:
        return await list_arkade_submitted_outgoing_intents(account.id, limit)
    except ArkadeOutgoingError as exc:
        raise _public_outgoing_error(exc) from exc


@arkade_router.get("/outgoing/{intent_id}", response_model=ArkadeOutgoingIntentResponse)
async def api_arkade_outgoing_intent(
    intent_id: str,
    account: Account = Depends(check_authenticated_account),
):
    try:
        return await get_arkade_outgoing_intent_for_account(account.id, intent_id)
    except ArkadeOutgoingError as exc:
        raise _public_outgoing_error(exc) from exc


@arkade_router.post(
    "/outgoing/{intent_id}/authorize",
    response_model=ArkadeOutgoingIntentResponse,
)
async def api_arkade_outgoing_authorize(
    intent_id: str,
    data: ArkadeOutgoingAuthorizeRequest,
    account: Account = Depends(check_authenticated_account),
):
    try:
        return await authorize_arkade_outgoing(
            account.id,
            intent_id,
            data.inputs,
            destination_script=data.destination_script,
            change=data.change,
        )
    except ArkadeOutgoingError as exc:
        raise _public_outgoing_error(exc) from exc


@arkade_router.post("/outgoing/{intent_id}/release", response_model=SimpleStatus)
async def api_arkade_outgoing_release(
    intent_id: str,
    account: Account = Depends(check_authenticated_account),
):
    try:
        await release_arkade_outgoing_payment(account.id, intent_id)
        return SimpleStatus(success=True, message="Arkade reservation released.")
    except ArkadeOutgoingError as exc:
        raise _public_outgoing_error(exc) from exc


@arkade_router.post(
    "/outgoing/{intent_id}/submit",
    response_model=ArkadeOutgoingIntentResponse,
)
async def api_arkade_lightning_submit(
    intent_id: str,
    data: ArkadeLightningFundingEvidence,
    account: Account = Depends(check_authenticated_account),
):
    try:
        return await submit_arkade_lightning_intent(account.id, intent_id, data)
    except ArkadeOutgoingError as exc:
        raise _public_outgoing_error(exc) from exc


@arkade_router.post(
    "/outgoing/{intent_id}/fail",
    response_model=ArkadeOutgoingIntentResponse,
)
async def api_arkade_lightning_fail(
    intent_id: str,
    data: ArkadeLightningFailureReport,
    account: Account = Depends(check_authenticated_account),
):
    """Record a browser-observed terminal claim failure for a funded swap."""
    try:
        return await fail_arkade_lightning_intent(account.id, intent_id, data.reason)
    except ArkadeOutgoingError as exc:
        raise _public_outgoing_error(exc) from exc
