from http import HTTPStatus

from fastapi import APIRouter, Depends, Header, HTTPException

from lnbits.core.models import (
    Account,
    ArkadeEnrollmentBindingResponse,
    ArkadeEnrollmentChallenge,
    ArkadeEnrollmentCompletion,
    ArkadeOutgoingAuthorizeRequest,
    ArkadeOutgoingIntentResponse,
    ArkadeReceiveAcknowledgement,
    ArkadeReceiveRequest,
)
from lnbits.core.services.arkade import (
    ArkadeEnrollmentError,
    ArkadeOutgoingError,
    ArkadeReceiveError,
    acknowledge_arkade_receive,
    authorize_arkade_outgoing,
    complete_enrollment,
    create_enrollment_challenge,
    get_arkade_outgoing_intent_for_account,
    get_arkade_receive_request_for_account,
)
from lnbits.decorators import check_authenticated_account

arkade_router = APIRouter(prefix="/api/v1/arkade", tags=["Arkade"])


def _public_error(exc: ArkadeEnrollmentError) -> HTTPException:
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
        "ARKADE_OUTGOING_ACCOUNT_MISMATCH",
        "ARKADE_OUTGOING_BUSY",
        "ARKADE_OUTGOING_CORRUPT",
        "ARKADE_OUTGOING_EXPIRED",
        "ARKADE_OUTGOING_IDEMPOTENCY_CONFLICT",
        "ARKADE_OUTGOING_INDEXER_INVALID",
        "ARKADE_OUTGOING_INDEXER_UNAVAILABLE",
        "ARKADE_OUTGOING_INPUT_CONFLICT",
        "ARKADE_OUTGOING_INPUT_UNAVAILABLE",
        "ARKADE_OUTGOING_INPUT_UNREGISTERED",
        "ARKADE_OUTGOING_INPUT_VALUE_MISMATCH",
        "ARKADE_OUTGOING_INPUTS_INVALID",
        "ARKADE_OUTGOING_INPUTS_MISSING",
        "ARKADE_OUTGOING_NOT_ALLOWED",
        "ARKADE_OUTGOING_NOT_FOUND",
        "ARKADE_OUTGOING_OUTPUT_CONFLICT",
        "ARKADE_OUTGOING_OUTPUT_INVALID",
        "ARKADE_OUTGOING_UNAVAILABLE",
        "ARKADE_DESCRIPTOR_REENROLLMENT_REQUIRED",
        "ARKADE_INSUFFICIENT_FUNDS",
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
