from http import HTTPStatus

from fastapi import APIRouter, Depends, Header, HTTPException

from lnbits.core.models import (
    Account,
    ArkadeEnrollmentBindingResponse,
    ArkadeEnrollmentChallenge,
    ArkadeEnrollmentCompletion,
    ArkadeReceiveAcknowledgement,
    ArkadeReceiveRequest,
)
from lnbits.core.services.arkade import (
    ArkadeEnrollmentError,
    ArkadeReceiveError,
    acknowledge_arkade_receive,
    complete_enrollment,
    create_enrollment_challenge,
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
