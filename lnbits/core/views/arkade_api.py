from http import HTTPStatus

from fastapi import APIRouter, Depends, Header, HTTPException

from lnbits.core.models import (
    Account,
    ArkadeEnrollmentBindingResponse,
    ArkadeEnrollmentChallenge,
    ArkadeEnrollmentCompletion,
)
from lnbits.core.services.arkade import (
    ArkadeEnrollmentError,
    complete_enrollment,
    create_enrollment_challenge,
)
from lnbits.decorators import check_authenticated_account

arkade_router = APIRouter(prefix="/api/v1/arkade", tags=["Arkade"])


def _public_error(exc: ArkadeEnrollmentError) -> HTTPException:
    return HTTPException(HTTPStatus.BAD_REQUEST, "ARKADE_ENROLLMENT_ERROR")


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
