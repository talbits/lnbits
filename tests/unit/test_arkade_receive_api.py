from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from lnbits.core.models import Account, ArkadeReceiveRequest
from lnbits.core.services.arkade import ArkadeEnrollmentError, ArkadeReceiveError
from lnbits.core.views.arkade_api import arkade_router
from lnbits.decorators import check_authenticated_account

ACCOUNT_ID = "00" * 16
WALLET_ID = "11" * 16
REQUEST_ID = "22" * 16


def _app(account: Account | None = None) -> FastAPI:
    app = FastAPI()
    app.include_router(arkade_router)
    if account:
        app.dependency_overrides[check_authenticated_account] = lambda: account
    return app


def _request() -> ArkadeReceiveRequest:
    return ArkadeReceiveRequest(
        account_id=ACCOUNT_ID,
        wallet_id=WALLET_ID,
        native_request_id=REQUEST_ID,
        idempotency_key="33" * 16,
        amount_sat=100,
        network="regtest",
        server_url="http://arkade",
        server_pubkey="44" * 32,
        expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
    )


def _ack_payload() -> dict:
    return {
        "native_request_id": REQUEST_ID,
        "account_id": ACCOUNT_ID,
        "wallet_id": WALLET_ID,
        "idempotency_key": "33" * 16,
        "amount_sat": 100,
        "index": 0,
        "address": (
            "tark1qpzyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyf2"
            "42424242424242424242424242424242424242424242424242uer577"
        ),
        "script": "5120" + "aa" * 32,
        "child_xonly_pubkey": "55" * 32,
        "network": "regtest",
        "server_url": "http://arkade",
        "server_pubkey": "44" * 32,
        "expires_at": int(_request().expires_at.timestamp()),
        "signature": "66" * 64,
        "exit_tapleaf": "00" * 38,
        "exit_control_block": "00" * 65,
    }


@pytest.mark.anyio
async def test_receive_api_requires_auth_and_sanitizes_errors(monkeypatch):
    unauthenticated = _app()
    async with AsyncClient(
        transport=ASGITransport(app=unauthenticated), base_url="http://test"
    ) as client:
        response = await client.post("/api/v1/arkade/receive/ack", json=_ack_payload())
    assert response.status_code == 401

    app = _app(Account(id=ACCOUNT_ID))
    monkeypatch.setattr(
        "lnbits.core.views.arkade_api.acknowledge_arkade_receive",
        AsyncMock(side_effect=ArkadeReceiveError("ARKADE_RECEIVE_MAPPING_CONFLICT")),
    )
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        conflict = await client.post("/api/v1/arkade/receive/ack", json=_ack_payload())
    assert conflict.status_code == 400
    assert conflict.json()["detail"] == "ARKADE_RECEIVE_MAPPING_CONFLICT"

    monkeypatch.setattr(
        "lnbits.core.views.arkade_api.acknowledge_arkade_receive",
        AsyncMock(side_effect=ArkadeEnrollmentError("ARKADE_ENROLLMENT_REQUIRED")),
    )
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        not_ready = await client.post("/api/v1/arkade/receive/ack", json=_ack_payload())
    assert not_ready.status_code == 400
    assert not_ready.json()["detail"] == "ARKADE_ENROLLMENT_REQUIRED"
