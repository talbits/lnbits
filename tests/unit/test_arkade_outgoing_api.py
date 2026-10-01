from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from lnbits.core.models import (
    Account,
    ArkadeOutgoingIntentInput,
    ArkadeOutgoingIntentResponse,
)
from lnbits.core.services.arkade import ArkadeOutgoingError
from lnbits.core.views.arkade_api import arkade_router
from lnbits.decorators import check_authenticated_account

ACCOUNT_ID = "00" * 16
OTHER_ACCOUNT_ID = "99" * 16
INTENT_ID = "22" * 16
WALLET_ID = "11" * 16
TXID = "33" * 32


def _app(account: Account | None = None) -> FastAPI:
    app = FastAPI()
    app.include_router(arkade_router)
    if account:
        app.dependency_overrides[check_authenticated_account] = lambda: account
    return app


def _response() -> ArkadeOutgoingIntentResponse:
    return ArkadeOutgoingIntentResponse(
        intent_id=INTENT_ID,
        account_id=ACCOUNT_ID,
        wallet_id=WALLET_ID,
        amount_msat=10_000,
        destination="tark1destination",
        destination_script="5120" + "aa" * 32,
        status="reserved",
        expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
        network="regtest",
        server_url="http://indexer",
        server_pubkey="44" * 32,
        inputs=[
            ArkadeOutgoingIntentInput(
                intent_id=INTENT_ID, txid=TXID, vout=0, amount_sat=40
            )
        ],
    )


def _authorize_body() -> dict:
    return {
        "inputs": [{"txid": TXID, "vout": 0, "amount_sat": 40}],
        "destination_script": "5120" + "aa" * 32,
    }


@pytest.mark.anyio
async def test_outgoing_api_requires_auth_for_get_and_authorize():
    app = _app()
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        get_response = await client.get(f"/api/v1/arkade/outgoing/{INTENT_ID}")
        list_response = await client.get("/api/v1/arkade/outgoing")
        post_response = await client.post(
            f"/api/v1/arkade/outgoing/{INTENT_ID}/authorize", json=_authorize_body()
        )
        submit_response = await client.post(
            f"/api/v1/arkade/outgoing/{INTENT_ID}/submit",
            json={
                "ark_txid": TXID,
                "lockup_address": "tark1lockup",
                "swap_rfq_id": "rfq",
                "solver_pubkey": "44" * 32,
            },
        )
        release_response = await client.post(
            f"/api/v1/arkade/outgoing/{INTENT_ID}/release"
        )
    assert get_response.status_code == 401
    assert list_response.status_code == 401
    assert post_response.status_code == 401
    assert submit_response.status_code == 401
    assert release_response.status_code == 401


@pytest.mark.anyio
async def test_outgoing_api_isolation_and_canonical_response(monkeypatch):
    app = _app(Account(id=ACCOUNT_ID))
    monkeypatch.setattr(
        "lnbits.core.views.arkade_api.get_arkade_outgoing_intent_for_account",
        AsyncMock(return_value=_response()),
    )
    monkeypatch.setattr(
        "lnbits.core.views.arkade_api.authorize_arkade_outgoing",
        AsyncMock(return_value=_response()),
    )
    submitted = AsyncMock(return_value=_response())
    monkeypatch.setattr(
        "lnbits.core.views.arkade_api.submit_arkade_lightning_intent", submitted
    )
    release = AsyncMock(return_value=True)
    monkeypatch.setattr(
        "lnbits.core.views.arkade_api.release_arkade_outgoing_payment", release
    )
    listed = AsyncMock(return_value=[_response()])
    monkeypatch.setattr(
        "lnbits.core.views.arkade_api.list_arkade_submitted_outgoing_intents",
        listed,
    )
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.get(f"/api/v1/arkade/outgoing/{INTENT_ID}")
        list_response = await client.get("/api/v1/arkade/outgoing?limit=1")
        authorized = await client.post(
            f"/api/v1/arkade/outgoing/{INTENT_ID}/authorize", json=_authorize_body()
        )
        funding = await client.post(
            f"/api/v1/arkade/outgoing/{INTENT_ID}/submit",
            json={
                "ark_txid": TXID,
                "lockup_address": "tark1lockup",
                "swap_rfq_id": "rfq",
                "solver_pubkey": "44" * 32,
            },
        )
        released = await client.post(f"/api/v1/arkade/outgoing/{INTENT_ID}/release")
    assert response.status_code == 200
    assert list_response.status_code == 200
    listed.assert_awaited_once_with(ACCOUNT_ID, 1)
    assert response.json()["action"] == "lnbits-arkade-outgoing-v1"
    assert response.json()["inputs"][0]["txid"] == TXID
    assert authorized.status_code == 200
    assert funding.status_code == 200
    submitted.assert_awaited_once()
    submitted_args = submitted.await_args
    assert submitted_args is not None
    assert submitted_args.args[:2] == (ACCOUNT_ID, INTENT_ID)
    assert submitted_args.args[2].ark_txid == TXID
    assert released.status_code == 200
    assert released.json()["success"] is True
    release.assert_awaited_once_with(ACCOUNT_ID, INTENT_ID)

    foreign = _app(Account(id=OTHER_ACCOUNT_ID))
    not_found = AsyncMock(side_effect=ArkadeOutgoingError("ARKADE_OUTGOING_NOT_FOUND"))
    monkeypatch.setattr(
        "lnbits.core.views.arkade_api.get_arkade_outgoing_intent_for_account",
        not_found,
    )
    monkeypatch.setattr(
        "lnbits.core.views.arkade_api.authorize_arkade_outgoing",
        AsyncMock(side_effect=ArkadeOutgoingError("ARKADE_OUTGOING_NOT_FOUND")),
    )
    async with AsyncClient(
        transport=ASGITransport(app=foreign), base_url="http://test"
    ) as client:
        foreign_response = await client.get(f"/api/v1/arkade/outgoing/{INTENT_ID}")
        foreign_authorize = await client.post(
            f"/api/v1/arkade/outgoing/{INTENT_ID}/authorize", json=_authorize_body()
        )
    absent = _app(Account(id=ACCOUNT_ID))
    monkeypatch.setattr(
        "lnbits.core.views.arkade_api.get_arkade_outgoing_intent_for_account",
        AsyncMock(side_effect=ArkadeOutgoingError("ARKADE_OUTGOING_NOT_FOUND")),
    )
    async with AsyncClient(
        transport=ASGITransport(app=absent), base_url="http://test"
    ) as client:
        absent_response = await client.get(f"/api/v1/arkade/outgoing/{INTENT_ID}")
    assert foreign_response.status_code == absent_response.status_code == 400
    assert foreign_response.json()["detail"] == absent_response.json()["detail"]
    assert foreign_authorize.json()["detail"] == absent_response.json()["detail"]


@pytest.mark.anyio
async def test_outgoing_api_failed_report_contract(monkeypatch):
    app = _app(Account(id=ACCOUNT_ID))
    failed = AsyncMock(
        return_value=_response().copy(
            update={"status": "failed", "failure_reason": "claim_attempt_failed"}
        )
    )
    monkeypatch.setattr(
        "lnbits.core.views.arkade_api.fail_arkade_lightning_intent", failed
    )
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        reported = await client.post(
            f"/api/v1/arkade/outgoing/{INTENT_ID}/fail",
            json={"reason": "claim_attempt_failed"},
        )
        refused = await client.post(
            f"/api/v1/arkade/outgoing/{INTENT_ID}/fail",
            json={"reason": "claim_attempt_failed $bad"},
        )
        empty = await client.post(
            f"/api/v1/arkade/outgoing/{INTENT_ID}/fail", json={"reason": ""}
        )

    assert reported.status_code == 200
    assert reported.json()["status"] == "failed"
    assert reported.json()["failure_reason"] == "claim_attempt_failed"
    failed.assert_awaited_once_with(ACCOUNT_ID, INTENT_ID, "claim_attempt_failed")
    assert refused.status_code == 422
    assert empty.status_code == 422


@pytest.mark.anyio
async def test_outgoing_api_failed_report_maps_service_errors(monkeypatch):
    app = _app(Account(id=ACCOUNT_ID))
    monkeypatch.setattr(
        "lnbits.core.views.arkade_api.fail_arkade_lightning_intent",
        AsyncMock(
            side_effect=ArkadeOutgoingError("ARKADE_LIGHTNING_FAILURE_REASON_INVALID")
        ),
    )
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.post(
            f"/api/v1/arkade/outgoing/{INTENT_ID}/fail", json={"reason": "   "}
        )
    assert response.status_code == 400
    assert response.json()["detail"] == "ARKADE_LIGHTNING_FAILURE_REASON_INVALID"


@pytest.mark.anyio
@pytest.mark.parametrize(
    "payload",
    [
        {"inputs": []},
        {"inputs": [{"txid": TXID, "vout": 0, "amount_sat": 40, "extra": 1}]},
        {"inputs": [{"txid": TXID, "vout": 0, "amount_sat": 40}] * 101},
        {"inputs": [{"txid": TXID, "vout": 0, "amount_sat": 40}], "extra": 1},
    ],
)
async def test_outgoing_api_rejects_malformed_authorization_body(payload):
    app = _app(Account(id=ACCOUNT_ID))
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.post(
            f"/api/v1/arkade/outgoing/{INTENT_ID}/authorize", json=payload
        )
    assert response.status_code == 422


@pytest.mark.anyio
async def test_outgoing_api_bounds_recovery_enumeration():
    app = _app(Account(id=ACCOUNT_ID))
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        low = await client.get("/api/v1/arkade/outgoing?limit=0")
        high = await client.get("/api/v1/arkade/outgoing?limit=33")
    assert low.status_code == high.status_code == 422


@pytest.mark.anyio
async def test_outgoing_api_sanitizes_internal_service_errors(monkeypatch):
    app = _app(Account(id=ACCOUNT_ID))
    error = AsyncMock(side_effect=ArkadeOutgoingError("upstream secret"))
    monkeypatch.setattr(
        "lnbits.core.views.arkade_api.get_arkade_outgoing_intent_for_account", error
    )
    monkeypatch.setattr(
        "lnbits.core.views.arkade_api.authorize_arkade_outgoing",
        AsyncMock(side_effect=ArkadeOutgoingError("upstream secret")),
    )
    monkeypatch.setattr(
        "lnbits.core.views.arkade_api.release_arkade_outgoing_payment",
        AsyncMock(side_effect=ArkadeOutgoingError("upstream secret")),
    )
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        get_response = await client.get(f"/api/v1/arkade/outgoing/{INTENT_ID}")
        post_response = await client.post(
            f"/api/v1/arkade/outgoing/{INTENT_ID}/authorize", json=_authorize_body()
        )
        release_response = await client.post(
            f"/api/v1/arkade/outgoing/{INTENT_ID}/release"
        )
    assert get_response.status_code == post_response.status_code == 400
    assert release_response.status_code == 400
    assert (
        get_response.json()["detail"]
        == post_response.json()["detail"]
        == "ARKADE_OUTGOING_ERROR"
    )
    assert release_response.json()["detail"] == "ARKADE_OUTGOING_ERROR"


@pytest.mark.anyio
async def test_outgoing_api_exposes_custodial_unavailable(monkeypatch):
    app = _app(Account(id=ACCOUNT_ID))
    monkeypatch.setattr(
        "lnbits.core.views.arkade_api.get_arkade_outgoing_intent_for_account",
        AsyncMock(side_effect=ArkadeOutgoingError("ARKADE_OUTGOING_UNAVAILABLE")),
    )
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.get(f"/api/v1/arkade/outgoing/{INTENT_ID}")
    assert response.status_code == 400
    assert response.json()["detail"] == "ARKADE_OUTGOING_UNAVAILABLE"
