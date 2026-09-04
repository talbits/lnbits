import hashlib
import inspect
from datetime import datetime, timedelta, timezone
from typing import cast
from unittest.mock import AsyncMock
from uuid import uuid4

import pytest
from coincurve import PrivateKey
from fastapi import HTTPException as FastAPIHTTPException
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncConnection, create_async_engine

from lnbits.core import migrations
from lnbits.core.helpers import get_arkade_configuration
from lnbits.core.models import (
    Account,
    ArkadeAccountBinding,
    ArkadeEnrollmentChallenge,
    ArkadeEnrollmentCompletion,
)
from lnbits.core.services.arkade import (
    ArkadeEnrollmentError,
    canonical_enrollment_statement,
    complete_arkade_binding,
    complete_enrollment,
    require_arkade_payments_unavailable,
    require_arkade_ready,
    validate_arkade_identity_descriptor,
    verify_enrollment_proof,
)
from lnbits.db import SQLITE, Connection
from lnbits.settings import settings

TESTNET_IDENTITY_DESCRIPTOR = (
    "tr([73c5da0a/86'/1'/0']"
    "tpubDDfvzhdVV4unsoKt5aE6dcsNsfeWbTgmLZPi8LQDYU2xixrYemMfWJ3BaVne"
    "H3u7DBQePdTwhpybaKRU95pi6PMUtLPBJLVQRpzEnjfjZzX/0/*)"
)
TESTNET_IDENTITY_XONLY = (
    "55355ca83c973f1d97ce0e3843c85d78905af16b4dc531bc488e57212d230116"
)
TESTNET_IDENTITY_SECRET = (
    "dff1c8c2c016a572914b4c5adb8791d62b4768ae9d0a61be8ab94cf5038d7d90"
)
TESTNET_PRIVATE_DESCRIPTOR = (
    "tr([73c5da0a/86'/1'/0']"
    "tprv8gytrHbFLhE7zLJ6BvZWEDDGJe8aS8VrmFnvqpMv8CEZtUbn2NY5KoRKQNpkc"
    "L1yniyCBRi7dAPy4kUxHkcSvd9jzLmLMEG96TPwant2jbX/0/*)"
)
MAINNET_IDENTITY_DESCRIPTOR = (
    "tr([73c5da0a/86'/0'/0']"
    "xpub6BgBgsespWvERF3LHQu6CnqdvfEvtMcQjYrcRzx53QJjSxarj2afYWcLteoGV"
    "ky7D3UKDP9QyrLprQ3VCECoY49yfdDEHGCtMMj92pReUsQ/0/*)"
)
MAINNET_IDENTITY_XONLY = (
    "cc8a4bc64d897bddc5fbc2f670f7a8ba0b386779106cf1223c6fc5d7cd6fc115"
)


def test_enrollment_proof_uses_the_canonical_digest():
    private_key = PrivateKey.from_int(1)
    identity_key = private_key.public_key_xonly.format().hex()
    statement = canonical_enrollment_statement(
        account_id="00112233445566778899aabbccddeeff",
        enrollment_id="ffeeddccbbaa99887766554433221100",
        idempotency_key="aa" * 16,
        nonce="11" * 32,
        expires_at=1_800_000_000,
        network="regtest",
        server_url="http://localhost:7070",
        server_pubkey="22" * 32,
        identity_xonly_pubkey=identity_key,
        identity_descriptor=TESTNET_IDENTITY_DESCRIPTOR,
    )
    signature = private_key.sign_schnorr(
        hashlib.sha256(statement.encode("ascii")).digest()
    )

    verify_enrollment_proof(statement, identity_key, signature.hex())
    with pytest.raises(ArkadeEnrollmentError):
        verify_enrollment_proof(statement + "\n", identity_key, signature.hex())


def test_enrollment_statement_rejects_line_breaks():
    with pytest.raises(ArkadeEnrollmentError):
        canonical_enrollment_statement(
            account_id="00112233445566778899aabbccddeeff",
            enrollment_id="ffeeddccbbaa99887766554433221100",
            idempotency_key="bad\nkey",
            nonce="11" * 32,
            expires_at=1_800_000_000,
            network="regtest",
            server_url="http://localhost:7070",
            server_pubkey="22" * 32,
            identity_xonly_pubkey="33" * 32,
            identity_descriptor=TESTNET_IDENTITY_DESCRIPTOR,
        )


def test_identity_descriptor_matches_sdk_vectors_and_network():
    validate_arkade_identity_descriptor(
        TESTNET_IDENTITY_DESCRIPTOR, TESTNET_IDENTITY_XONLY, "regtest"
    )
    validate_arkade_identity_descriptor(
        MAINNET_IDENTITY_DESCRIPTOR, MAINNET_IDENTITY_XONLY, "bitcoin"
    )
    with pytest.raises(ArkadeEnrollmentError, match="descriptor"):
        validate_arkade_identity_descriptor(
            TESTNET_IDENTITY_DESCRIPTOR, TESTNET_IDENTITY_XONLY, "bitcoin"
        )
    with pytest.raises(ArkadeEnrollmentError, match="descriptor"):
        validate_arkade_identity_descriptor(
            TESTNET_IDENTITY_DESCRIPTOR, "00" * 32, "regtest"
        )


@pytest.mark.parametrize(
    "descriptor",
    [
        TESTNET_PRIVATE_DESCRIPTOR,
        TESTNET_IDENTITY_DESCRIPTOR.replace("/0/*)", "/1/*)"),
        TESTNET_IDENTITY_DESCRIPTOR.replace("/86'/1'/0'", "/86'/0'/0'"),
        TESTNET_IDENTITY_DESCRIPTOR.replace("/86'/1'/0'", "/86'/1'/1'"),
        TESTNET_IDENTITY_DESCRIPTOR.replace("tr(", "wpkh("),
        TESTNET_IDENTITY_DESCRIPTOR[:-1] + ",{pk(00)})",
    ],
)
def test_identity_descriptor_rejects_non_sdk_shapes(descriptor):
    with pytest.raises(ArkadeEnrollmentError, match="descriptor"):
        validate_arkade_identity_descriptor(
            descriptor, TESTNET_IDENTITY_XONLY, "regtest"
        )


@pytest.mark.anyio
async def test_challenge_is_idempotent_and_rejects_live_rebind(monkeypatch):
    import lnbits.core.services.arkade as service
    from lnbits.settings import settings

    now = datetime.now(timezone.utc)
    binding = ArkadeAccountBinding(
        account_id="00112233445566778899aabbccddeeff",
        enrollment_id="ffeeddccbbaa99887766554433221100",
        network="regtest",
        server_url="http://localhost:7070",
        server_pubkey="22" * 32,
        created_at=now,
        updated_at=now,
    )
    monkeypatch.setattr(
        settings, "lnbits_effective_installation_mode", "arkade_noncustodial"
    )
    monkeypatch.setattr(
        service, "get_arkade_binding", lambda *_args, **_kwargs: _binding(binding)
    )

    async def update(current, **kwargs):
        current.enrollment_id = kwargs["enrollment_id"]
        current.idempotency_key = kwargs["idempotency_key"]
        current.challenge_nonce = kwargs["nonce"]
        current.challenge_expires_at = kwargs["expires_at"]
        return True

    monkeypatch.setattr(service, "update_arkade_challenge", update)
    account = Account(id=binding.account_id)
    challenge = await service.create_enrollment_challenge(account, "aa" * 16)
    replay = await service.create_enrollment_challenge(account, "aa" * 16)
    assert challenge.enrollment_id == replay.enrollment_id
    assert (
        cast(ArkadeEnrollmentChallenge, challenge).nonce
        == cast(ArkadeEnrollmentChallenge, replay).nonce
    )
    with pytest.raises(ArkadeEnrollmentError, match="already active"):
        await service.create_enrollment_challenge(account, "bb" * 16)


@pytest.mark.anyio
async def test_challenge_cas_loser_reloads_only_same_key_winner(monkeypatch):
    import lnbits.core.services.arkade as service

    binding = _binding_model()
    monkeypatch.setattr(
        settings, "lnbits_effective_installation_mode", "arkade_noncustodial"
    )
    monkeypatch.setattr(service, "get_arkade_binding", AsyncMock(return_value=binding))
    monkeypatch.setattr(
        service, "update_arkade_challenge", AsyncMock(return_value=False)
    )
    with pytest.raises(ArkadeEnrollmentError, match="already active"):
        await service.create_enrollment_challenge(
            Account(id=binding.account_id), "aa" * 16
        )

    winner = _binding_model(
        idempotency_key="aa" * 16,
        challenge_nonce="bb" * 32,
        challenge_expires_at=datetime.now(timezone.utc) + timedelta(minutes=5),
    )
    monkeypatch.setattr(service, "get_arkade_binding", AsyncMock(return_value=winner))
    monkeypatch.setattr(
        service,
        "update_arkade_challenge",
        AsyncMock(side_effect=IntegrityError("update", {}, ValueError("race"))),
    )
    result = await service.create_enrollment_challenge(
        Account(id=binding.account_id), "aa" * 16
    )
    assert cast(ArkadeEnrollmentChallenge, result).nonce == "bb" * 32

    other = _binding_model(
        idempotency_key="cc" * 16,
        challenge_nonce="dd" * 32,
        challenge_expires_at=datetime.now(timezone.utc),
    )
    monkeypatch.setattr(service, "get_arkade_binding", AsyncMock(return_value=other))
    with pytest.raises(ArkadeEnrollmentError, match="already active"):
        await service.create_enrollment_challenge(
            Account(id=binding.account_id), "aa" * 16
        )


async def _binding(binding):
    return binding


@pytest.fixture
async def sqlite_connection():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.connect() as raw_connection:
        connection = Connection(
            cast(AsyncConnection, raw_connection), SQLITE, "test", None
        )
        await connection.execute("CREATE TABLE accounts (id TEXT PRIMARY KEY)")
        await migrations.m052_create_arkade_account_bindings_table(connection)
        await migrations.m056_add_arkade_account_descriptor(connection)
        yield connection
    await engine.dispose()


def _server_key() -> str:
    return PrivateKey.from_int(1).public_key_xonly.format().hex()


def _binding_model(state="pending", **overrides):
    now = datetime.now(timezone.utc)
    values = {
        "account_id": "00112233445566778899aabbccddeeff",
        "enrollment_id": "ffeeddccbbaa99887766554433221100",
        "network": "regtest",
        "server_url": "http://localhost:7070",
        "server_pubkey": "22" * 32,
        "created_at": now,
        "updated_at": now,
        "state": state,
    }
    values.update(overrides)
    return ArkadeAccountBinding(**values)


def test_custodial_configuration_is_not_required(monkeypatch):
    monkeypatch.setattr(settings, "lnbits_effective_installation_mode", "custodial")
    monkeypatch.setattr(settings, "lnbits_arkade_network", None)
    monkeypatch.setattr(settings, "lnbits_arkade_server_url", None)
    monkeypatch.setattr(settings, "lnbits_arkade_server_pubkey", None)

    import lnbits.core.services.users as users

    users._validate_arkade_creation_configuration()


def test_arkade_configuration_is_canonical_and_validated(monkeypatch):
    monkeypatch.setattr(settings, "lnbits_arkade_network", "regtest")
    monkeypatch.setattr(settings, "lnbits_arkade_server_url", "HTTPS://Example.COM/")
    monkeypatch.setattr(settings, "lnbits_arkade_server_pubkey", _server_key().upper())

    assert get_arkade_configuration() == (
        "regtest",
        "https://example.com",
        _server_key(),
    )


@pytest.mark.parametrize(
    "field,value",
    [
        ("lnbits_arkade_server_pubkey", "0" * 64),
        ("lnbits_arkade_server_pubkey", "not-a-key"),
        ("lnbits_arkade_server_url", "https://例え.example"),
        ("lnbits_arkade_server_url", "https://[::1]/"),
    ],
)
def test_arkade_configuration_rejects_invalid_point_unicode_and_ipv6(
    monkeypatch, field, value
):
    monkeypatch.setattr(settings, "lnbits_arkade_network", "regtest")
    monkeypatch.setattr(settings, "lnbits_arkade_server_url", "https://example.com")
    monkeypatch.setattr(settings, "lnbits_arkade_server_pubkey", _server_key())
    monkeypatch.setattr(settings, field, value)

    with pytest.raises(RuntimeError, match="ARKADE_CONFIG_INVALID"):
        get_arkade_configuration()


@pytest.mark.anyio
async def test_m052_has_state_and_challenge_shape_checks(sqlite_connection):
    now = datetime.now(timezone.utc)
    await sqlite_connection.execute(
        "INSERT INTO accounts (id) VALUES (:id)",
        {"id": "a" * 32},
    )
    await sqlite_connection.execute(
        """
        INSERT INTO arkade_account_bindings
        (account_id, state, enrollment_id, network, server_url, server_pubkey,
         created_at, updated_at)
        VALUES (:account_id, 'pending', :enrollment_id, 'regtest',
                'http://localhost', :server_pubkey, :created_at, :updated_at)
        """,
        {
            "account_id": "a" * 32,
            "enrollment_id": "b" * 32,
            "server_pubkey": "c" * 64,
            "created_at": now,
            "updated_at": now,
        },
    )
    with pytest.raises(IntegrityError):
        await sqlite_connection.execute(
            "UPDATE arkade_account_bindings SET state='ready' WHERE account_id=:id",
            {"id": "a" * 32},
        )
    with pytest.raises(IntegrityError):
        await sqlite_connection.execute(
            "UPDATE arkade_account_bindings SET challenge_nonce='d' "
            "WHERE account_id=:id",
            {"id": "a" * 32},
        )


@pytest.mark.anyio
async def test_m052_enforces_unique_enrollment_idempotency_and_identity(
    sqlite_connection,
):
    await sqlite_connection.execute(
        "INSERT INTO accounts (id) VALUES (:id), (:other)",
        {"id": "a" * 32, "other": "b" * 32},
    )
    values = {
        "account_id": "a" * 32,
        "enrollment_id": "c" * 32,
        "idempotency_key": "d" * 32,
        "identity": "e" * 64,
    }
    await sqlite_connection.execute(
        """
        INSERT INTO arkade_account_bindings
        (account_id, state, enrollment_id, idempotency_key, identity_xonly_pubkey,
         backup_acknowledged_at, ready_at, network, server_url, server_pubkey)
        VALUES (:account_id, 'ready', :enrollment_id, :idempotency_key, :identity,
                1, 1, 'regtest', 'http://localhost', :server_pubkey)
        """,
        {**values, "server_pubkey": "f" * 64},
    )
    for column, value in (
        ("enrollment_id", "c" * 32),
        ("idempotency_key", "d" * 32),
        ("identity_xonly_pubkey", "e" * 64),
    ):
        with pytest.raises(IntegrityError):
            await sqlite_connection.execute(
                "INSERT INTO arkade_account_bindings "
                "(account_id, state, enrollment_id, idempotency_key, "
                "identity_xonly_pubkey, backup_acknowledged_at, ready_at, "
                "network, server_url, server_pubkey) VALUES "
                "(:account_id, 'ready', :enrollment_id, :idempotency_key, "
                ":identity, 1, 1, 'regtest', 'http://localhost', :server_pubkey)",
                {
                    "account_id": "b" * 32,
                    "enrollment_id": value if column == "enrollment_id" else "1" * 32,
                    "idempotency_key": (
                        value if column == "idempotency_key" else "2" * 32
                    ),
                    "identity": (
                        value if column == "identity_xonly_pubkey" else "3" * 64
                    ),
                    "server_pubkey": "4" * 64,
                },
            )


@pytest.mark.anyio
async def test_m056_descriptor_is_nullable_and_unique(sqlite_connection):
    await sqlite_connection.execute(
        "INSERT INTO accounts (id) VALUES (:first), (:second)",
        {"first": "6" * 32, "second": "7" * 32},
    )
    for account_id, enrollment_id in (("6" * 32, "8" * 32), ("7" * 32, "9" * 32)):
        await sqlite_connection.execute(
            "INSERT INTO arkade_account_bindings "
            "(account_id, state, enrollment_id, network, server_url, server_pubkey) "
            "VALUES (:account_id, 'pending', :enrollment_id, 'regtest', "
            "'http://localhost', :server_pubkey)",
            {
                "account_id": account_id,
                "enrollment_id": enrollment_id,
                "server_pubkey": "a" * 64,
            },
        )
    await sqlite_connection.execute(
        "UPDATE arkade_account_bindings SET identity_descriptor = :descriptor "
        "WHERE account_id = :account_id",
        {"descriptor": TESTNET_IDENTITY_DESCRIPTOR, "account_id": "6" * 32},
    )
    with pytest.raises(IntegrityError):
        await sqlite_connection.execute(
            "UPDATE arkade_account_bindings SET identity_descriptor = :descriptor "
            "WHERE account_id = :account_id",
            {"descriptor": TESTNET_IDENTITY_DESCRIPTOR, "account_id": "7" * 32},
        )


@pytest.mark.anyio
async def test_require_authenticated_enrollment_dependency_rejects_missing_token():
    from fastapi import Request

    from lnbits.decorators import check_authenticated_account

    scope = {
        "type": "http",
        "method": "POST",
        "path": "/api/v1/arkade/enrollment/challenge",
    }
    request = Request(scope)
    with pytest.raises(FastAPIHTTPException, match="Missing access token"):
        await check_authenticated_account(request, None)


def test_enrollment_route_uses_strict_dependency_and_optional_header():
    from lnbits.core.views.arkade_api import api_arkade_enrollment_challenge

    parameters = inspect.signature(api_arkade_enrollment_challenge).parameters
    assert (
        parameters["account"].default.dependency.__name__
        == "check_authenticated_account"
    )
    assert parameters["idempotency_key"].default.default is None


@pytest.mark.anyio
async def test_enrollment_page_route_requires_authenticated_session():
    from fastapi import Request
    from fastapi.routing import APIRoute

    from lnbits.core.views.generic import generic_router
    from lnbits.decorators import check_authenticated_account

    route = next(
        route
        for route in generic_router.routes
        if isinstance(route, APIRoute) and route.path == "/arkade/enrollment"
    )
    assert any(
        dependency.dependency is check_authenticated_account
        for dependency in route.dependencies
    )
    request = Request(
        {
            "type": "http",
            "method": "GET",
            "path": "/arkade/enrollment",
            "query_string": b"usr=" + (b"a" * 32),
        }
    )
    with pytest.raises(FastAPIHTTPException, match="Missing access token"):
        await check_authenticated_account(request, None)


@pytest.mark.anyio
async def test_missing_idempotency_header_maps_to_stable_error(monkeypatch):
    from lnbits.core.views import arkade_api

    monkeypatch.setattr(
        arkade_api,
        "create_enrollment_challenge",
        AsyncMock(side_effect=ArkadeEnrollmentError("Invalid idempotency key.")),
    )
    with pytest.raises(FastAPIHTTPException) as exc:
        await arkade_api.api_arkade_enrollment_challenge(Account(id=uuid4().hex), None)
    assert exc.value.detail == "ARKADE_ENROLLMENT_ERROR"


@pytest.mark.anyio
async def test_payment_guard_preserves_pending_error_and_blocks_ready(monkeypatch):
    import lnbits.core.services.arkade as service

    monkeypatch.setattr(
        settings, "lnbits_effective_installation_mode", "arkade_noncustodial"
    )
    binding = _binding_model()
    monkeypatch.setattr(service, "get_arkade_binding", AsyncMock(return_value=binding))
    with pytest.raises(ArkadeEnrollmentError, match="ARKADE_ENROLLMENT_REQUIRED"):
        await require_arkade_payments_unavailable(binding.account_id)

    binding.state = "ready"
    binding.identity_xonly_pubkey = _server_key()
    binding.backup_acknowledged_at = binding.updated_at
    binding.ready_at = binding.updated_at
    monkeypatch.setattr(service, "get_arkade_binding", AsyncMock(return_value=binding))
    with pytest.raises(ArkadeEnrollmentError, match="ARKADE_PAYMENTS_UNAVAILABLE"):
        await require_arkade_payments_unavailable(binding.account_id)
    await require_arkade_ready(binding.account_id)


@pytest.mark.anyio
async def test_custodial_payment_guard_is_noop(monkeypatch):
    monkeypatch.setattr(settings, "lnbits_effective_installation_mode", "custodial")
    await require_arkade_payments_unavailable("a" * 32)


@pytest.mark.anyio
async def test_complete_binding_reconstructs_statement_and_is_idempotent(monkeypatch):
    import lnbits.core.services.arkade as service

    private_key = PrivateKey(bytes.fromhex(TESTNET_IDENTITY_SECRET))
    identity = TESTNET_IDENTITY_XONLY
    binding = _binding_model(
        idempotency_key="aa" * 16,
        challenge_nonce="bb" * 32,
        challenge_expires_at=datetime.now(timezone.utc) + timedelta(minutes=5),
    )
    monkeypatch.setattr(
        settings, "lnbits_effective_installation_mode", "arkade_noncustodial"
    )
    ready = _binding_model(
        state="ready",
        idempotency_key=binding.idempotency_key,
        identity_xonly_pubkey=identity,
        identity_descriptor=TESTNET_IDENTITY_DESCRIPTOR,
        backup_acknowledged_at=binding.updated_at,
        ready_at=binding.updated_at,
    )
    get_binding = AsyncMock(side_effect=[binding, ready])
    monkeypatch.setattr(service, "get_arkade_binding", get_binding)
    complete = AsyncMock(return_value=True)
    monkeypatch.setattr(service, "complete_arkade_binding", complete)
    idempotency_key = binding.idempotency_key
    nonce = binding.challenge_nonce
    expires_at = binding.challenge_expires_at
    assert idempotency_key and nonce and expires_at
    statement = canonical_enrollment_statement(
        account_id=binding.account_id,
        enrollment_id=binding.enrollment_id,
        idempotency_key=idempotency_key,
        nonce=nonce,
        expires_at=int(expires_at.timestamp()),
        network=binding.network,
        server_url=binding.server_url,
        server_pubkey=binding.server_pubkey,
        identity_xonly_pubkey=identity,
        identity_descriptor=TESTNET_IDENTITY_DESCRIPTOR,
    )
    data = ArkadeEnrollmentCompletion(
        enrollment_id=binding.enrollment_id,
        idempotency_key=idempotency_key,
        identity_xonly_pubkey=identity,
        identity_descriptor=TESTNET_IDENTITY_DESCRIPTOR,
        signature=private_key.sign_schnorr(
            hashlib.sha256(statement.encode("ascii")).digest()
        ).hex(),
    )
    result = await complete_enrollment(Account(id=binding.account_id), data)
    assert result.state == "ready"
    complete.assert_awaited_once()


@pytest.mark.anyio
async def test_complete_binding_rejects_expired_challenge_and_mismatch(monkeypatch):
    import lnbits.core.services.arkade as service

    binding = _binding_model(
        idempotency_key="aa" * 16,
        challenge_nonce="bb" * 32,
        challenge_expires_at=datetime.now(timezone.utc) - timedelta(seconds=1),
    )
    monkeypatch.setattr(
        settings, "lnbits_effective_installation_mode", "arkade_noncustodial"
    )
    monkeypatch.setattr(service, "get_arkade_binding", AsyncMock(return_value=binding))
    idempotency_key = binding.idempotency_key
    assert idempotency_key
    data = ArkadeEnrollmentCompletion(
        enrollment_id=binding.enrollment_id,
        idempotency_key=idempotency_key,
        identity_xonly_pubkey=_server_key(),
        identity_descriptor=TESTNET_IDENTITY_DESCRIPTOR,
        signature="00" * 64,
    )
    with pytest.raises(ArkadeEnrollmentError, match="expired"):
        await complete_enrollment(Account(id=binding.account_id), data)
    data.enrollment_id = "1" * 32
    with pytest.raises(ArkadeEnrollmentError, match="mismatch"):
        await complete_enrollment(Account(id=binding.account_id), data)


@pytest.mark.anyio
async def test_complete_arkade_binding_real_sql_cas_and_expiry(sqlite_connection):
    now = datetime.now(timezone.utc)
    expiry = now + timedelta(minutes=5)
    await sqlite_connection.execute(
        "INSERT INTO accounts (id) VALUES (:valid), (:expired)",
        {"valid": "a" * 32, "expired": "b" * 32},
    )
    for account_id, enrollment_id, idempotency_key, nonce, expires_at in (
        ("a" * 32, "c" * 32, "d" * 32, "e" * 64, expiry),
        ("b" * 32, "f" * 32, "1" * 32, "2" * 64, now - timedelta(seconds=1)),
    ):
        await sqlite_connection.execute(
            """
            INSERT INTO arkade_account_bindings
            (account_id, state, enrollment_id, idempotency_key, challenge_nonce,
             challenge_expires_at, network, server_url, server_pubkey,
             created_at, updated_at)
            VALUES (:account_id, 'pending', :enrollment_id, :idempotency_key,
                    :nonce, :expires_at, 'regtest', 'http://localhost', :server,
                    :created_at, :updated_at)
            """,
            {
                "account_id": account_id,
                "enrollment_id": enrollment_id,
                "idempotency_key": idempotency_key,
                "nonce": nonce,
                "expires_at": expires_at,
                "server": "3" * 64,
                "created_at": now,
                "updated_at": now,
            },
        )

    assert await complete_arkade_binding(
        account_id="a" * 32,
        enrollment_id="c" * 32,
        idempotency_key="d" * 32,
        nonce="e" * 64,
        expires_at=expiry,
        server_utc_now=now,
        identity_xonly_pubkey="4" * 64,
        identity_descriptor=TESTNET_IDENTITY_DESCRIPTOR,
        acknowledged_at=now,
        conn=sqlite_connection,
    )
    ready = await sqlite_connection.fetchone(
        "SELECT state, challenge_nonce, challenge_expires_at, "
        "identity_xonly_pubkey, identity_descriptor, "
        "backup_acknowledged_at, ready_at "
        "FROM arkade_account_bindings WHERE account_id=:id",
        {"id": "a" * 32},
    )
    assert ready["state"] == "ready"
    assert ready["challenge_nonce"] is None
    assert ready["challenge_expires_at"] is None
    assert ready["identity_xonly_pubkey"] == "4" * 64
    assert ready["identity_descriptor"] == TESTNET_IDENTITY_DESCRIPTOR
    assert ready["backup_acknowledged_at"] is not None
    assert ready["ready_at"] is not None

    assert not await complete_arkade_binding(
        account_id="b" * 32,
        enrollment_id="f" * 32,
        idempotency_key="1" * 32,
        nonce="2" * 64,
        expires_at=now - timedelta(seconds=1),
        server_utc_now=now,
        identity_xonly_pubkey="5" * 64,
        identity_descriptor=TESTNET_IDENTITY_DESCRIPTOR,
        acknowledged_at=now,
        conn=sqlite_connection,
    )
    expired = await sqlite_connection.fetchone(
        "SELECT state, challenge_nonce, identity_xonly_pubkey "
        "FROM arkade_account_bindings WHERE account_id=:id",
        {"id": "b" * 32},
    )
    assert expired == {
        "state": "pending",
        "challenge_nonce": "2" * 64,
        "identity_xonly_pubkey": None,
    }


@pytest.mark.anyio
async def test_exact_ready_replay_skips_verification_and_mutation(monkeypatch):
    import lnbits.core.services.arkade as service

    binding = _binding_model(
        state="ready",
        idempotency_key="aa" * 16,
        identity_xonly_pubkey=_server_key(),
        identity_descriptor=TESTNET_IDENTITY_DESCRIPTOR,
    )
    binding.backup_acknowledged_at = binding.updated_at
    binding.ready_at = binding.updated_at
    monkeypatch.setattr(
        settings, "lnbits_effective_installation_mode", "arkade_noncustodial"
    )
    monkeypatch.setattr(service, "get_arkade_binding", AsyncMock(return_value=binding))
    verify = AsyncMock(side_effect=AssertionError("replay verified"))
    mutate = AsyncMock(side_effect=AssertionError("replay mutated"))
    monkeypatch.setattr(service, "verify_enrollment_proof", verify)
    monkeypatch.setattr(service, "complete_arkade_binding", mutate)
    data = ArkadeEnrollmentCompletion(
        enrollment_id=binding.enrollment_id,
        idempotency_key="aa" * 16,
        identity_xonly_pubkey=_server_key(),
        identity_descriptor=TESTNET_IDENTITY_DESCRIPTOR,
        signature="00" * 64,
    )
    result = await complete_enrollment(Account(id=binding.account_id), data)
    assert result.state == "ready"
    verify.assert_not_awaited()
    mutate.assert_not_awaited()
    data.identity_xonly_pubkey = "1" * 64
    with pytest.raises(ArkadeEnrollmentError, match="binding mismatch"):
        await complete_enrollment(Account(id=binding.account_id), data)


@pytest.mark.anyio
async def test_wallet_guards_isolate_pending_ready_shared_and_custodial(monkeypatch):
    from lnbits.core.crud import arkade

    monkeypatch.setattr(
        settings, "lnbits_effective_installation_mode", "arkade_noncustodial"
    )
    pending = _binding_model()
    get_binding = AsyncMock(return_value=pending)
    monkeypatch.setattr(arkade, "get_arkade_binding", get_binding)
    with pytest.raises(ValueError, match="ARKADE_ENROLLMENT_REQUIRED"):
        await arkade.ensure_arkade_wallet_creation_allowed("a" * 32, "lightning")
    await arkade.ensure_arkade_wallet_creation_allowed(
        "a" * 32, "lightning", allow_pending=True
    )
    with pytest.raises(ValueError, match="ARKADE_SHARED_WALLET_UNSUPPORTED"):
        await arkade.ensure_arkade_wallet_creation_allowed(
            "a" * 32, "lightning-shared", allow_pending=True
        )
    pending.state = "ready"
    await arkade.ensure_arkade_wallet_creation_allowed("a" * 32, "lightning")
    monkeypatch.setattr(settings, "lnbits_effective_installation_mode", "custodial")
    await arkade.ensure_arkade_wallet_creation_allowed("a" * 32, "lightning-shared")


@pytest.mark.anyio
async def test_account_and_wallet_deletion_guards_are_before_mutation(
    monkeypatch, sqlite_connection
):
    from lnbits.core.crud import arkade

    monkeypatch.setattr(
        settings, "lnbits_effective_installation_mode", "arkade_noncustodial"
    )
    with pytest.raises(ValueError, match="ARKADE_ACCOUNT_DELETION_BLOCKED"):
        await arkade.ensure_arkade_account_deletion_allowed("a" * 32)

    await sqlite_connection.execute(
        'CREATE TABLE wallets (id TEXT PRIMARY KEY, "user" TEXT, deleted BOOLEAN)'
    )
    await sqlite_connection.execute(
        'INSERT INTO wallets (id, "user", deleted) VALUES '
        "('w1', 'a', false), ('w3', 'a', true)"
    )
    ready = _binding_model(state="ready", identity_xonly_pubkey=_server_key())
    ready.backup_acknowledged_at = ready.updated_at
    ready.ready_at = ready.updated_at
    monkeypatch.setattr(arkade, "get_arkade_binding", AsyncMock(return_value=ready))
    with pytest.raises(ValueError, match="ARKADE_FINAL_WALLET_DELETION_BLOCKED"):
        await arkade.ensure_arkade_wallet_deletion_allowed("w1", conn=sqlite_connection)
    await sqlite_connection.execute(
        "INSERT INTO wallets (id, \"user\", deleted) VALUES ('w2', 'a', false)"
    )
    await arkade.ensure_arkade_wallet_deletion_allowed(
        "w1", deleted=False, conn=sqlite_connection
    )
    await arkade.ensure_arkade_wallet_deletion_allowed("w3", conn=sqlite_connection)
    await sqlite_connection.execute("DELETE FROM wallets WHERE id='w2'")
    with pytest.raises(ValueError, match="ARKADE_FINAL_WALLET_DELETION_BLOCKED"):
        await arkade.ensure_arkade_wallet_deletion_allowed("w1", conn=sqlite_connection)


@pytest.mark.anyio
async def test_create_user_account_arkade_order_and_compensation(monkeypatch):
    import lnbits.core.services.users as users

    class Context:
        queries: list[tuple[str, dict | None]]

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_):
            return None

        async def execute(self, query, values=None):
            self.queries.append((query, values))

    conn = Context()
    conn.queries = []
    events = []
    account = Account(id=uuid4().hex)
    result = type("UserResult", (), {"id": account.id})()
    monkeypatch.setattr(
        settings, "lnbits_effective_installation_mode", "arkade_noncustodial"
    )
    monkeypatch.setattr(users, "_validate_arkade_creation_configuration", lambda: None)
    monkeypatch.setattr(users.db, "connect", lambda: conn)
    monkeypatch.setattr(users, "check_users_limit", AsyncMock())
    monkeypatch.setattr(
        users,
        "create_account",
        AsyncMock(side_effect=lambda a, conn: (events.append("account"), a)[1]),
    )
    monkeypatch.setattr(
        users,
        "create_arkade_binding",
        AsyncMock(side_effect=lambda *args, **kwargs: events.append("binding")),
    )
    create_wallet = AsyncMock(side_effect=lambda **kwargs: events.append("wallet"))
    monkeypatch.setattr(users, "create_wallet", create_wallet)
    extension = AsyncMock()
    monkeypatch.setattr(users, "create_user_extension", extension)
    monkeypatch.setattr(users, "get_user_from_account", AsyncMock(return_value=result))

    user = await users.create_user_account_no_ckeck(account, default_exts=["default"])
    assert user.id == account.id
    assert events == ["account", "binding", "wallet"]
    wallet_args = create_wallet.await_args
    assert wallet_args is not None
    assert wallet_args.kwargs["allow_pending"] is True
    extension.assert_not_awaited()

    create_wallet.side_effect = RuntimeError("wallet failed")
    with pytest.raises(RuntimeError, match="wallet failed"):
        await users.create_user_account_no_ckeck(Account(id=uuid4().hex))
    cleanup = [query for query, _ in conn.queries if query.startswith("DELETE")]
    assert [query.split()[2] for query in cleanup] == [
        "extensions",
        "wallets",
        "arkade_account_bindings",
        "accounts",
    ]


@pytest.mark.anyio
async def test_create_user_account_custodial_keeps_default_extensions(monkeypatch):
    import lnbits.core.services.users as users

    class Context:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *_):
            return None

        async def execute(self, *_args, **_kwargs):
            return None

    account = Account(id=uuid4().hex)
    monkeypatch.setattr(settings, "lnbits_effective_installation_mode", "custodial")
    monkeypatch.setattr(settings, "lnbits_user_default_extensions", ["default"])
    monkeypatch.setattr(users.db, "connect", lambda: Context())
    monkeypatch.setattr(users, "check_users_limit", AsyncMock())
    monkeypatch.setattr(users, "create_account", AsyncMock(return_value=account))
    binding = AsyncMock()
    monkeypatch.setattr(users, "create_arkade_binding", binding)
    monkeypatch.setattr(users, "create_wallet", AsyncMock())
    extension = AsyncMock()
    monkeypatch.setattr(users, "create_user_extension", extension)
    monkeypatch.setattr(users, "get_user_from_account", AsyncMock(return_value=account))

    await users.create_user_account_no_ckeck(account)
    binding.assert_not_awaited()
    extension.assert_awaited_once()


@pytest.mark.anyio
async def test_payment_roots_never_reach_funding_or_extension_checks(monkeypatch):
    import lnbits.core.services.payments as payments

    wallet = payments.Wallet(
        id="w" * 32,
        user="a" * 32,
        name="wallet",
        adminkey="k" * 32,
        inkey="i" * 32,
    )
    blocked = AsyncMock(
        side_effect=ArkadeEnrollmentError("ARKADE_PAYMENTS_UNAVAILABLE")
    )
    monkeypatch.setattr(payments, "require_arkade_payments_unavailable", blocked)
    monkeypatch.setattr(payments, "get_wallet", AsyncMock(return_value=wallet))
    funding = AsyncMock()
    monkeypatch.setattr(payments, "get_funding_source", funding)
    with pytest.raises(ArkadeEnrollmentError, match="ARKADE_PAYMENTS_UNAVAILABLE"):
        await payments.create_invoice(wallet_id=wallet.id, amount=1, memo="test")
    funding.assert_not_awaited()

    extension_check = AsyncMock()
    monkeypatch.setattr(payments, "check_user_extension_access", extension_check)
    with pytest.raises(ArkadeEnrollmentError, match="ARKADE_PAYMENTS_UNAVAILABLE"):
        await payments._check_wallet_for_payment(wallet.id, "", 1000)
    extension_check.assert_not_awaited()
