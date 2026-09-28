import hashlib
from datetime import datetime, timedelta, timezone
from typing import cast
from unittest.mock import AsyncMock

import pytest
from bech32 import CHARSET, bech32_hrp_expand, bech32_polymod, convertbits
from coincurve import PrivateKey
from sqlalchemy.ext.asyncio import AsyncConnection, create_async_engine

import lnbits.db as db_module
from lnbits.core import migrations
from lnbits.core.crud import wallets
from lnbits.core.crud.wallets import (
    delete_unused_wallets,
    remove_deleted_wallets,
)
from lnbits.core.models import (
    ArkadeIndexerVtxo,
    ArkadeReceiveAcknowledgement,
    Wallet,
)
from lnbits.core.services import arkade
from lnbits.db import SQLITE, Connection
from lnbits.settings import settings

ACCOUNT_ID = "00" * 16
WALLET_ID = "11" * 16


@pytest.fixture
async def connection(monkeypatch):
    monkeypatch.setattr(db_module, "DB_TYPE", SQLITE)
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.connect() as raw:
        connection = Connection(cast(AsyncConnection, raw), SQLITE, "test", None)
        await connection.execute("CREATE TABLE accounts (id TEXT PRIMARY KEY)")
        await connection.execute(
            'CREATE TABLE wallets (id TEXT PRIMARY KEY, "user" TEXT NOT NULL, '
            "name TEXT NOT NULL, adminkey TEXT NOT NULL, inkey TEXT NOT NULL, "
            "deleted BOOLEAN NOT NULL DEFAULT false, created_at INTEGER, "
            "updated_at INTEGER)"
        )
        await connection.execute(
            "INSERT INTO accounts (id) VALUES (:id)", {"id": ACCOUNT_ID}
        )
        await connection.execute(
            'INSERT INTO wallets (id, "user", name, adminkey, inkey) '
            "VALUES (:id, :user, 'test', 'a', 'b')",
            {"id": WALLET_ID, "user": ACCOUNT_ID},
        )
        await connection.execute(
            "CREATE TABLE apipayments ("
            "wallet_id TEXT, native_id TEXT, amount INT, fee INT, status TEXT)"
        )
        await migrations.m052_create_arkade_account_bindings_table(connection)
        await migrations.m053_create_arkade_receive_tables(connection)
        await migrations.m055_create_arkade_outgoing_tables(connection)
        await migrations.m057_add_arkade_outgoing_outputs(connection)
        await migrations.m058_add_arkade_lightning_quote_fields(connection)
        await migrations.m059_create_arkade_lightning_terminal_events(connection)
        await migrations.m060_add_arkade_lightning_refund_binding(connection)
        await migrations.m061_add_arkade_lightning_failed_state(connection)
        await migrations.m062_extend_arkade_reconciliation_errors(connection)
        now = datetime.now(timezone.utc)
        await connection.execute(
            "INSERT INTO arkade_account_bindings "
            "(account_id, state, enrollment_id, network, server_url, server_pubkey, "
            "identity_xonly_pubkey, backup_acknowledged_at, ready_at) VALUES "
            "(:account_id, 'ready', :enrollment_id, 'regtest', 'http://arkade', "
            ":server, "
            ":identity, :ack, :ready)",
            {
                "account_id": ACCOUNT_ID,
                "enrollment_id": "22" * 16,
                "server": "33" * 32,
                "identity": "44" * 32,
                "ack": now,
                "ready": now,
            },
        )
        yield connection
    await engine.dispose()


@pytest.fixture
def ready_mode(monkeypatch):
    monkeypatch.setattr(
        settings, "lnbits_effective_installation_mode", "arkade_noncustodial"
    )
    monkeypatch.setattr(
        arkade,
        "get_wallet",
        AsyncMock(return_value=_wallet()),
    )


def _wallet():
    return Wallet(
        id=WALLET_ID,
        user=ACCOUNT_ID,
        name="test",
        adminkey="a",
        inkey="b",
    )


def _ark_address(server_pubkey: str, taproot_key: str) -> str:
    payload = convertbits(bytes.fromhex("00" + server_pubkey + taproot_key), 8, 5, True)
    assert payload is not None
    checksum_input = bech32_hrp_expand("tark") + payload + [0] * 6
    checksum = bech32_polymod(checksum_input) ^ 0x2BC830A3
    checksum_words = [(checksum >> 5 * (5 - i)) & 31 for i in range(6)]
    return "tark1" + "".join(CHARSET[word] for word in payload + checksum_words)


def _exit_fixture(child_xonly_pubkey: str) -> tuple[str, str, str]:
    # Captured from the installed SDK's DefaultVtxo.Script.exit() for
    # child key c6047f...09b95c709ee5, server key 5, and CSV 144 blocks.
    assert child_xonly_pubkey == (
        "c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"
    )
    return (
        "029000b27520" + child_xonly_pubkey + "acc0",
        "c1"
        "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0"
        "136f8575c92f23b30addafb8e5e7e15f66a0f18666198f55007626f30bab1ac9",
        "a4bb62bda9a34df9d81c7cc98c06ea3cf3536de0c548dc1c27493f3a5793f103",
    )


def _ack_data(request):
    private_key = PrivateKey.from_int(2)
    child = private_key.public_key_xonly.format().hex()
    tapleaf, control, output = _exit_fixture(child)
    data = ArkadeReceiveAcknowledgement(
        native_request_id=request.native_request_id,
        account_id=ACCOUNT_ID,
        wallet_id=WALLET_ID,
        idempotency_key=request.idempotency_key,
        amount_sat=request.amount_sat,
        index=7,
        address=_ark_address(request.server_pubkey, output),
        script="5120" + output,
        child_xonly_pubkey=child,
        network=request.network,
        server_url=request.server_url,
        server_pubkey=request.server_pubkey,
        expires_at=int(request.expires_at.timestamp()),
        signature="00" * 64,
        exit_tapleaf=tapleaf,
        exit_control_block=control,
    )
    digest = hashlib.sha256(
        arkade.canonical_receive_statement(data).encode("ascii")
    ).digest()
    data.signature = private_key.sign_schnorr(digest).hex()
    return data


async def _ack(connection, request):
    data = _ack_data(request)
    return await arkade.acknowledge_arkade_receive(ACCOUNT_ID, data, connection)


async def _create(
    connection, amount_sat=100, idempotency_key="55" * 16, expires_at=None
):
    return await arkade.create_arkade_receive_request_for_account(
        ACCOUNT_ID,
        wallet_id=WALLET_ID,
        amount_sat=amount_sat,
        idempotency_key=idempotency_key,
        expires_at=expires_at or datetime.now(timezone.utc) + timedelta(hours=1),
        conn=connection,
    )


async def _settled_outgoing_with_change(
    connection, *, input_txid: str, input_amount_sat: int, change_amount_sat: int
):
    intent_id = "da" * 16
    arkade_txid = "db" * 32
    now = datetime.now(timezone.utc)
    await connection.execute(
        "INSERT INTO arkade_outgoing_intents ("
        "intent_id, account_id, wallet_id, amount_msat, max_fee_msat, "
        "destination, destination_kind, status, arkade_txid, actual_fee_msat, "
        "expires_at, reserved_at, destination_script, change_index, "
        "change_script, change_amount_sat) VALUES ("
        ":intent, :account, :wallet, :amount, 0, 'destination', "
        "'arkade_address', 'settled', :arkade_txid, 0, :expires_at, :reserved_at, "
        ":destination_script, 9, :change_script, :change_amount_sat)",
        {
            "intent": intent_id,
            "account": ACCOUNT_ID,
            "wallet": WALLET_ID,
            "amount": (input_amount_sat - change_amount_sat) * 1000,
            "arkade_txid": arkade_txid,
            "expires_at": now + timedelta(hours=1),
            "reserved_at": now,
            "destination_script": "5120" + "dc" * 32,
            "change_script": "5120" + "dd" * 32,
            "change_amount_sat": change_amount_sat,
        },
    )
    await connection.execute(
        "INSERT INTO arkade_outgoing_intent_inputs "
        "(intent_id, txid, vout, amount_sat) VALUES (:intent, :txid, 0, :amount)",
        {"intent": intent_id, "txid": input_txid, "amount": input_amount_sat},
    )
    return arkade_txid, "5120" + "dd" * 32


@pytest.mark.anyio
async def test_receive_ack_and_duplicate_reconciliation(connection, ready_mode):
    request = await _create(connection)
    request = await _ack(connection, request)
    assert request.state == "acknowledged"
    request = await _ack(connection, request)
    assert request.state == "acknowledged"
    invalid = _ack_data(request).copy(update={"signature": "00" * 64})
    with pytest.raises(arkade.ArkadeReceiveError, match="INVALID_PROOF"):
        await arkade.acknowledge_arkade_receive(ACCOUNT_ID, invalid, connection)
    unrelated = _ack_data(request)
    unrelated = unrelated.copy(
        update={
            "exit_control_block": unrelated.exit_control_block[:66]
            + PrivateKey.from_int(5).public_key_xonly.format().hex()
        }
    )
    with pytest.raises(arkade.ArkadeReceiveError, match="INVALID_MAPPING"):
        await arkade.acknowledge_arkade_receive(ACCOUNT_ID, unrelated, connection)
    malformed = _ack_data(request).copy(
        update={
            "exit_control_block": "c1"
            + "00" * 32
            + "136f8575c92f23b30addafb8e5e7e15f66a0f18666198f55007626f30bab1ac9"
        }
    )
    with pytest.raises(arkade.ArkadeReceiveError, match="INVALID_MAPPING"):
        await arkade.acknowledge_arkade_receive(ACCOUNT_ID, malformed, connection)
    noncanonical_sequence = _ack_data(request).copy(
        update={
            "exit_tapleaf": "0110b27520"
            + _ack_data(request).child_xonly_pubkey
            + "acc0"
        }
    )
    with pytest.raises(arkade.ArkadeReceiveError, match="INVALID_MAPPING"):
        await arkade.acknowledge_arkade_receive(
            ACCOUNT_ID, noncanonical_sequence, connection
        )
    columns = await connection.fetchall("PRAGMA table_info(arkade_receive_requests)")
    assert "signature" not in {column["name"] for column in columns}
    assert request.script is not None
    vtxo = ArkadeIndexerVtxo(
        txid="66" * 32, vout=0, amount_sat=100, script=request.script
    )
    await arkade.reconcile_arkade_receive(ACCOUNT_ID, [vtxo, vtxo], conn=connection)
    await arkade.reconcile_arkade_receive(ACCOUNT_ID, [vtxo], conn=connection)
    state = await arkade.get_arkade_reconciliation(ACCOUNT_ID, conn=connection)
    assert state and state.state == "ok"
    stored = await connection.fetchone(
        "SELECT COUNT(*) AS count FROM arkade_receive_outpoints"
    )
    assert stored["count"] == 1
    stored_request = await arkade.get_arkade_receive_request(
        request.native_request_id, connection
    )
    assert stored_request and stored_request.state == "settled"


@pytest.mark.anyio
async def test_mapped_wallet_survives_bulk_cleanup(connection, ready_mode):
    request = await _create(connection, idempotency_key="56" * 16)
    await connection.execute(
        "UPDATE wallets SET deleted = true WHERE id = :wallet",
        {"wallet": WALLET_ID},
    )
    await remove_deleted_wallets(connection)
    await connection.execute(
        "UPDATE wallets SET updated_at = 0 WHERE id = :wallet",
        {"wallet": WALLET_ID},
    )
    await delete_unused_wallets(0, connection)
    row = await connection.fetchone(
        "SELECT id FROM wallets WHERE id = :wallet", {"wallet": WALLET_ID}
    )
    assert row and request.wallet_id == WALLET_ID


@pytest.mark.anyio
async def test_bulk_cleanup_reuses_arkade_deletion_guard(connection, ready_mode):
    wallet_id = "22" * 16
    await connection.execute(
        'INSERT INTO wallets (id, "user", name, adminkey, inkey, deleted, '
        "created_at, updated_at) VALUES (:wallet, :account, 'old', 'a', 'b', "
        "true, 0, 0)",
        {"wallet": wallet_id, "account": ACCOUNT_ID},
    )
    await connection.execute(
        "INSERT INTO apipayments (wallet_id, amount, fee, status) "
        "VALUES (:wallet, 1000, 0, 'success')",
        {"wallet": wallet_id},
    )
    await remove_deleted_wallets(connection)
    assert await connection.fetchone(
        "SELECT id FROM wallets WHERE id = :wallet", {"wallet": wallet_id}
    )

    await connection.execute(
        "DELETE FROM apipayments WHERE wallet_id = :wallet", {"wallet": wallet_id}
    )
    await connection.execute(
        "INSERT INTO arkade_outgoing_intents ("
        "intent_id, account_id, wallet_id, amount_msat, max_fee_msat, "
        "destination, destination_kind, status, expires_at) VALUES ("
        ":intent, :account, :wallet, 1000, 0, 'destination', 'arkade_address', "
        "'submitted', :expires_at)",
        {
            "intent": "44" * 16,
            "account": ACCOUNT_ID,
            "wallet": wallet_id,
            "expires_at": datetime.now(timezone.utc) + timedelta(days=1),
        },
    )
    await remove_deleted_wallets(connection)
    assert await connection.fetchone(
        "SELECT id FROM wallets WHERE id = :wallet", {"wallet": wallet_id}
    )

    await connection.execute(
        "DELETE FROM arkade_outgoing_intents WHERE wallet_id = :wallet",
        {"wallet": wallet_id},
    )
    await remove_deleted_wallets(connection)
    assert not await connection.fetchone(
        "SELECT id FROM wallets WHERE id = :wallet", {"wallet": wallet_id}
    )

    unused_wallet_id = "33" * 16
    await connection.execute(
        'INSERT INTO wallets (id, "user", name, adminkey, inkey, deleted, '
        "created_at, updated_at) VALUES (:wallet, :account, 'old', 'a', 'b', "
        "true, 0, 0)",
        {"wallet": unused_wallet_id, "account": ACCOUNT_ID},
    )
    await connection.execute(
        "INSERT INTO arkade_outgoing_intents ("
        "intent_id, account_id, wallet_id, amount_msat, max_fee_msat, "
        "destination, destination_kind, status, expires_at) VALUES ("
        ":intent, :account, :wallet, 1000, 0, 'destination', 'arkade_address', "
        "'submitted', :expires_at)",
        {
            "intent": "55" * 16,
            "account": ACCOUNT_ID,
            "wallet": unused_wallet_id,
            "expires_at": datetime.now(timezone.utc) + timedelta(days=1),
        },
    )
    await delete_unused_wallets(0, connection)
    assert await connection.fetchone(
        "SELECT id FROM wallets WHERE id = :wallet", {"wallet": unused_wallet_id}
    )
    await connection.execute(
        "DELETE FROM arkade_outgoing_intents WHERE wallet_id = :wallet",
        {"wallet": unused_wallet_id},
    )
    await delete_unused_wallets(0, connection)
    assert not await connection.fetchone(
        "SELECT id FROM wallets WHERE id = :wallet", {"wallet": unused_wallet_id}
    )


@pytest.mark.anyio
@pytest.mark.parametrize("cleanup", [remove_deleted_wallets, delete_unused_wallets])
async def test_cleanup_rechecks_reactivated_wallet_before_delete(
    monkeypatch, connection, ready_mode, cleanup
):
    await connection.execute(
        "UPDATE wallets SET deleted = true, updated_at = 0 WHERE id = :wallet",
        {"wallet": WALLET_ID},
    )
    guard = wallets.ensure_arkade_wallet_deletion_allowed

    async def interleave(wallet_id, deleted=True, conn=None):
        await guard(wallet_id, deleted=deleted, conn=conn)
        if deleted:
            await connection.execute(
                "UPDATE wallets SET deleted = false WHERE id = :wallet",
                {"wallet": WALLET_ID},
            )
            await _create(connection, idempotency_key="56" * 16)

    monkeypatch.setattr(wallets, "ensure_arkade_wallet_deletion_allowed", interleave)
    if cleanup is delete_unused_wallets:
        await cleanup(0, connection)
    else:
        await cleanup(connection)

    row = await connection.fetchone(
        "SELECT deleted FROM wallets WHERE id = :wallet", {"wallet": WALLET_ID}
    )
    assert row and not row["deleted"]


@pytest.mark.anyio
async def test_late_payment_after_expiry_keeps_mapping(connection, ready_mode):
    request = await _create(
        connection,
        idempotency_key="57" * 16,
        expires_at=datetime.now(timezone.utc) - timedelta(minutes=1),
    )
    request = await _ack(connection, request)
    assert request.script is not None
    await arkade.reconcile_arkade_receive(
        ACCOUNT_ID,
        [
            ArkadeIndexerVtxo(
                txid="58" * 32, vout=0, amount_sat=100, script=request.script
            )
        ],
        conn=connection,
    )
    stored = await arkade.get_arkade_receive_request(
        request.native_request_id, connection
    )
    assert stored and stored.wallet_id == WALLET_ID and stored.state == "settled"


@pytest.mark.anyio
async def test_conflicting_amount_fails_closed(connection, ready_mode):
    request = await _create(connection, idempotency_key="77" * 16)
    request = await _ack(connection, request)
    assert request.script is not None
    await arkade.reconcile_arkade_receive(
        ACCOUNT_ID,
        [
            ArkadeIndexerVtxo(
                txid="88" * 32,
                vout=0,
                amount_sat=101,
                script=request.script,
            )
        ],
        conn=connection,
    )
    state = await arkade.get_arkade_reconciliation(ACCOUNT_ID, conn=connection)
    assert state and state.state == "reconciliation_required"
    outpoint = await connection.fetchone(
        "SELECT status FROM arkade_receive_outpoints WHERE native_request_id = :id",
        {"id": request.native_request_id},
    )
    assert outpoint and outpoint["status"] == "conflict"
    stored_request = await arkade.get_arkade_receive_request(
        request.native_request_id, connection
    )
    assert stored_request and stored_request.state == "reconciliation_required"
    clean = ArkadeIndexerVtxo(
        txid="89" * 32,
        vout=0,
        amount_sat=100,
        script=request.script,
    )
    await arkade.reconcile_arkade_receive(ACCOUNT_ID, [clean], conn=connection)
    state = await arkade.get_arkade_reconciliation(ACCOUNT_ID, conn=connection)
    assert state and state.state == "reconciliation_required"


@pytest.mark.anyio
async def test_request_and_mapping_conflicts_are_rejected(connection, ready_mode):
    with pytest.raises(arkade.ArkadeReceiveError, match="INVALID_IDEMPOTENCY"):
        await _create(connection, idempotency_key="bad")
    request = await _create(connection, idempotency_key="ee" * 16)
    with pytest.raises(arkade.ArkadeReceiveError, match="IDEMPOTENCY_CONFLICT"):
        await arkade.create_arkade_receive_request_for_account(
            ACCOUNT_ID,
            wallet_id=WALLET_ID,
            amount_sat=101,
            idempotency_key="ee" * 16,
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
            conn=connection,
        )
    data = _ack_data(request)
    await arkade.acknowledge_arkade_receive(ACCOUNT_ID, data, connection)
    wrong_account = data.copy(update={"account_id": "ff" * 16})
    with pytest.raises(arkade.ArkadeReceiveError, match="ACCOUNT_MISMATCH"):
        await arkade.acknowledge_arkade_receive(ACCOUNT_ID, wrong_account, connection)
    wrong_config = data.copy(update={"server_url": "http://other-arkade"})
    with pytest.raises(arkade.ArkadeReceiveError, match="MAPPING_CONFLICT"):
        await arkade.acknowledge_arkade_receive(ACCOUNT_ID, wrong_config, connection)
    wrong_wallet = data.copy(update={"wallet_id": "ff" * 16})
    with pytest.raises(arkade.ArkadeReceiveError, match="MAPPING_CONFLICT"):
        await arkade.acknowledge_arkade_receive(ACCOUNT_ID, wrong_wallet, connection)
    wrong_signature = data.copy(update={"signature": "00" * 64})
    with pytest.raises(arkade.ArkadeReceiveError, match="INVALID_PROOF"):
        await arkade.acknowledge_arkade_receive(ACCOUNT_ID, wrong_signature, connection)
    second = await _create(connection, amount_sat=50, idempotency_key="ef" * 16)
    conflict = data.copy(update={"script": "5120" + "bb" * 32})
    with pytest.raises(arkade.ArkadeReceiveError, match="MAPPING_CONFLICT"):
        await arkade.acknowledge_arkade_receive(ACCOUNT_ID, conflict, connection)
    # Same index/address/script is rejected by the portable unique constraints.
    with pytest.raises(arkade.ArkadeReceiveError, match="MAPPING_CONFLICT"):
        await _ack(connection, second)


@pytest.mark.anyio
async def test_partial_receive_remains_acknowledged(connection, ready_mode):
    request = await _create(connection, idempotency_key="ab" * 16)
    request = await _ack(connection, request)
    assert request.script is not None
    await arkade.reconcile_arkade_receive(
        ACCOUNT_ID,
        [
            ArkadeIndexerVtxo(
                txid="ac" * 32,
                vout=0,
                amount_sat=40,
                script=request.script,
            )
        ],
        conn=connection,
    )
    state = await arkade.get_arkade_reconciliation(ACCOUNT_ID, conn=connection)
    assert state and state.state == "ok"
    stored_request = await arkade.get_arkade_receive_request(
        request.native_request_id, connection
    )
    assert stored_request and stored_request.state == "acknowledged"


@pytest.mark.anyio
async def test_verified_outgoing_change_is_backing_without_income(
    connection, ready_mode
):
    request = await _ack(connection, await _create(connection))
    assert request.script
    received = ArkadeIndexerVtxo(
        txid="a1" * 32, vout=0, amount_sat=100, script=request.script
    )
    await arkade.reconcile_arkade_receive(ACCOUNT_ID, [received], conn=connection)
    arkade_txid, change_script = await _settled_outgoing_with_change(
        connection, input_txid=received.txid, input_amount_sat=100, change_amount_sat=60
    )
    spent = received.copy(
        update={
            "is_spent": True,
            "spent_by": "a2" * 32,
            "arkade_txid": arkade_txid,
        }
    )
    change = ArkadeIndexerVtxo(
        txid=arkade_txid,
        vout=1,
        amount_sat=60,
        script=change_script,
        is_preconfirmed=True,
    )

    await arkade.reconcile_arkade_receive(ACCOUNT_ID, [spent, change], conn=connection)

    state = await arkade.get_arkade_reconciliation(ACCOUNT_ID, conn=connection)
    assert state and state.state == "ok"
    outpoints = await connection.fetchone(
        "SELECT COUNT(*) AS count, COALESCE(SUM(amount_sat), 0) AS total "
        "FROM arkade_receive_outpoints WHERE account_id = :account_id",
        {"account_id": ACCOUNT_ID},
    )
    assert outpoints["count"] == 1
    assert outpoints["total"] == 100


@pytest.mark.anyio
@pytest.mark.parametrize(
    "divergence",
    ["external_spend", "expiry", "height_expiry", "renewal", "missing"],
)
async def test_backing_divergence_holds_account(connection, ready_mode, divergence):
    request = await _ack(connection, await _create(connection))
    assert request.script
    received = ArkadeIndexerVtxo(
        txid="b1" * 32, vout=0, amount_sat=100, script=request.script
    )
    await arkade.reconcile_arkade_receive(ACCOUNT_ID, [received], conn=connection)
    if divergence == "external_spend":
        evidence = [
            received.copy(
                update={
                    "is_spent": True,
                    "spent_by": "b2" * 32,
                    "arkade_txid": "b3" * 32,
                }
            )
        ]
    elif divergence == "expiry":
        evidence = [
            received.copy(
                update={"expires_at": datetime.now(timezone.utc) - timedelta(seconds=1)}
            )
        ]
    elif divergence == "height_expiry":
        evidence = [received.copy(update={"expires_at_height": 144})]
    elif divergence == "missing":
        evidence = []
    else:
        evidence = [
            received.copy(update={"is_swept": True}),
            received.copy(update={"txid": "b4" * 32}),
        ]

    await arkade.reconcile_arkade_receive(ACCOUNT_ID, evidence, conn=connection)

    state = await arkade.get_arkade_reconciliation(ACCOUNT_ID, conn=connection)
    assert state and state.state == "reconciliation_required"


@pytest.mark.anyio
async def test_fresh_backing_fetch_includes_settled_change_script(
    connection, ready_mode, monkeypatch
):
    _, change_script = await _settled_outgoing_with_change(
        connection, input_txid="c1" * 32, input_amount_sat=100, change_amount_sat=60
    )
    requested_scripts = []

    class Response:
        def raise_for_status(self):
            return None

        def json(self):
            return {"vtxos": [], "page": {"current": 1, "next": 0, "total": 0}}

    class Client:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return None

        async def get(self, _url, *, params):
            requested_scripts.extend(value for key, value in params if key == "scripts")
            return Response()

    monkeypatch.setattr(arkade.httpx, "AsyncClient", lambda **_kwargs: Client())
    assert await arkade.fetch_arkade_indexer_vtxos(ACCOUNT_ID, connection) == []
    assert change_script in requested_scripts


@pytest.mark.anyio
async def test_unattributed_state_is_sticky_and_terminal_flags_merge(
    connection, ready_mode
):
    unknown = ArkadeIndexerVtxo(
        txid="99" * 32, vout=1, amount_sat=3, script="5120" + "bb" * 32
    )
    await arkade.reconcile_arkade_receive(ACCOUNT_ID, [unknown], conn=connection)
    await arkade.reconcile_arkade_receive(ACCOUNT_ID, [], conn=connection)
    state = await arkade.get_arkade_reconciliation(ACCOUNT_ID, conn=connection)
    assert state and state.state == "reconciliation_required"
    await arkade.reconcile_arkade_receive(ACCOUNT_ID, [unknown], conn=connection)
    outpoint_count = await connection.fetchone(
        "SELECT COUNT(*) AS count FROM arkade_receive_outpoints "
        "WHERE txid = :txid AND vout = :vout",
        {"txid": unknown.txid, "vout": unknown.vout},
    )
    assert outpoint_count["count"] == 1

    request = await _create(connection, idempotency_key="9a" * 16)
    data = _ack_data(request)
    unattributed = ArkadeIndexerVtxo(
        txid="9b" * 32,
        vout=0,
        amount_sat=request.amount_sat,
        script=data.script,
        is_spent=True,
        spent_by="9c" * 32,
    )
    await arkade.reconcile_arkade_receive(ACCOUNT_ID, [unattributed], conn=connection)
    await arkade.acknowledge_arkade_receive(ACCOUNT_ID, data, connection)
    conflicting_terminal = unattributed.copy(update={"spent_by": "9d" * 32})
    await arkade.reconcile_arkade_receive(
        ACCOUNT_ID, [conflicting_terminal], conn=connection
    )
    outpoint = await connection.fetchone(
        "SELECT native_request_id, status FROM arkade_receive_outpoints "
        "WHERE txid = :txid",
        {"txid": unattributed.txid},
    )
    assert outpoint and outpoint["native_request_id"] is None
    assert outpoint["status"] == "conflict"

    request = await arkade.get_arkade_receive_request(
        request.native_request_id, connection
    )
    assert request and request.script is not None
    spent = ArkadeIndexerVtxo(
        txid="ab" * 32,
        vout=0,
        amount_sat=100,
        script=request.script,
        is_preconfirmed=True,
        is_spent=True,
        spent_by="cd" * 32,
    )
    old = spent.copy(
        update={"is_preconfirmed": False, "is_spent": False, "spent_by": None}
    )
    await arkade.reconcile_arkade_receive(ACCOUNT_ID, [spent], conn=connection)
    await arkade.reconcile_arkade_receive(ACCOUNT_ID, [old], conn=connection)
    row = await connection.fetchone(
        "SELECT is_preconfirmed, is_spent, spent_by FROM arkade_receive_outpoints "
        "WHERE txid = :txid",
        {"txid": spent.txid},
    )
    assert not bool(row["is_preconfirmed"])
    assert bool(row["is_spent"])
    assert row["spent_by"] == spent.spent_by
    conflict = spent.copy(update={"spent_by": "ef" * 32})
    await arkade.reconcile_arkade_receive(ACCOUNT_ID, [conflict], conn=connection)
    state = await arkade.get_arkade_reconciliation(ACCOUNT_ID, conn=connection)
    assert state and state.state == "reconciliation_required"


@pytest.mark.anyio
async def test_cross_account_conflict_cannot_mutate_other_row(connection, ready_mode):
    account_b = "bb" * 16
    txid = "bc" * 32
    script = "5120" + "bd" * 32
    await connection.execute(
        "INSERT INTO accounts (id) VALUES (:id)", {"id": account_b}
    )
    await connection.execute(
        "INSERT INTO arkade_receive_outpoints "
        "(account_id, txid, vout, amount_sat, script, status) VALUES "
        "(:account_id, :txid, 0, 100, :script, 'valid')",
        {"account_id": account_b, "txid": txid, "script": script},
    )
    await arkade.reconcile_arkade_receive(
        ACCOUNT_ID,
        [ArkadeIndexerVtxo(txid=txid, vout=0, amount_sat=101, script=script)],
        conn=connection,
    )
    row = await connection.fetchone(
        "SELECT status FROM arkade_receive_outpoints "
        "WHERE account_id = :account_id AND txid = :txid",
        {"account_id": account_b, "txid": txid},
    )
    assert row and row["status"] == "valid"
    state = await arkade.get_arkade_reconciliation(ACCOUNT_ID, conn=connection)
    assert state and state.state == "reconciliation_required"


@pytest.mark.anyio
async def test_indexer_pages_use_pinned_page_parameters(
    connection, ready_mode, monkeypatch
):
    request = await _create(connection, idempotency_key="bb" * 16)
    request = await _ack(connection, request)

    class Response:
        def __init__(self, body):
            self.body = body

        def raise_for_status(self):
            return None

        def json(self):
            return self.body

    class Client:
        pages = {
            0: {
                "vtxos": [
                    {
                        "outpoint": {"txid": "10" * 32, "vout": 0},
                        "amount": "40",
                        "script": request.script,
                        "isPreconfirmed": False,
                        "isSpent": False,
                        "isSwept": False,
                        "isUnrolled": False,
                        "createdAt": "1735689600",
                        "expiresAt": None,
                        "commitmentTxids": [],
                    }
                ],
                "page": {"current": 1, "next": 2, "total": 2},
            },
            2: {
                "vtxos": [
                    {
                        "outpoint": {"txid": "20" * 32, "vout": 0},
                        "amount": "60",
                        "script": request.script,
                        "isPreconfirmed": False,
                        "isSpent": False,
                        "isSwept": False,
                        "isUnrolled": False,
                        "createdAt": "1735689600",
                        "expiresAt": None,
                        "commitmentTxids": [],
                    }
                ],
                "page": {"current": 2, "next": 2, "total": 2},
            },
        }
        calls = []

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return None

        async def get(self, _url, params):
            self.calls.append(params)
            params = dict(params)
            return Response(self.pages[int(params["page.index"])])

    client = Client()
    monkeypatch.setattr(arkade.httpx, "AsyncClient", lambda **_kwargs: client)
    evidence = await arkade.fetch_arkade_indexer_vtxos(ACCOUNT_ID, connection)
    assert [item.amount_sat for item in evidence] == [40, 60]
    assert [dict(call)["page.index"] for call in client.calls] == ["0", "2"]
    assert all(("scripts", request.script) in call for call in client.calls)
    assert all(("page.size", "500") in call for call in client.calls)


@pytest.mark.anyio
async def test_invalid_indexer_json_marks_required(connection, ready_mode, monkeypatch):
    request = await _create(connection, idempotency_key="cc" * 16)
    await _ack(connection, request)

    class Client:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return None

        async def get(self, *_args, **_kwargs) -> object:
            class Response:
                def raise_for_status(self):
                    return None

                def json(self):
                    raise ValueError("upstream detail")

            return Response()

    monkeypatch.setattr(arkade.httpx, "AsyncClient", lambda **_kwargs: Client())
    with pytest.raises(arkade.ArkadeReceiveError, match="INVALID_RESPONSE"):
        await arkade.fetch_arkade_indexer_vtxos(ACCOUNT_ID, connection)
    state = await arkade.get_arkade_reconciliation(ACCOUNT_ID, conn=connection)
    assert state and state.state == "reconciliation_required"


@pytest.mark.anyio
async def test_indexer_reconnect_after_transport_failure(
    connection, ready_mode, monkeypatch
):
    request = await _create(connection, idempotency_key="cd" * 16)
    await _ack(connection, request)

    class Offline:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return None

        async def get(self, *_args, **_kwargs) -> object:
            raise arkade.httpx.ConnectError("offline")

    monkeypatch.setattr(arkade.httpx, "AsyncClient", lambda **_kwargs: Offline())
    with pytest.raises(arkade.ArkadeReceiveError, match="UNAVAILABLE"):
        await arkade.fetch_arkade_indexer_vtxos(ACCOUNT_ID, connection)

    class Online(Offline):
        async def get(self, *_args, **_kwargs) -> object:
            return type(
                "Response",
                (),
                {
                    "raise_for_status": lambda _self: None,
                    "json": lambda _self: {
                        "vtxos": [],
                        "page": {"current": 1, "next": 1, "total": 1},
                    },
                },
            )()

    monkeypatch.setattr(arkade.httpx, "AsyncClient", lambda **_kwargs: Online())
    assert await arkade.fetch_arkade_indexer_vtxos(ACCOUNT_ID, connection) == []


@pytest.mark.anyio
async def test_indexer_chunks_32_scripts(connection, ready_mode, monkeypatch):
    now = datetime.now(timezone.utc)
    for index in range(33):
        key = f"{index + 1:064x}"
        await connection.execute(
            "INSERT INTO arkade_receive_requests ("
            "native_request_id, account_id, wallet_id, idempotency_key, amount_sat, "
            '"index", address, script, child_xonly_pubkey, network, server_url, '
            "server_pubkey, expires_at, state) VALUES ("
            ":request_id, :account_id, :wallet_id, :idempotency_key, 1, :idx, "
            ":address, :script, :child, 'regtest', 'http://arkade', :server, "
            ":expires_at, 'acknowledged')",
            {
                "request_id": f"{index + 100:032x}",
                "account_id": ACCOUNT_ID,
                "wallet_id": WALLET_ID,
                "idempotency_key": f"{index + 100:032x}",
                "idx": index + 100,
                "address": _ark_address("33" * 32, key),
                "script": "5120" + key,
                "child": "11" * 32,
                "server": "33" * 32,
                "expires_at": now,
            },
        )

    class Client:
        calls = []

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return None

        async def get(self, _url, params):
            self.calls.append(params)
            return type(
                "Response",
                (),
                {
                    "raise_for_status": lambda _self: None,
                    "json": lambda _self: {
                        "vtxos": [],
                        "page": {"current": 1, "next": 1, "total": 1},
                    },
                },
            )()

    client = Client()
    monkeypatch.setattr(arkade.httpx, "AsyncClient", lambda **_kwargs: client)
    await arkade.fetch_arkade_indexer_vtxos(ACCOUNT_ID, connection)
    assert len(client.calls) == 2
    assert [sum(key == "scripts" for key, _ in call) for call in client.calls] == [
        32,
        1,
    ]


def test_indexer_parser_rejects_unpinned_shapes():
    assert (
        arkade.parse_indexer_vtxos(
            {"vtxos": [], "page": {"current": 1, "next": 0, "total": 0}}
        )
        == []
    )
    with pytest.raises(arkade.ArkadeReceiveError, match="INVALID_RESPONSE"):
        arkade.parse_indexer_vtxos(
            {
                "vtxos": [
                    {
                        "outpoint": {"txid": "aa" * 32, "vout": 0},
                        "amount": "1",
                        "script": "51",
                        "isPreconfirmed": False,
                        "isSpent": False,
                        "isSwept": False,
                        "isUnrolled": False,
                        "createdAt": "1735689600",
                        "expiresAt": None,
                        "commitmentTxids": [],
                    }
                ],
                "page": {"current": 1, "next": 0, "total": 0},
            }
        )
    with pytest.raises(arkade.ArkadeReceiveError, match="INVALID_RESPONSE"):
        arkade._validate_indexer_page({"current": 1, "next": 2})
    with pytest.raises(arkade.ArkadeReceiveError, match="INVALID_RESPONSE"):
        arkade._validate_indexer_page({"current": 2, "next": 3, "total": 1})
    with pytest.raises(arkade.ArkadeReceiveError, match="INVALID_RESPONSE"):
        arkade.parse_indexer_vtxos(
            {
                "vtxos": [
                    {
                        "outpoint": {"txid": "aa" * 32, "vout": 0},
                        "amount": 1,
                        "script": "51",
                    }
                ]
            }
        )
    parsed = arkade.parse_indexer_vtxos(
        {
            "vtxos": [
                {
                    "outpoint": {"txid": "bb" * 32, "vout": 0},
                    "amount": "1",
                    "script": "51",
                    "isPreconfirmed": False,
                    "isSpent": False,
                    "isSwept": False,
                    "isUnrolled": False,
                    "createdAt": "1735689600",
                    "expiresAt": None,
                    "commitmentTxids": [],
                    "spentBy": "",
                }
            ]
        }
    )
    assert parsed[0].spent_by is None
    with pytest.raises(arkade.ArkadeReceiveError, match="INVALID_RESPONSE"):
        arkade.parse_indexer_vtxos(
            {
                "vtxos": [
                    {
                        "outpoint": {"txid": "bb" * 32, "vout": 0},
                        "amount": "1",
                        "script": "51",
                        "isSpent": False,
                        "isSwept": False,
                    }
                ]
            }
        )


async def _browser_funded_lightning_intent(connection, *, funding_txid: str):
    """A swap the client funded itself: no inputs or change journaled."""
    intent_id = "ee" * 16
    now = datetime.now(timezone.utc)
    await connection.execute(
        "INSERT INTO arkade_outgoing_intents ("
        "intent_id, account_id, wallet_id, amount_msat, max_fee_msat, "
        "destination, destination_kind, status, arkade_txid, "
        "expires_at, reserved_at) VALUES ("
        ":intent, :account, :wallet, 1000000, 4000, 'bolt11', "
        "'lightning', 'submitted', :arkade_txid, :expires_at, :reserved_at)",
        {
            "intent": intent_id,
            "account": ACCOUNT_ID,
            "wallet": WALLET_ID,
            "arkade_txid": funding_txid,
            "expires_at": now + timedelta(hours=1),
            "reserved_at": now,
        },
    )
    return intent_id


@pytest.mark.anyio
async def test_browser_funded_swap_attributes_spend_and_change(connection, ready_mode):
    """Funding our own input and returning change must not flag the account."""
    request = await _ack(connection, await _create(connection))
    assert request.script
    received = ArkadeIndexerVtxo(
        txid="b1" * 32, vout=0, amount_sat=100, script=request.script
    )
    await arkade.reconcile_arkade_receive(ACCOUNT_ID, [received], conn=connection)

    funding_txid = "b2" * 32
    intent_id = await _browser_funded_lightning_intent(
        connection, funding_txid=funding_txid
    )
    spent = received.copy(
        update={
            "is_spent": True,
            "spent_by": "b3" * 32,
            "arkade_txid": funding_txid,
        }
    )
    change = ArkadeIndexerVtxo(
        txid=funding_txid,
        vout=1,
        amount_sat=60,
        script=request.script,
        is_preconfirmed=True,
    )

    await arkade.reconcile_arkade_receive(ACCOUNT_ID, [spent, change], conn=connection)

    state = await arkade.get_arkade_reconciliation(ACCOUNT_ID, conn=connection)
    assert state and state.state == "ok"
    stored = await connection.fetchone(
        "SELECT change_index, change_script, change_amount_sat "
        "FROM arkade_outgoing_intents WHERE intent_id = :intent_id",
        {"intent_id": intent_id},
    )
    assert stored is not None
    # The wallet's change index is the client's derivation index, so the
    # reconciler skips the change output without inventing one.
    assert stored["change_index"] is None
    assert stored["change_script"] is None
    assert stored["change_amount_sat"] is None

    with pytest.raises(arkade.ArkadeReceiveError, match="INVALID_RESPONSE"):
        arkade.parse_indexer_vtxos(
            {
                "vtxos": [
                    {
                        "outpoint": {"txid": "bb" * 32, "vout": 2**32},
                        "amount": "1",
                        "script": "51",
                        "isPreconfirmed": False,
                        "isSpent": False,
                        "isSwept": False,
                    }
                ]
            }
        )
    with pytest.raises(arkade.ArkadeReceiveError, match="INVALID_RESPONSE"):
        arkade.parse_indexer_vtxos(
            {
                "vtxos": [
                    {
                        "outpoint": {"txid": "bb" * 32, "vout": 0},
                        "amount": str(2_100_000_000_000_001),
                        "script": "51",
                        "isPreconfirmed": False,
                        "isSpent": False,
                        "isSwept": False,
                    }
                ]
            }
        )
