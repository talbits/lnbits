from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock

import httpx
import pytest
from embit.psbt import PSBT
from embit.script import Script
from embit.transaction import Transaction, TransactionInput, TransactionOutput

from lnbits.core.models.arkade import (
    ArkadeIndexerVtxo,
    ArkadeOutgoingIntentInput,
)
from lnbits.core.services import arkade

DESTINATION = "5120" + "22" * 32
CHANGE = "5120" + "33" * 32
INPUT_TXID = "aa" * 32
CHECKPOINT_TXID = "bb" * 32
ARK_TXID = "cc" * 32


def _claim(
    amount_sat: int = 10, txid: str = INPUT_TXID, vout: int = 0
) -> ArkadeOutgoingIntentInput:
    return ArkadeOutgoingIntentInput(
        intent_id="11" * 16,
        txid=txid,
        vout=vout,
        amount_sat=amount_sat,
    )


def _evidence(
    *,
    amount_sat: int = 10,
    spent_by: str | None = CHECKPOINT_TXID,
    arkade_txid: str | None = ARK_TXID,
    settled_by: str | None = None,
    is_spent: bool = True,
    is_swept: bool = False,
    is_unrolled: bool = False,
    txid: str = INPUT_TXID,
    vout: int = 0,
) -> ArkadeIndexerVtxo:
    return ArkadeIndexerVtxo(
        txid=txid,
        vout=vout,
        amount_sat=amount_sat,
        script="5120" + "44" * 32,
        created_at=datetime.now(timezone.utc),
        commitment_txids=[],
        spent_by=spent_by,
        arkade_txid=arkade_txid,
        settled_by=settled_by,
        is_spent=is_spent,
        is_swept=is_swept,
        is_unrolled=is_unrolled,
    )


def _psbt(amount_sat: int = 10, *, change: bool = False) -> tuple[str, str]:
    outputs = [
        TransactionOutput(
            amount_sat - (5 if change else 0), Script(bytes.fromhex(DESTINATION))
        )
    ]
    if change:
        outputs.append(TransactionOutput(5, Script(bytes.fromhex(CHANGE))))
    outputs.append(TransactionOutput(0, Script(bytes.fromhex("51024e73"))))
    tx = Transaction(
        version=3,
        vin=[TransactionInput(bytes.fromhex(CHECKPOINT_TXID), 0)],
        vout=outputs,
    )
    psbt = PSBT(tx)
    psbt.inputs[0].witness_utxo = TransactionOutput(
        amount_sat, Script(bytes.fromhex("5120" + "55" * 32))
    )
    encoded = psbt.to_base64()
    return encoded, psbt.tx.txid().hex()


def test_outgoing_virtual_tx_verifies_no_change():
    encoded, txid = _psbt()
    result = arkade.verify_arkade_outgoing_virtual_tx(
        arkade_txid=txid,
        psbt_base64=encoded,
        claims=[_claim()],
        evidence=[_evidence(arkade_txid=txid)],
        destination_script=DESTINATION,
        amount_msat=10_000,
    )
    assert result.status == "verified"
    assert result.arkade_txid == txid


def test_outgoing_virtual_tx_verifies_change():
    encoded, txid = _psbt(15, change=True)
    result = arkade.verify_arkade_outgoing_virtual_tx(
        arkade_txid=txid,
        psbt_base64=encoded,
        claims=[_claim(15)],
        evidence=[_evidence(amount_sat=15, arkade_txid=txid)],
        destination_script=DESTINATION,
        amount_msat=10_000,
        change_script=CHANGE,
        change_amount_sat=5,
    )
    assert result.status == "verified"


@pytest.mark.parametrize(
    ("updates", "status", "code"),
    [
        ({"is_spent": False, "spent_by": None}, "pending", "NOT_SPENT"),
        ({"arkade_txid": "dd" * 32}, "verified", None),
        ({"is_swept": True}, "contradictory", "TERMINAL_CONFLICT"),
        ({"is_unrolled": True}, "contradictory", "TERMINAL_CONFLICT"),
        ({"settled_by": "dd" * 32}, "contradictory", "TERMINAL_CONFLICT"),
    ],
)
def test_outgoing_indexer_evidence_classification(updates, status, code):
    evidence = _evidence(**updates)
    result = arkade.classify_arkade_outgoing_evidence([_claim()], [evidence])
    assert result.status == status
    if code:
        assert result.code and code in result.code


def test_outgoing_indexer_evidence_conflicting_ark_ids_is_contradictory():
    second_claim = _claim(10, txid="ee" * 32)
    second_evidence = _evidence(
        txid="ee" * 32,
        spent_by="ff" * 32,
        arkade_txid="dd" * 32,
    )
    result = arkade.classify_arkade_outgoing_evidence(
        [_claim(), second_claim], [_evidence(), second_evidence]
    )
    assert result.status == "contradictory"
    assert result.code == "ARKADE_OUTGOING_EVIDENCE_ARK_TXID_CONFLICT"


def test_outgoing_indexer_evidence_missing_is_pending():
    result = arkade.classify_arkade_outgoing_evidence([_claim()], [])
    assert result.status == "pending"
    assert result.code == "ARKADE_OUTGOING_EVIDENCE_INCOMPLETE"


def test_outgoing_indexer_evidence_binds_claim_amount():
    result = arkade.classify_arkade_outgoing_evidence(
        [_claim(15)], [_evidence(amount_sat=10)]
    )
    assert result.status == "contradictory"
    assert result.code == "ARKADE_OUTGOING_EVIDENCE_INPUT_VALUE_INVALID"


@pytest.mark.parametrize("field", ["spent_by", "arkade_txid"])
def test_outgoing_indexer_evidence_rejects_malformed_ids(field):
    evidence = _evidence()
    evidence = ArkadeIndexerVtxo.construct(**{**evidence.dict(), field: "gg" * 32})
    with pytest.raises(arkade.ArkadeReceiveError, match="INVALID_RESPONSE"):
        arkade.classify_arkade_outgoing_evidence([_claim()], [evidence])


def test_outgoing_virtual_tx_rejects_claim_amount_mismatch():
    encoded, txid = _psbt()
    result = arkade.verify_arkade_outgoing_virtual_tx(
        arkade_txid=txid,
        psbt_base64=encoded,
        claims=[_claim(15)],
        evidence=[_evidence(arkade_txid=txid)],
        destination_script=DESTINATION,
        amount_msat=10_000,
    )
    assert result.status == "contradictory"
    assert result.code == "ARKADE_OUTGOING_EVIDENCE_INPUT_VALUE_INVALID"


@pytest.mark.parametrize("kind", ["txid", "input", "p2a"])
def test_outgoing_virtual_tx_conflicts_are_contradictory(kind):
    encoded, txid = _psbt()
    if kind == "txid":
        result = arkade.verify_arkade_outgoing_virtual_tx(
            arkade_txid="dd" * 32,
            psbt_base64=encoded,
            claims=[_claim()],
            evidence=[_evidence(arkade_txid=txid)],
            destination_script=DESTINATION,
            amount_msat=10_000,
        )
    elif kind == "input":
        bad_tx = Transaction(
            version=3,
            vin=[TransactionInput(bytes.fromhex("ee" * 32), 0)],
            vout=[
                TransactionOutput(10, Script(bytes.fromhex(DESTINATION))),
                TransactionOutput(0, Script(bytes.fromhex("51024e73"))),
            ],
        )
        bad_psbt = PSBT(bad_tx)
        bad_psbt.inputs[0].witness_utxo = TransactionOutput(
            10, Script(bytes.fromhex("5120" + "55" * 32))
        )
        result = arkade.verify_arkade_outgoing_virtual_tx(
            arkade_txid=bad_psbt.tx.txid().hex(),
            psbt_base64=bad_psbt.to_base64(),
            claims=[_claim()],
            evidence=[_evidence(arkade_txid=bad_psbt.tx.txid().hex())],
            destination_script=DESTINATION,
            amount_msat=10_000,
        )
    else:
        bad_psbt = PSBT.parse(__import__("base64").b64decode(encoded))
        bad_psbt.outputs[-1].script_pubkey = Script(bytes.fromhex("6a00"))
        result = arkade.verify_arkade_outgoing_virtual_tx(
            arkade_txid=txid,
            psbt_base64=bad_psbt.to_base64(),
            claims=[_claim()],
            evidence=[_evidence(arkade_txid=txid)],
            destination_script=DESTINATION,
            amount_msat=10_000,
        )
    assert result.status == "contradictory"


def test_outgoing_virtual_tx_malformed_psbt_is_sanitized():
    with pytest.raises(arkade.ArkadeReceiveError, match="INVALID_RESPONSE"):
        arkade.verify_arkade_outgoing_virtual_tx(
            arkade_txid=ARK_TXID,
            psbt_base64="not-base64",
            claims=[_claim()],
            evidence=[_evidence()],
            destination_script=DESTINATION,
            amount_msat=10_000,
        )


def test_outgoing_virtual_tx_rejects_duplicate_inputs():
    tx = Transaction(
        version=3,
        vin=[
            TransactionInput(bytes.fromhex(CHECKPOINT_TXID), 0),
            TransactionInput(bytes.fromhex(CHECKPOINT_TXID), 0),
        ],
        vout=[
            TransactionOutput(10, Script(bytes.fromhex(DESTINATION))),
            TransactionOutput(0, Script(bytes.fromhex("51024e73"))),
        ],
    )
    parsed = PSBT(tx)
    for item in parsed.inputs:
        item.witness_utxo = TransactionOutput(
            10, Script(bytes.fromhex("5120" + "55" * 32))
        )
    txid = parsed.tx.txid().hex()
    result = arkade.verify_arkade_outgoing_virtual_tx(
        arkade_txid=txid,
        psbt_base64=parsed.to_base64(),
        claims=[_claim()],
        evidence=[_evidence(arkade_txid=txid)],
        destination_script=DESTINATION,
        amount_msat=10_000,
    )
    assert result.status == "contradictory"
    assert result.code == "ARKADE_OUTGOING_EVIDENCE_INPUT_INVALID"


def test_outgoing_virtual_tx_rejects_oversized_base64():
    oversized = "A" * (arkade._MAX_INDEXER_PSBT_BASE64_LENGTH + 4)
    with pytest.raises(arkade.ArkadeReceiveError, match="INVALID_RESPONSE"):
        arkade.verify_arkade_outgoing_virtual_tx(
            arkade_txid=ARK_TXID,
            psbt_base64=oversized,
            claims=[_claim()],
            evidence=[_evidence()],
            destination_script=DESTINATION,
            amount_msat=10_000,
        )


@pytest.mark.anyio
async def test_virtual_tx_fetch_http_error_is_sanitized(monkeypatch):
    monkeypatch.setattr(
        arkade,
        "get_arkade_binding",
        AsyncMock(return_value=_binding()),
    )

    class Client:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return None

        async def get(self, *_args, **_kwargs):
            raise httpx.ConnectError("private upstream detail")

    monkeypatch.setattr(arkade.httpx, "AsyncClient", lambda **_kwargs: Client())
    with pytest.raises(arkade.ArkadeReceiveError, match="UNAVAILABLE"):
        await arkade.fetch_arkade_indexer_virtual_tx("00" * 16, ARK_TXID)


@pytest.mark.anyio
async def test_outpoint_fetch_can_include_spent_vtxos(monkeypatch):
    monkeypatch.setattr(
        arkade,
        "get_arkade_binding",
        AsyncMock(return_value=_binding()),
    )

    class Response:
        def raise_for_status(self):
            return None

        def json(self):
            return {"vtxos": [], "page": {"current": 0, "next": 0, "total": 0}}

    class Client:
        def __init__(self):
            self.params = None

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return None

        async def get(self, _url, params):
            self.params = params
            return Response()

    client = Client()
    monkeypatch.setattr(arkade.httpx, "AsyncClient", lambda **_kwargs: client)
    await arkade.fetch_arkade_indexer_vtxos_for_outpoints(
        "00" * 16, [(INPUT_TXID, 0)], spendable_only=False
    )
    assert client.params is not None
    assert ("spendableOnly", "false") in client.params


def _binding():
    return SimpleNamespace(state="ready", server_url="http://indexer")
