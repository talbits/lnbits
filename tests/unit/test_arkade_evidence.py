import hashlib
import json
from pathlib import Path

import pytest
from embit.compact import to_bytes
from embit.psbt import PSBT
from embit.script import Script, Witness
from embit.transaction import Transaction, TransactionInput, TransactionOutput

from lnbits.core.services.arkade import _TAPROOT_UNSPENDABLE_KEY, _tagged_hash
from lnbits.core.services.arkade_evidence import (
    ArkadeLightningEvidenceIntent,
    ArkadeLightningEvidenceStatus,
    verify_arkade_lightning_terminal_evidence,
)

ROOT = Path(__file__).parents[2]
REAL_FIXTURE = json.loads((ROOT / "tests/fixtures/arkade_l5_evidence.json").read_text())

LOCKUP_TXID = "aa" * 32
ARK_TXID = "cc" * 32
SOLVER = "c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"
SENDER = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
SERVER = "5cbdf0646e5db4eaa398f365f2ea7a0e3d419b6c6aefb4f9f7a5b3e2b6f1d2c3"


def _sdk_refund_script():
    leaf = b"\x51\xb2\x75\x20" + bytes.fromhex(SENDER) + b"\xac"
    leaf_hash = _tagged_hash("TapLeaf", b"\xc0" + to_bytes(len(leaf)) + leaf)
    internal = __import__("coincurve").PublicKeyXOnly(_TAPROOT_UNSPENDABLE_KEY)
    internal.tweak_add(_tagged_hash("TapTweak", internal.format() + leaf_hash))
    return "5120" + internal.format().hex()


REFUND_PK_SCRIPT = _sdk_refund_script()
LOCKUP_SCRIPT = "5120" + "22" * 32
REFUND_LOCKTIME = 1_789_353_732


def _intent(**updates):
    values = {
        "payment_hash": "11" * 32,
        "amount_msat": 100_000,
        "quote_from_amount_sat": 105,
        "quote_to_amount_sat": 100,
        "max_fee_msat": 5_000,
        "refund_locktime": REFUND_LOCKTIME,
        "solver_pubkey": SOLVER,
        "sender_pubkey": SENDER,
        "server_pubkey": SERVER,
        "lockup_script": LOCKUP_SCRIPT,
        "refund_pk_script": REFUND_PK_SCRIPT,
    }
    values.update(updates)
    intent = ArkadeLightningEvidenceIntent(**values)
    if "lockup_script" not in updates:
        values["lockup_script"] = _contract_output(intent)
    return ArkadeLightningEvidenceIntent(**values)


def _vtxo(**updates):
    value = {
        "txid": LOCKUP_TXID,
        "vout": 0,
        "amount_sat": 105,
        "script": LOCKUP_SCRIPT,
        "is_spent": True,
        "spent_by": "bb" * 32,
        "arkade_txid": ARK_TXID,
    }
    value.update(updates)
    return value


def _control(leaf: bytes, sibling: bytes = b"\x33" * 32) -> bytes:
    leaf_hash = _tagged_hash("TapLeaf", b"\xc0" + to_bytes(len(leaf)) + leaf)
    root = _tagged_hash("TapBranch", min(leaf_hash, sibling) + max(leaf_hash, sibling))
    internal = __import__("coincurve").PublicKeyXOnly(_TAPROOT_UNSPENDABLE_KEY)
    internal.tweak_add(_tagged_hash("TapTweak", internal.format() + root))
    parity = b"\xc1" if internal.parity else b"\xc0"
    return parity + _TAPROOT_UNSPENDABLE_KEY + sibling


def _contract_output(intent):
    claim = _claim_leaf(intent)
    refund = bytes.fromhex(_refund_leaf_hex())
    claim_hash = _tagged_hash("TapLeaf", b"\xc0" + to_bytes(len(claim)) + claim)
    refund_hash = _tagged_hash("TapLeaf", b"\xc0" + to_bytes(len(refund)) + refund)
    root = _tagged_hash(
        "TapBranch", min(claim_hash, refund_hash) + max(claim_hash, refund_hash)
    )
    internal = __import__("coincurve").PublicKeyXOnly(_TAPROOT_UNSPENDABLE_KEY)
    internal.tweak_add(_tagged_hash("TapTweak", internal.format() + root))
    return "5120" + internal.format().hex()


def _psbt(
    *,
    preimage=None,
    refund=False,
    lockup_txid=LOCKUP_TXID,
    locktime=0,
    sequence=0xFFFFFFFF,
    output_script=None,
    tapleaf=None,
    intent=None,
):
    tx = Transaction(
        version=3,
        locktime=locktime,
        vin=[TransactionInput(bytes.fromhex(lockup_txid), 0, sequence=sequence)],
        vout=[
            TransactionOutput(
                105,
                Script(bytes.fromhex(output_script or "5120" + "44" * 32)),
            )
        ],
    )
    parsed = PSBT(tx)
    parsed.inputs[0].unknown = {}
    intent = intent or _intent()
    parsed.inputs[0].witness_utxo = TransactionOutput(
        105, Script(bytes.fromhex(intent.lockup_script))
    )
    leaf = tapleaf or (
        bytes.fromhex(_refund_leaf_hex()) if refund else _claim_leaf(intent)
    )
    sibling = bytes.fromhex(_refund_leaf_hex()) if not refund else _claim_leaf(intent)
    parsed.inputs[0].taproot_scripts[
        _control(
            leaf, _tagged_hash("TapLeaf", b"\xc0" + to_bytes(len(sibling)) + sibling)
        )
    ] = (leaf + b"\xc0")
    if preimage is not None:
        parsed.inputs[0].unknown[b"\xdecondition"] = (
            to_bytes(1) + to_bytes(len(preimage)) + preimage
        )
    if refund:
        parsed.inputs[0].final_scriptwitness = Witness([b"\x00" * 64])
    return {parsed.tx.txid().hex(): parsed.to_base64()}


def _terminal_psbt(checkpoint_psbt, intent, *, refund=False):
    checkpoint_id = next(iter(checkpoint_psbt))
    output_script = REFUND_PK_SCRIPT if refund else "5120" + "44" * 32
    tx = Transaction(
        version=3,
        vin=[TransactionInput(bytes.fromhex(checkpoint_id), 0)],
        vout=[
            TransactionOutput(105, Script(bytes.fromhex(output_script))),
            TransactionOutput(0, Script(bytes.fromhex("51024e73"))),
        ],
    )
    parsed = PSBT(tx)
    parsed.inputs[0].witness_utxo = TransactionOutput(
        105, Script(bytes.fromhex("5120" + "55" * 32))
    )
    return {parsed.tx.txid().hex(): parsed.to_base64()}


def _claim_leaf(intent):
    committed = hashlib.new("ripemd160", bytes.fromhex(intent.payment_hash)).digest()
    return (
        b"\x82\x01\x20\x88\xa9\x14"
        + committed
        + b"\x87\x69\x20"
        + bytes.fromhex(intent.solver_pubkey)
        + b"\xad\x20"
        + bytes.fromhex(intent.server_pubkey)
        + b"\xac"
    )


def _refund_leaf_hex():
    locktime = REFUND_LOCKTIME.to_bytes(4, "little")
    return (
        bytes([len(locktime)])
        + locktime
        + b"\xb1\x75\x20"
        + bytes.fromhex(SENDER)
        + b"\xad\x20"
        + bytes.fromhex(SERVER)
        + b"\xac"
    ).hex()


def test_real_open_fixture_stays_non_terminal():
    refund = REAL_FIXTURE["refund"]
    assert refund["readLockupFate"]["fate"] == "open"
    verdict = verify_arkade_lightning_terminal_evidence(
        _intent(
            payment_hash=refund["paymentHash"],
            lockup_script=refund["lockupScriptHex"],
            quote_from_amount_sat=1000,
            quote_to_amount_sat=1000,
            amount_msat=1_000_000,
            max_fee_msat=1,
        ),
        [refund["indexer"]["vtxo"]],
        {},
    )
    assert verdict.status is ArkadeLightningEvidenceStatus.PENDING


def test_missing_indexer_data_is_unknown_pending():
    verdict = verify_arkade_lightning_terminal_evidence(_intent(), [], {})
    assert verdict.status is ArkadeLightningEvidenceStatus.PENDING
    assert verdict.reason == "unknown: no lockup VTXO observed"


def test_real_claim_fixture_without_stored_psbt_stays_pending():
    claim = REAL_FIXTURE["claim"]
    vtxo = claim["indexer"]["vtxo"]
    verdict = verify_arkade_lightning_terminal_evidence(
        _intent(
            payment_hash=claim["paymentHash"],
            lockup_script=claim["lockupScriptHex"],
            quote_from_amount_sat=1000,
            quote_to_amount_sat=1000,
            amount_msat=1_000_000,
            max_fee_msat=1,
        ),
        [vtxo],
        {},
    )
    assert verdict.status is ArkadeLightningEvidenceStatus.PENDING


def test_synthetic_claim_requires_and_accepts_hashed_preimage():
    preimage = b"claim-preimage".ljust(32, b"\x00")
    intent = _intent(payment_hash=hashlib.sha256(preimage).hexdigest())
    psbts = _psbt(preimage=preimage, intent=intent)
    terminal = _terminal_psbt(psbts, intent)
    verdict = verify_arkade_lightning_terminal_evidence(
        intent,
        [
            _vtxo(
                script=intent.lockup_script,
                spent_by=next(iter(psbts)),
                arkade_txid=next(iter(terminal)),
            )
        ],
        psbts,
        terminal_psbts=terminal,
    )
    assert verdict.status is ArkadeLightningEvidenceStatus.CLAIMED
    assert verdict.ark_txid == next(iter(terminal))
    assert verdict.preimage_hash == intent.payment_hash


def test_funding_outpoint_and_terminal_txid_are_bound():
    preimage = b"claim-preimage".ljust(32, b"\x00")
    intent = _intent(
        payment_hash=hashlib.sha256(preimage).hexdigest(),
        funding_outpoint=(LOCKUP_TXID, 0),
    )
    checkpoint = _psbt(preimage=preimage, intent=intent)
    terminal = _terminal_psbt(checkpoint, intent)
    terminal_id = next(iter(terminal))
    assert (
        verify_arkade_lightning_terminal_evidence(
            intent,
            [
                _vtxo(
                    script=intent.lockup_script,
                    spent_by=next(iter(checkpoint)),
                    arkade_txid=terminal_id,
                )
            ],
            checkpoint,
            terminal_psbts={terminal_id: terminal[terminal_id]},
        ).status
        is ArkadeLightningEvidenceStatus.CLAIMED
    )
    verdict = verify_arkade_lightning_terminal_evidence(
        intent,
        [
            _vtxo(
                txid="dd" * 32,
                script=intent.lockup_script,
                spent_by=next(iter(checkpoint)),
                arkade_txid=terminal_id,
            )
        ],
        checkpoint,
        terminal_psbts=terminal,
    )
    assert verdict.status is ArkadeLightningEvidenceStatus.CONTRADICTORY


def test_synthetic_matured_refund_requires_leaf_and_return_value():
    intent = _intent()
    psbts = _psbt(refund=True, locktime=REFUND_LOCKTIME, sequence=0xFFFFFFFE)
    terminal = _terminal_psbt(psbts, intent, refund=True)
    verdict = verify_arkade_lightning_terminal_evidence(
        intent,
        [
            _vtxo(
                script=intent.lockup_script,
                spent_by=next(iter(psbts)),
                arkade_txid=next(iter(terminal)),
            )
        ],
        psbts,
        terminal_psbts=terminal,
        now=REFUND_LOCKTIME,
    )
    assert verdict.status is ArkadeLightningEvidenceStatus.REFUNDED
    assert verdict.refund_output == (0, 105, REFUND_PK_SCRIPT)


@pytest.mark.parametrize(
    "changes",
    [
        {"quote_from_amount_sat": 106},
        {"payment_hash": "22" * 32},
        {"solver_pubkey": "23" * 32},
    ],
)
def test_wrong_binding_is_contradictory(changes):
    psbts = _psbt()
    intent = _intent(**changes)
    terminal = _terminal_psbt(psbts, intent)
    verdict = verify_arkade_lightning_terminal_evidence(
        intent,
        [
            _vtxo(
                script=intent.lockup_script,
                spent_by=next(iter(psbts)),
                arkade_txid=next(iter(terminal)),
            )
        ],
        psbts,
        terminal_psbts=terminal,
    )
    assert verdict.status is ArkadeLightningEvidenceStatus.CONTRADICTORY


def test_claim_and_refund_conflict_is_contradictory():
    preimage = b"claim-preimage".ljust(32, b"\x00")
    intent = _intent(payment_hash=hashlib.sha256(preimage).hexdigest())
    claim = _psbt(preimage=preimage, intent=intent)
    claim_terminal = _terminal_psbt(claim, intent)
    refund = _psbt(
        refund=True,
        lockup_txid="dd" * 32,
        locktime=REFUND_LOCKTIME,
        sequence=0xFFFFFFFE,
    )
    refund_terminal = _terminal_psbt(refund, intent, refund=True)
    claim_id = next(iter(claim))
    refund_id = next(iter(refund))
    verdict = verify_arkade_lightning_terminal_evidence(
        intent,
        [
            _vtxo(
                script=intent.lockup_script,
                spent_by=claim_id,
                arkade_txid=next(iter(claim_terminal)),
            ),
            _vtxo(
                script=intent.lockup_script,
                txid="dd" * 32,
                spent_by=refund_id,
                arkade_txid=next(iter(claim_terminal)),
            ),
        ],
        {**claim, **refund},
        terminal_psbts={**claim_terminal, **refund_terminal},
        now=REFUND_LOCKTIME,
    )
    assert verdict.status is ArkadeLightningEvidenceStatus.CONTRADICTORY


def test_malformed_psbt_is_contradictory():
    checkpoint_id = "bb" * 32
    verdict = verify_arkade_lightning_terminal_evidence(
        _intent(),
        [_vtxo(spent_by=checkpoint_id, arkade_txid=ARK_TXID)],
        {checkpoint_id: "not-base64"},
        terminal_psbts={ARK_TXID: "not-base64"},
    )
    assert verdict.status is ArkadeLightningEvidenceStatus.CONTRADICTORY
