"""Pure verification of public Arkade Lightning terminal evidence."""

import base64
import hashlib
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import Enum
from io import BytesIO
from types import MappingProxyType
from typing import cast

from coincurve import PublicKeyXOnly
from embit.compact import read_from as read_compact
from embit.psbt import PSBT

from .arkade import _TAPROOT_UNSPENDABLE_KEY, _tagged_hash

_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_SCRIPT = re.compile(r"^[0-9a-fA-F]+$")
_MAX_PSBT_BYTES = 4 * 1024 * 1024
_CONDITION_KEY = b"\xdecondition"


class ArkadeLightningEvidenceStatus(str, Enum):
    PENDING = "pending"
    CLAIMED = "claimed"
    REFUNDED = "refunded"
    CONTRADICTORY = "contradictory"


@dataclass(frozen=True)
class ArkadeLightningEvidenceIntent:
    """Immutable public contract binding needed by the verifier.

    The persisted outgoing model currently lacks the script/key material needed
    to verify a VHTLC leaf.  The integration slice must construct this value
    from that row plus its original public quote/contract binding.
    """

    payment_hash: str
    amount_msat: int
    quote_from_amount_sat: int
    quote_to_amount_sat: int
    max_fee_msat: int
    refund_locktime: int
    solver_pubkey: str
    sender_pubkey: str
    server_pubkey: str
    lockup_script: str
    refund_pk_script: str
    funding_outpoint: tuple[str, int] | None = None


@dataclass(frozen=True)
class ArkadeCheckpointPSBT:
    checkpoint_txid: str
    psbt_base64: str


@dataclass(frozen=True)
class ArkadeLightningEvidenceVerdict:
    status: ArkadeLightningEvidenceStatus
    ark_txid: str | None = None
    preimage_hash: str | None = None
    reason: str | None = None
    refund_output: tuple[int, int, str] | None = None


def verify_arkade_lightning_terminal_evidence(  # noqa: C901
    intent: ArkadeLightningEvidenceIntent,
    indexer_vtxos: Sequence[object],
    checkpoint_psbts: (
        Mapping[str, str] | Sequence[ArkadeCheckpointPSBT] | Sequence[str]
    ),
    *,
    terminal_psbts: Mapping[str, str] | None = None,
    now: int | None = None,
) -> ArkadeLightningEvidenceVerdict:
    """Classify a lockup using only public indexer VTXOs and virtual tx PSBTs."""
    try:
        _validate_intent(intent)
        vtxos = [_vtxo(value, intent.lockup_script) for value in indexer_vtxos]
    except (AttributeError, TypeError, ValueError, KeyError):
        return _contradictory("malformed indexer or intent data")

    if not vtxos:
        return _pending("unknown: no lockup VTXO observed")
    if len(vtxos) != len({(v.txid, v.vout) for v in vtxos}):
        return _contradictory("duplicate lockup outpoint")
    if any(v.script.lower() != intent.lockup_script.lower() for v in vtxos):
        return _contradictory("lockup script mismatch")
    if any(v.amount_sat != intent.quote_from_amount_sat for v in vtxos):
        return _contradictory("lockup amount mismatch")
    if intent.funding_outpoint is not None and any(
        (v.txid, v.vout) != intent.funding_outpoint for v in vtxos
    ):
        return _contradictory("lockup funding outpoint mismatch")
    if any(v.is_swept or v.is_unrolled for v in vtxos):
        return _contradictory("lockup was swept or unrolled")

    if any(not v.is_spent and not v.spent_by for v in vtxos):
        return _pending("lockup remains open")
    if any(not v.spent_by or not v.ark_txid for v in vtxos):
        return _pending("spent lockup has not been fully indexed")
    if len({v.ark_txid for v in vtxos}) != 1:
        return _contradictory("conflicting terminal Ark txids")
    checkpoint_ids = [cast(str, v.spent_by) for v in vtxos]
    if len(set(checkpoint_ids)) != len(vtxos):
        return _contradictory("duplicate checkpoint spend ids")

    try:
        psbts = _psbt_map(checkpoint_psbts, checkpoint_ids)
    except (TypeError, ValueError, KeyError):
        return _contradictory("malformed checkpoint evidence")
    if psbts is None:
        return _pending("checkpoint PSBT not yet observed")

    terminal_ids = [cast(str, v.ark_txid) for v in vtxos]
    try:
        terminal_map = _psbt_map(terminal_psbts or {}, terminal_ids)
    except (TypeError, ValueError, KeyError):
        return _contradictory("malformed terminal evidence")
    if terminal_map is None:
        return _pending("terminal Ark PSBT not yet observed")
    try:
        terminal_psbt = _parse_psbt(terminal_map[terminal_ids[0]])
        if not _valid_terminal_transaction(
            terminal_psbt, checkpoint_ids, terminal_ids[0], intent
        ):
            return _contradictory("terminal Ark transaction mismatch")
    except Exception:
        return _contradictory("malformed terminal Ark PSBT")

    try:
        spends = [
            _inspect_spend(intent, vtxo, psbts[checkpoint_id], terminal_psbt, now)
            for vtxo, checkpoint_id in zip(vtxos, checkpoint_ids, strict=True)
        ]
    except Exception:
        return _contradictory("malformed checkpoint PSBT")

    claims = [spend for spend in spends if spend.claim]
    refunds = [spend for spend in spends if spend.refund]
    invalid = [spend for spend in spends if not spend.claim and not spend.refund]
    if invalid:
        return _contradictory(invalid[0].reason)
    if claims and refunds:
        return _contradictory("claim and refund evidence conflict")
    if len(claims) > 1 or len(refunds) > 1:
        return _contradictory("multiple terminal spends")

    ark_txid = next(iter({v.ark_txid for v in vtxos}))
    if claims:
        return ArkadeLightningEvidenceVerdict(
            ArkadeLightningEvidenceStatus.CLAIMED,
            ark_txid=ark_txid,
            preimage_hash=intent.payment_hash,
            reason="valid claim preimage in public checkpoint evidence",
        )
    output = refunds[0].refund_output
    return ArkadeLightningEvidenceVerdict(
        ArkadeLightningEvidenceStatus.REFUNDED,
        ark_txid=ark_txid,
        refund_output=output,
        reason="valid matured refund leaf in public Ark evidence",
    )


@dataclass(frozen=True)
class _Vtxo:
    txid: str
    vout: int
    amount_sat: int
    script: str
    is_spent: bool
    spent_by: str | None
    ark_txid: str | None
    is_swept: bool
    is_unrolled: bool


@dataclass(frozen=True)
class _Spend:
    claim: bool
    refund: bool
    reason: str
    refund_output: tuple[int, int, str] | None = None


def _validate_intent(intent: ArkadeLightningEvidenceIntent) -> None:
    for field in (
        "payment_hash",
        "solver_pubkey",
        "sender_pubkey",
        "server_pubkey",
    ):
        value = getattr(intent, field)
        if not isinstance(value, str) or not _HEX64.fullmatch(value):
            raise ValueError(f"invalid {field}")
    if not isinstance(intent.lockup_script, str) or not _valid_script(
        intent.lockup_script
    ):
        raise ValueError("invalid lockup script")
    if not isinstance(intent.refund_pk_script, str) or not _valid_script(
        intent.refund_pk_script
    ):
        raise ValueError("invalid refund script")
    if len(
        intent.refund_pk_script
    ) != 68 or not intent.refund_pk_script.lower().startswith("5120"):
        raise ValueError("invalid refund destination script")
    if intent.funding_outpoint is not None:
        txid, vout = intent.funding_outpoint
        if not _HEX64.fullmatch(txid) or not isinstance(vout, int) or vout < 0:
            raise ValueError("invalid funding outpoint")
    if (
        intent.amount_msat <= 0
        or intent.amount_msat % 1000
        or intent.quote_from_amount_sat < intent.quote_to_amount_sat
        or intent.quote_to_amount_sat * 1000 != intent.amount_msat
        or intent.max_fee_msat <= 0
        or (intent.quote_from_amount_sat - intent.quote_to_amount_sat) * 1000
        > intent.max_fee_msat
        or intent.refund_locktime <= 0
    ):
        raise ValueError("invalid quote binding")


def _vtxo(value: object, expected_script: str) -> _Vtxo:  # noqa: C901
    def get(*names: str, default: object = None) -> object:
        for name in names:
            if isinstance(value, Mapping) and name in value:
                return value[name]
            if hasattr(value, name):
                return getattr(value, name)
        return default

    txid = get("txid")
    vout = get("vout")
    if txid is None or vout is None:
        outpoint = get("outpoint")
        if not isinstance(outpoint, str):
            raise ValueError("missing outpoint")
        match = re.fullmatch(r"([0-9a-f]{64}):(?:vout)?([0-9]+)", outpoint)
        if not match:
            raise ValueError("invalid outpoint")
        txid, vout = match.groups()
        vout = int(vout)
    script = get("script", "pk_script", "lockupScriptHex", default=expected_script)
    amount = get("amount_sat", "value", "valueSats")
    spent_by = get("spent_by", "spentBy", "spentByCheckpointTxid")
    ark_txid = get("arkade_txid", "arkTxId", "arkTxid")
    is_spent = get("is_spent", "isSpent", default=bool(spent_by))
    if not isinstance(txid, str) or not _HEX64.fullmatch(txid):
        raise ValueError("invalid VTXO txid")
    if not isinstance(vout, int) or vout < 0:
        raise ValueError("invalid VTXO vout")
    if not isinstance(amount, int) or amount <= 0:
        raise ValueError("invalid VTXO amount")
    if not isinstance(script, str) or not _valid_script(script):
        raise ValueError("invalid VTXO script")
    for identifier in (spent_by, ark_txid):
        if identifier is not None and (
            not isinstance(identifier, str) or not _HEX64.fullmatch(identifier)
        ):
            raise ValueError("invalid terminal id")
    spent_by = spent_by if isinstance(spent_by, str) else None
    ark_txid = ark_txid if isinstance(ark_txid, str) else None
    return _Vtxo(
        txid,
        vout,
        amount,
        script,
        bool(is_spent),
        spent_by,
        ark_txid,
        bool(get("is_swept", "isSwept", default=False)),
        bool(get("is_unrolled", "isUnrolled", default=False)),
    )


def _psbt_map(
    values: Mapping[str, str] | Sequence[ArkadeCheckpointPSBT] | Sequence[str],
    checkpoint_ids: Sequence[str],
) -> Mapping[str, str] | None:
    if isinstance(values, Mapping):
        if any(not isinstance(k, str) or not _HEX64.fullmatch(k) for k in values):
            raise ValueError("invalid checkpoint id")
        result = dict(values)
    elif all(isinstance(item, ArkadeCheckpointPSBT) for item in values):
        psbt_items = cast(Sequence[ArkadeCheckpointPSBT], values)
        keys = [item.checkpoint_txid for item in psbt_items]
        if len(keys) != len(set(keys)):
            raise ValueError("duplicate checkpoint PSBT")
        result = {item.checkpoint_txid: item.psbt_base64 for item in psbt_items}
    elif all(isinstance(item, str) for item in values):
        text_items = cast(Sequence[str], values)
        if len(text_items) != len(checkpoint_ids):
            raise ValueError("checkpoint PSBT count mismatch")
        result = dict(zip(checkpoint_ids, text_items, strict=True))
    else:
        raise TypeError("unsupported checkpoint PSBT container")
    if len(result) != len(values):
        raise ValueError("duplicate checkpoint PSBT")
    expected = set(checkpoint_ids)
    if set(result) - expected:
        raise ValueError("checkpoint evidence contains an extra spend")
    if any(identifier not in result for identifier in expected):
        return None
    return MappingProxyType(result)


def _parse_psbt(psbt_base64: str) -> PSBT:
    if not isinstance(psbt_base64, str):
        raise TypeError("PSBT must be base64")
    raw = base64.b64decode(psbt_base64, validate=True)
    if not 1 <= len(raw) <= _MAX_PSBT_BYTES:
        raise ValueError("invalid PSBT size")
    return PSBT.parse(raw)


def _valid_terminal_transaction(
    psbt: PSBT,
    checkpoint_ids: Sequence[str],
    terminal_id: str,
    intent: ArkadeLightningEvidenceIntent,
) -> bool:
    if psbt.tx.txid().hex() != terminal_id:
        return False
    expected = {(checkpoint_id, 0) for checkpoint_id in checkpoint_ids}
    actual = {(txin.txid.hex(), txin.vout) for txin in psbt.tx.vin}
    if len(psbt.tx.vin) != len(expected) or actual != expected:
        return False
    try:
        for index in range(len(psbt.tx.vin)):
            utxo = psbt.utxo(index)
            if utxo is None or utxo.value != intent.quote_from_amount_sat:
                return False
    except (IndexError, ValueError, TypeError):
        return False
    return _nonzero_output_total(psbt) == intent.quote_from_amount_sat


def _inspect_spend(  # noqa: C901
    intent: ArkadeLightningEvidenceIntent,
    vtxo: _Vtxo,
    psbt_base64: str,
    terminal_psbt: PSBT,
    now: int | None,
) -> _Spend:
    if not isinstance(psbt_base64, str):
        raise TypeError("PSBT must be base64")
    psbt = _parse_psbt(psbt_base64)
    if psbt.tx.txid().hex() != vtxo.spent_by:
        return _Spend(False, False, "checkpoint txid mismatch")
    matches = [
        index
        for index, txin in enumerate(psbt.tx.vin)
        if txin.txid.hex() == vtxo.txid and txin.vout == vtxo.vout
    ]
    if len(matches) != 1:
        return _Spend(False, False, "lockup outpoint missing or duplicated")
    input_index = matches[0]
    input_scope = psbt.inputs[input_index]
    utxo = psbt.utxo(input_index)
    if utxo is None:
        return _Spend(False, False, "lockup input unavailable")
    if utxo.value != intent.quote_from_amount_sat or (
        utxo.script_pubkey.data.hex().lower() != intent.lockup_script.lower()
    ):
        return _Spend(False, False, "lockup input amount or script mismatch")

    leaves = [
        (control, value[:-1])
        for control, value in input_scope.taproot_scripts.items()
        if len(value) >= 1 and len(control) >= 1 and value[-1] == control[0] & 0xFE
    ]
    claim_leaf = _claim_leaf(intent)
    refund_leaf = _refund_leaf(intent)
    valid_claim_membership = any(
        script == claim_leaf
        and _valid_membership(intent.lockup_script, control, script)
        for control, script in leaves
    )
    valid_refund_membership = any(
        script == refund_leaf
        and _valid_membership(intent.lockup_script, control, script)
        for control, script in leaves
    )
    condition_items = _condition_items(input_scope.unknown)
    final_items = list(getattr(input_scope.final_scriptwitness, "items", []))
    has_claim_preimage = any(
        len(item) == 32 and hashlib.sha256(item).hexdigest() == intent.payment_hash
        for item in [*condition_items, *final_items]
    )
    if has_claim_preimage and not valid_claim_membership:
        return _Spend(False, False, "claim preimage lacks valid lockup leaf membership")
    claim = has_claim_preimage and valid_claim_membership
    claim = claim and _nonzero_output_total(psbt) == intent.quote_from_amount_sat
    refund_output = _valid_refund_outputs(terminal_psbt, intent)
    refund = (
        valid_refund_membership
        and _valid_refund_timelock(psbt, input_index, intent, now)
        and refund_output is not None
    )
    if has_claim_preimage and not claim:
        return _Spend(False, False, "claim value does not bind to quote")
    if valid_refund_membership and not refund:
        return _Spend(
            False,
            False,
            "refund is immature or does not return the lockup value",
        )
    if claim and refund:
        return _Spend(False, False, "claim and refund branches conflict")
    if claim:
        return _Spend(True, False, "")
    if refund:
        return _Spend(False, True, "", refund_output)
    return _Spend(False, False, "spend is neither a valid claim nor a valid refund")


def _condition_items(unknown: Mapping[bytes, bytes]) -> list[bytes]:
    items: list[bytes] = []
    for key, value in unknown.items():
        if key != _CONDITION_KEY:
            continue
        stream = BytesIO(value)
        count = read_compact(stream)
        for _ in range(count):
            length = read_compact(stream)
            item = stream.read(length)
            if len(item) != length:
                raise ValueError("truncated condition witness")
            items.append(item)
        if stream.read(1):
            raise ValueError("trailing condition witness data")
    return items


def _valid_membership(lockup_script: str, control: bytes, leaf: bytes) -> bool:
    if len(control) < 33 or (len(control) - 33) % 32 or len(control) > 33 + 32 * 128:
        return False
    if control[0] & 0xFE != 0xC0 or control[1:33] != _TAPROOT_UNSPENDABLE_KEY:
        return False
    output = bytes.fromhex(lockup_script)
    if len(output) != 34 or output[:2] != b"\x51\x20":
        return False
    leaf_hash = _tagged_hash(
        "TapLeaf", bytes([control[0] & 0xFE]) + _compact_size(len(leaf)) + leaf
    )
    for sibling in (
        control[index : index + 32] for index in range(33, len(control), 32)
    ):
        leaf_hash = _tagged_hash(
            "TapBranch",
            min(leaf_hash, sibling) + max(leaf_hash, sibling),
        )
    try:
        internal = PublicKeyXOnly(control[1:33])
        internal.tweak_add(_tagged_hash("TapTweak", internal.format() + leaf_hash))
    except (TypeError, ValueError):
        return False
    return internal.format() == output[2:] and internal.parity == bool(control[0] & 1)


def _valid_refund_timelock(
    psbt: PSBT, input_index: int, intent: ArkadeLightningEvidenceIntent, now: int | None
) -> bool:
    if (
        now is None
        or now < intent.refund_locktime
        or (psbt.tx.locktime < intent.refund_locktime)
    ):
        return False
    # The SDK uses Unix-seconds CLTV values; the transaction must use the same
    # BIP65 type and a non-final input sequence.
    if intent.refund_locktime < 500_000_000 or psbt.tx.locktime < 500_000_000:
        return False
    return psbt.tx.vin[input_index].sequence != 0xFFFFFFFF


def _valid_refund_outputs(
    psbt: PSBT, intent: ArkadeLightningEvidenceIntent
) -> tuple[int, int, str] | None:
    outputs = psbt.tx.vout
    returned = [
        (index, output.value)
        for index, output in enumerate(outputs)
        if output.script_pubkey.data.hex().lower() == intent.refund_pk_script.lower()
    ]
    nonzero = sum(output.value for output in outputs)
    if (
        len(returned) != 1
        or returned[0][1] != intent.quote_from_amount_sat
        or (nonzero != intent.quote_from_amount_sat)
    ):
        return None
    return returned[0][0], returned[0][1], intent.refund_pk_script.lower()


def _nonzero_output_total(psbt: PSBT) -> int:
    return sum(output.value for output in psbt.tx.vout)


def _claim_leaf(intent: ArkadeLightningEvidenceIntent) -> bytes:
    committed = hashlib.new(
        "ripemd160",
        bytes.fromhex(intent.payment_hash),
    ).digest()
    return (
        b"\x82\x01\x20\x88\xa9\x14"
        + committed
        + b"\x87\x69\x20"
        + bytes.fromhex(intent.solver_pubkey)
        + b"\xad\x20"
        + bytes.fromhex(intent.server_pubkey)
        + b"\xac"
    )


def _refund_leaf(intent: ArkadeLightningEvidenceIntent) -> bytes:
    locktime = intent.refund_locktime.to_bytes(
        max(1, (intent.refund_locktime.bit_length() + 7) // 8), "little"
    )
    if locktime[-1] & 0x80:
        locktime += b"\x00"
    return (
        bytes([len(locktime)])
        + locktime
        + b"\xb1\x75\x20"
        + bytes.fromhex(intent.sender_pubkey)
        + b"\xad\x20"
        + bytes.fromhex(intent.server_pubkey)
        + b"\xac"
    )


def _compact_size(value: int) -> bytes:
    if value < 0xFD:
        return bytes([value])
    if value <= 0xFFFF:
        return b"\xfd" + value.to_bytes(2, "little")
    if value <= 0xFFFFFFFF:
        return b"\xfe" + value.to_bytes(4, "little")
    return b"\xff" + value.to_bytes(8, "little")


def _valid_script(value: str) -> bool:
    return bool(value) and len(value) % 2 == 0 and bool(_SCRIPT.fullmatch(value))


def _pending(reason: str) -> ArkadeLightningEvidenceVerdict:
    return ArkadeLightningEvidenceVerdict(
        ArkadeLightningEvidenceStatus.PENDING,
        reason=reason,
    )


def _contradictory(reason: str) -> ArkadeLightningEvidenceVerdict:
    return ArkadeLightningEvidenceVerdict(
        ArkadeLightningEvidenceStatus.CONTRADICTORY, reason=reason
    )


__all__ = [
    "ArkadeCheckpointPSBT",
    "ArkadeLightningEvidenceIntent",
    "ArkadeLightningEvidenceStatus",
    "ArkadeLightningEvidenceVerdict",
    "verify_arkade_lightning_terminal_evidence",
]
