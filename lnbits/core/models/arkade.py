from datetime import datetime, timezone
from typing import Literal

from pydantic import BaseModel, Field, root_validator

ArkadeBindingState = Literal["pending", "ready"]
ArkadeReceiveState = Literal[
    "pending", "acknowledged", "settled", "reconciliation_required"
]
ArkadeReconciliationState = Literal["ok", "reconciliation_required"]


class ArkadeAccountBinding(BaseModel):
    account_id: str
    state: ArkadeBindingState = "pending"
    enrollment_id: str
    idempotency_key: str | None = None
    challenge_nonce: str | None = None
    challenge_expires_at: datetime | None = None
    network: str
    server_url: str
    server_pubkey: str
    identity_xonly_pubkey: str | None = None
    identity_descriptor: str | None = Field(default=None, max_length=512)
    backup_acknowledged_at: datetime | None = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    ready_at: datetime | None = None


class ArkadeEnrollmentChallenge(BaseModel):
    account_id: str
    state: Literal["pending"]
    enrollment_id: str
    idempotency_key: str
    nonce: str
    expires_at: int
    network: str
    server_url: str
    server_pubkey: str
    identity_kind: Literal["mnemonic_hd"] = "mnemonic_hd"
    action: Literal["lnbits-arkade-enrollment-v1"] = "lnbits-arkade-enrollment-v1"


class ArkadeEnrollmentCompletion(BaseModel):
    enrollment_id: str = Field(regex=r"^[0-9a-f]{32}$")
    idempotency_key: str = Field(regex=r"^[0-9a-f]{32}$")
    identity_xonly_pubkey: str = Field(regex=r"^[0-9a-f]{64}$")
    identity_descriptor: str = Field(min_length=1, max_length=512)
    signature: str = Field(regex=r"^[0-9a-f]{128}$")


class ArkadeEnrollmentBindingResponse(BaseModel):
    account_id: str
    state: ArkadeBindingState
    enrollment_id: str
    idempotency_key: str
    network: str
    server_url: str
    server_pubkey: str
    identity_xonly_pubkey: str | None = None
    identity_descriptor: str | None = Field(default=None, max_length=512)
    backup_acknowledged_at: datetime | None = None
    created_at: datetime
    updated_at: datetime
    ready_at: datetime | None = None


class ArkadeReceiveRequest(BaseModel):
    account_id: str
    wallet_id: str
    native_request_id: str
    idempotency_key: str
    amount_sat: int = Field(ge=1, le=2_100_000_000_000_000)
    index: int | None = Field(default=None, ge=0, le=2_147_483_647)
    address: str | None = None
    script: str | None = None
    child_xonly_pubkey: str | None = None
    network: str
    server_url: str
    server_pubkey: str
    expires_at: datetime
    state: ArkadeReceiveState = "pending"
    settled_at: datetime | None = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class ArkadeReceiveAcknowledgement(BaseModel):
    native_request_id: str = Field(regex=r"^[0-9a-f]{32}$")
    account_id: str = Field(regex=r"^[0-9a-f]{32}$")
    wallet_id: str = Field(regex=r"^[0-9a-f]{32}$")
    idempotency_key: str = Field(regex=r"^[0-9a-f]{32}$")
    amount_sat: int = Field(ge=1, le=2_100_000_000_000_000)
    index: int = Field(ge=0, le=2_147_483_647)
    address: str = Field(min_length=1, max_length=512)
    script: str = Field(regex=r"^[0-9a-fA-F]+$", min_length=2, max_length=4096)
    child_xonly_pubkey: str = Field(regex=r"^[0-9a-f]{64}$")
    network: str = Field(regex=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,31}$")
    server_url: str = Field(min_length=1, max_length=512)
    server_pubkey: str = Field(regex=r"^[0-9a-f]{64}$")
    expires_at: int = Field(ge=0)
    signature: str = Field(regex=r"^[0-9a-f]{128}$")
    exit_tapleaf: str = Field(regex=r"^[0-9a-f]{76,86}$")
    exit_control_block: str = Field(regex=r"^[0-9a-f]{130}$")


class ArkadeIndexerVtxo(BaseModel):
    txid: str = Field(regex=r"^[0-9a-f]{64}$")
    vout: int = Field(ge=0, le=4_294_967_295)
    amount_sat: int = Field(ge=1, le=2_100_000_000_000_000)
    script: str = Field(regex=r"^[0-9a-fA-F]+$", min_length=2, max_length=4096)
    is_preconfirmed: bool = False
    is_spent: bool = False
    is_swept: bool = False
    spent_by: str | None = None
    settled_by: str | None = None
    arkade_txid: str | None = None
    is_unrolled: bool = False
    created_at: datetime | None = None
    expires_at: datetime | None = None
    expires_at_height: int | None = None
    commitment_txids: list[str] = Field(default_factory=list)


class ArkadeReconciliation(BaseModel):
    account_id: str
    state: ArkadeReconciliationState = "ok"
    last_error: str | None = None
    observed_at: datetime | None = None
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


ArkadeOutgoingStatus = Literal[
    "reserved",
    "quote_ready",
    "submitted",
    "settled",
    "refunded",
    "failed",
    "released",
    "disputed",
]
ArkadeOutgoingEvidenceStatus = Literal["verified", "pending", "contradictory"]
ArkadeOutgoingDestinationKind = Literal["arkade_address", "lightning"]


class ArkadeLightningTerminalEvent(BaseModel):
    event_id: str = Field(regex=r"^[0-9a-f]{32}$")
    terminal_state: Literal["settled", "refunded", "failed", "disputed"]
    payment_payload: str
    attempts: int = Field(ge=0)
    next_attempt_at: datetime
    lease_token: str | None = None
    lease_until: datetime | None = None
    listeners_delivered_at: datetime | None = None
    webhook_delivered_at: datetime | None = None
    created_at: datetime


class ArkadeLightningQuoteInput(BaseModel):
    """Unfunded browser quote and public lockup binding."""

    bolt11: str = Field(min_length=1, max_length=1023)
    payment_hash: str = Field(regex=r"^[0-9a-f]{64}$")
    amount_msat: int | None = Field(default=None, gt=0, multiple_of=1000)
    max_fee_msat: int = Field(gt=0)
    quote_pair: str = Field(min_length=1, max_length=128)
    quote_from_amount_sat: int = Field(gt=0, le=2_100_000_000_000_000)
    quote_to_amount_sat: int = Field(gt=0, le=2_100_000_000_000_000)
    quote_valid_until: datetime
    refund_locktime: int = Field(gt=0)
    solver_pubkey: str = Field(regex=r"^[0-9a-f]{64}$")
    swap_rfq_id: str = Field(min_length=1, max_length=512)
    lockup_address: str = Field(regex=r"^\S+$", min_length=1, max_length=1023)

    class Config:
        extra = "forbid"


class ArkadeLightningFundingEvidence(BaseModel):
    """Public evidence that the browser funded the reserved Lightning lockup."""

    ark_txid: str = Field(regex=r"^[0-9a-f]{64}$")
    lockup_address: str = Field(regex=r"^\S+$", min_length=1, max_length=1023)
    swap_rfq_id: str = Field(min_length=1, max_length=512)
    solver_pubkey: str = Field(regex=r"^[0-9a-f]{64}$")
    sender_pubkey: str | None = Field(default=None, regex=r"^[0-9a-f]{64}$")
    refund_pk_script: str | None = Field(
        default=None, regex=r"^[0-9a-fA-F]+$", min_length=2, max_length=4096
    )

    class Config:
        extra = "forbid"


class ArkadeLightningFailureReport(BaseModel):
    """Browser-observed terminal claim failure for a funded Lightning swap."""

    reason: str = Field(min_length=1, max_length=200, regex=r"^[A-Za-z0-9_.:\- ]+$")

    class Config:
        extra = "forbid"


class ArkadeReconciliationResolveRequest(BaseModel):
    """Operator request to clear a sticky account reconciliation flag."""

    account_id: str = Field(min_length=1, max_length=64)
    reason: str = Field(min_length=3, max_length=200, regex=r"^[A-Za-z0-9_.:\- ]+$")

    class Config:
        extra = "forbid"


class ArkadeReconciliationResolveResponse(BaseModel):
    account_id: str
    previous_state: ArkadeReconciliationState
    state: ArkadeReconciliationState
    last_error: str | None = None


class ArkadeOutgoingIntent(BaseModel):
    intent_id: str = Field(regex=r"^[0-9a-f]{32}$")
    account_id: str
    wallet_id: str
    amount_msat: int = Field(gt=0, multiple_of=1000)
    max_fee_msat: int = Field(default=0, ge=0)
    destination: str = Field(min_length=1, max_length=1023)
    bolt11: str | None = Field(default=None, min_length=1, max_length=1023)
    payment_hash: str | None = Field(default=None, regex=r"^[0-9a-f]{64}$")
    quote_pair: str | None = Field(default=None, min_length=1, max_length=128)
    quote_from_amount_sat: int | None = Field(
        default=None, gt=0, le=2_100_000_000_000_000
    )
    quote_to_amount_sat: int | None = Field(
        default=None, gt=0, le=2_100_000_000_000_000
    )
    quote_valid_until: datetime | None = None
    refund_locktime: int | None = Field(default=None, gt=0)
    solver_pubkey: str | None = Field(default=None, regex=r"^[0-9a-f]{64}$")
    swap_rfq_id: str | None = Field(default=None, min_length=1, max_length=512)
    lockup_address: str | None = Field(
        default=None, regex=r"^\S+$", min_length=1, max_length=1023
    )
    sender_pubkey: str | None = Field(default=None, regex=r"^[0-9a-f]{64}$")
    refund_pk_script: str | None = Field(
        default=None, regex=r"^[0-9a-fA-F]+$", min_length=2, max_length=4096
    )
    settlement_ark_txid: str | None = Field(default=None, regex=r"^[0-9a-f]{64}$")
    refund_ark_txid: str | None = Field(default=None, regex=r"^[0-9a-f]{64}$")
    destination_script: str | None = None
    change_index: int | None = Field(default=None, ge=0, le=2_147_483_647)
    change_script: str | None = None
    change_amount_sat: int | None = Field(default=None, gt=0, le=2_100_000_000_000_000)
    destination_kind: ArkadeOutgoingDestinationKind = "arkade_address"
    status: ArkadeOutgoingStatus = "reserved"
    arkade_txid: str | None = Field(default=None, regex=r"^[0-9a-f]{64}$")
    actual_fee_msat: int | None = Field(default=None, ge=0)
    expires_at: datetime
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    reserved_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    submitted_at: datetime | None = None
    settled_at: datetime | None = None
    failed_at: datetime | None = None
    failure_reason: str | None = Field(default=None, min_length=1, max_length=200)
    released_at: datetime | None = None
    disputed_at: datetime | None = None

    @root_validator
    def validate_expiry(cls, values):
        expires_at = values.get("expires_at")
        reserved_at = values.get("reserved_at")
        if expires_at and reserved_at and expires_at <= reserved_at:
            raise ValueError("Arkade outgoing intent must expire after reservation")
        return values

    @root_validator
    def validate_fee_kind(cls, values):
        destination_kind = values.get("destination_kind")
        max_fee_msat = values.get("max_fee_msat")
        if destination_kind == "arkade_address" and max_fee_msat != 0:
            raise ValueError("Arkade address intents must have zero fee")
        if destination_kind == "arkade_address" and values.get(
            "actual_fee_msat"
        ) not in (None, 0):
            raise ValueError("Arkade address intents must have zero actual fee")
        if destination_kind == "lightning" and (
            max_fee_msat is None or max_fee_msat <= 0
        ):
            raise ValueError("Lightning intents must have a positive fee cap")
        return values


class ArkadeOutgoingIntentInput(BaseModel):
    intent_id: str = Field(regex=r"^[0-9a-f]{32}$")
    txid: str = Field(regex=r"^[0-9a-f]{64}$")
    vout: int = Field(ge=0, le=4_294_967_295)
    amount_sat: int = Field(gt=0, le=2_100_000_000_000_000)
    claimed_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class ArkadeOutgoingSelectedInput(BaseModel):
    txid: str = Field(regex=r"^[0-9a-f]{64}$")
    vout: int = Field(ge=0, le=4_294_967_295)
    amount_sat: int = Field(gt=0, le=2_100_000_000_000_000)

    class Config:
        extra = "forbid"


class ArkadeOutgoingEvidenceResult(BaseModel):
    status: ArkadeOutgoingEvidenceStatus
    arkade_txid: str | None = Field(default=None, regex=r"^[0-9a-f]{64}$")
    code: str | None = None


class ArkadeOutgoingChangeCommitment(BaseModel):
    index: int = Field(ge=0, le=2_147_483_647)
    address: str = Field(min_length=1, max_length=1023)
    script: str = Field(regex=r"^[0-9a-fA-F]+$", min_length=2, max_length=4096)
    child_xonly_pubkey: str = Field(regex=r"^[0-9a-f]{64}$")
    amount_sat: int = Field(gt=0, le=2_100_000_000_000_000)
    exit_tapleaf: str = Field(regex=r"^[0-9a-f]{76,86}$")
    exit_control_block: str = Field(regex=r"^[0-9a-f]{130}$")

    class Config:
        extra = "forbid"


class ArkadeOutgoingAuthorizeRequest(BaseModel):
    inputs: list[ArkadeOutgoingSelectedInput] = Field(..., min_items=1, max_items=100)
    destination_script: str = Field(
        regex=r"^[0-9a-fA-F]+$", min_length=2, max_length=4096
    )
    change: ArkadeOutgoingChangeCommitment | None = None

    class Config:
        extra = "forbid"


class ArkadeMaintenancePlan(BaseModel):
    operation_id: str = Field(regex=r"^[0-9a-f]{32}$")
    inputs: list[ArkadeOutgoingSelectedInput] = Field(..., min_items=1, max_items=100)
    output: ArkadeOutgoingChangeCommitment
    signature: str = Field(regex=r"^[0-9a-f]{128}$")

    class Config:
        extra = "forbid"


class ArkadeBackingStatus(BaseModel):
    ledger_msat: int
    spendable_sat: int
    recoverable_sat: int
    expiring_sat: int
    state: ArkadeReconciliationState
    maintenance: ArkadeMaintenancePlan | None = None
    maintenance_inputs: list[ArkadeOutgoingSelectedInput] = Field(default_factory=list)


class ArkadeOutgoingIntentResponse(BaseModel):
    action: Literal["lnbits-arkade-outgoing-v1"] = "lnbits-arkade-outgoing-v1"
    version: Literal[1] = 1
    intent_id: str
    account_id: str
    wallet_id: str
    amount_msat: int
    max_fee_msat: int = Field(default=0, ge=0)
    destination: str
    bolt11: str | None = Field(default=None, min_length=1, max_length=1023)
    payment_hash: str | None = Field(default=None, regex=r"^[0-9a-f]{64}$")
    quote_pair: str | None = Field(default=None, min_length=1, max_length=128)
    quote_from_amount_sat: int | None = Field(
        default=None, gt=0, le=2_100_000_000_000_000
    )
    quote_to_amount_sat: int | None = Field(
        default=None, gt=0, le=2_100_000_000_000_000
    )
    quote_valid_until: datetime | None = None
    refund_locktime: int | None = Field(default=None, gt=0)
    solver_pubkey: str | None = Field(default=None, regex=r"^[0-9a-f]{64}$")
    swap_rfq_id: str | None = Field(default=None, min_length=1, max_length=512)
    lockup_address: str | None = Field(
        default=None, regex=r"^\S+$", min_length=1, max_length=1023
    )
    arkade_txid: str | None = Field(default=None, regex=r"^[0-9a-f]{64}$")
    destination_script: str | None = None
    destination_kind: ArkadeOutgoingDestinationKind = "arkade_address"
    status: ArkadeOutgoingStatus
    expires_at: datetime
    network: str
    server_url: str
    server_pubkey: str
    inputs: list[ArkadeOutgoingIntentInput]
    change_index: int | None = None
    change_script: str | None = None
    change_amount_sat: int | None = None
    failed_at: datetime | None = None
    failure_reason: str | None = Field(default=None, min_length=1, max_length=200)
