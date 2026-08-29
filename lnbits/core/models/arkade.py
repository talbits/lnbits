from datetime import datetime, timezone
from typing import Literal

from pydantic import BaseModel, Field

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


class ArkadeReconciliation(BaseModel):
    account_id: str
    state: ArkadeReconciliationState = "ok"
    last_error: str | None = None
    observed_at: datetime | None = None
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
