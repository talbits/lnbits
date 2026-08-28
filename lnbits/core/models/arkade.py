from datetime import datetime, timezone
from typing import Literal

from pydantic import BaseModel, Field

ArkadeBindingState = Literal["pending", "ready"]


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
