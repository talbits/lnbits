"""Executable Phase 1 contract for one account's logical wallet ledger.

This deliberately models accounting only. Arkade owns the aggregate funds;
LNbits owns the allocation among logical wallet IDs.
"""

from __future__ import annotations

import json
from dataclasses import dataclass

import pytest


class LedgerError(ValueError):
    """A requested ledger operation cannot be applied."""


@dataclass(frozen=True)
class Reservation:
    wallet_id: str
    amount_msat: int
    max_fee_msat: int


@dataclass(frozen=True)
class Receipt:
    wallet_id: str
    amount_msat: int


@dataclass
class LogicalLedger:
    account_id: str
    aggregate_msat: int
    unallocated_msat: int
    wallets: dict[str, int]
    reservations: dict[str, Reservation]
    receipts: dict[str, Receipt]

    @classmethod
    def from_observed_aggregate(
        cls, account_id: str, *, aggregate_msat: int
    ) -> LogicalLedger:
        return cls(account_id, aggregate_msat, aggregate_msat, {}, {}, {})

    def add_wallet(self, wallet_id: str, balance_msat: int = 0) -> None:
        if wallet_id in self.wallets or balance_msat < 0:
            raise LedgerError("invalid logical wallet")
        if balance_msat > self.unallocated_msat:
            raise LedgerError("insufficient unallocated balance")
        self.wallets[wallet_id] = balance_msat
        self.unallocated_msat -= balance_msat

    def receive(self, receipt_id: str, wallet_id: str, amount_msat: int) -> bool:
        if wallet_id not in self.wallets or amount_msat <= 0:
            raise LedgerError("invalid receipt")
        if receipt_id in self.receipts:
            receipt = self.receipts[receipt_id]
            if receipt.wallet_id != wallet_id:
                raise LedgerError("receipt target changed")
            if receipt.amount_msat != amount_msat:
                raise LedgerError("receipt amount changed")
            return False
        self.receipts[receipt_id] = Receipt(wallet_id, amount_msat)
        self.wallets[wallet_id] += amount_msat
        self.aggregate_msat += amount_msat
        return True

    def reserve(
        self, intent_id: str, wallet_id: str, amount_msat: int, max_fee_msat: int
    ) -> None:
        if wallet_id not in self.wallets or amount_msat <= 0 or max_fee_msat < 0:
            raise LedgerError("invalid reservation")
        if intent_id in self.reservations:
            raise LedgerError("intent already reserved")
        required_msat = amount_msat + max_fee_msat
        if self.wallets[wallet_id] < required_msat:
            raise LedgerError("logical wallet lacks amount plus max fee")
        self.wallets[wallet_id] -= required_msat
        self.reservations[intent_id] = Reservation(wallet_id, amount_msat, max_fee_msat)

    def settle(self, intent_id: str, actual_fee_msat: int) -> None:
        reservation = self.reservations.pop(intent_id)
        if actual_fee_msat < 0 or actual_fee_msat > reservation.max_fee_msat:
            self.reservations[intent_id] = reservation
            raise LedgerError("actual fee exceeds reservation")
        self.wallets[reservation.wallet_id] += (
            reservation.max_fee_msat - actual_fee_msat
        )
        self.aggregate_msat -= reservation.amount_msat + actual_fee_msat

    def release(self, intent_id: str) -> None:
        reservation = self.reservations.pop(intent_id)
        self.wallets[reservation.wallet_id] += (
            reservation.amount_msat + reservation.max_fee_msat
        )

    def transfer(
        self,
        source_wallet_id: str,
        target: LogicalLedger,
        target_wallet_id: str,
        amount_msat: int,
    ) -> None:
        if target is not self:
            raise LedgerError("external Arkade transfer required")
        if (
            source_wallet_id not in self.wallets
            or target_wallet_id not in self.wallets
            or amount_msat <= 0
            or self.wallets[source_wallet_id] < amount_msat
        ):
            raise LedgerError("insufficient logical wallet balance")
        self.wallets[source_wallet_id] -= amount_msat
        self.wallets[target_wallet_id] += amount_msat

    def to_json(self) -> str:
        return json.dumps(
            {
                "account_id": self.account_id,
                "aggregate_msat": self.aggregate_msat,
                "unallocated_msat": self.unallocated_msat,
                "wallets": self.wallets,
                "reservations": {
                    intent_id: {
                        "wallet_id": reservation.wallet_id,
                        "amount_msat": reservation.amount_msat,
                        "max_fee_msat": reservation.max_fee_msat,
                    }
                    for intent_id, reservation in self.reservations.items()
                },
                "receipts": {
                    receipt_id: {
                        "wallet_id": receipt.wallet_id,
                        "amount_msat": receipt.amount_msat,
                    }
                    for receipt_id, receipt in self.receipts.items()
                },
            },
            sort_keys=True,
        )

    @classmethod
    def from_json(cls, value: str) -> LogicalLedger:
        state = json.loads(value)
        return cls(
            account_id=state["account_id"],
            aggregate_msat=state["aggregate_msat"],
            unallocated_msat=state["unallocated_msat"],
            wallets=state["wallets"],
            reservations={
                intent_id: Reservation(**reservation)
                for intent_id, reservation in state["reservations"].items()
            },
            receipts={
                receipt_id: Receipt(**receipt)
                for receipt_id, receipt in state["receipts"].items()
            },
        )


def test_phase1_account_logical_ledger_contract() -> None:
    ledger = LogicalLedger.from_observed_aggregate("account-1", aggregate_msat=100_000)
    ledger.add_wallet("wallet-a", 10_000)
    ledger.add_wallet("wallet-b", 70_000)
    assert ledger.wallets == {"wallet-a": 10_000, "wallet-b": 70_000}
    assert ledger.aggregate_msat == 100_000

    assert ledger.receive("receipt-a", "wallet-a", 5_000)
    snapshot = ledger.to_json()
    assert not ledger.receive("receipt-a", "wallet-a", 5_000)
    assert ledger.wallets == {"wallet-a": 15_000, "wallet-b": 70_000}
    with pytest.raises(LedgerError, match="receipt amount changed"):
        ledger.receive("receipt-a", "wallet-a", 6_000)
    with pytest.raises(LedgerError, match="receipt target changed"):
        ledger.receive("receipt-a", "wallet-b", 5_000)

    before_rejection = ledger.to_json()
    with pytest.raises(LedgerError, match="amount plus max fee"):
        ledger.reserve("intent-rejected", "wallet-a", 14_000, 2_000)
    assert ledger.to_json() == before_rejection
    assert ledger.aggregate_msat > 16_000

    aggregate_before_reservation = ledger.aggregate_msat
    ledger.reserve("intent-a", "wallet-a", 8_000, 2_000)
    assert ledger.reservations["intent-a"].wallet_id == "wallet-a"
    assert ledger.wallets == {"wallet-a": 5_000, "wallet-b": 70_000}
    assert ledger.aggregate_msat == aggregate_before_reservation
    assert "vtxo" not in ledger.to_json().lower()
    snapshot = ledger.to_json()
    reloaded = LogicalLedger.from_json(snapshot)
    assert reloaded.wallets == {"wallet-a": 5_000, "wallet-b": 70_000}
    assert reloaded.reservations == {"intent-a": Reservation("wallet-a", 8_000, 2_000)}
    assert reloaded.receipts == {"receipt-a": Receipt("wallet-a", 5_000)}
    assert not reloaded.receive("receipt-a", "wallet-a", 5_000)

    ledger.settle("intent-a", actual_fee_msat=1_000)
    assert ledger.wallets == {"wallet-a": 6_000, "wallet-b": 70_000}
    assert ledger.aggregate_msat == 96_000
    assert not ledger.reservations

    ledger.reserve("intent-failed", "wallet-b", 10_000, 500)
    ledger.release("intent-failed")
    assert ledger.wallets["wallet-b"] == 70_000

    aggregate_before_transfer = ledger.aggregate_msat
    ledger.transfer("wallet-b", ledger, "wallet-a", 20_000)
    assert ledger.wallets == {"wallet-a": 26_000, "wallet-b": 50_000}
    assert ledger.aggregate_msat == aggregate_before_transfer

    before_transfer_rejection = ledger.to_json()
    with pytest.raises(LedgerError, match="insufficient"):
        ledger.transfer("wallet-a", ledger, "wallet-b", 27_000)
    assert ledger.to_json() == before_transfer_rejection

    other_account = LogicalLedger.from_observed_aggregate(
        "account-2", aggregate_msat=30_000
    )
    other_account.add_wallet("wallet-c", 30_000)
    first_state, second_state = ledger.to_json(), other_account.to_json()
    with pytest.raises(LedgerError, match="external Arkade transfer required"):
        ledger.transfer("wallet-a", other_account, "wallet-c", 1_000)
    assert (ledger.to_json(), other_account.to_json()) == (first_state, second_state)

    restored = LogicalLedger.from_json(ledger.to_json())
    assert restored.wallets == ledger.wallets
    assert restored.reservations == ledger.reservations
    assert restored.receipts == ledger.receipts
    assert not any(
        secret in snapshot.lower()
        for secret in (
            "mnemonic",
            "seed",
            "secret",
            "nsec",
            "private_key",
            "private key",
        )
    )
