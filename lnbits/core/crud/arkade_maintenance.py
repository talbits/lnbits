"""Read legacy renewal records so receive reconciliation avoids double credit."""

from pydantic import ValidationError

from lnbits.core.db import db
from lnbits.core.models.arkade import ArkadeIndexerVtxo, ArkadeMaintenancePlan
from lnbits.db import Connection, Database


async def maintenance_rows(account_id: str, conn: Connection | Database | None = None):
    return await (conn or db).fetchall(
        "SELECT * FROM arkade_maintenance WHERE account_id = :account_id",
        {"account_id": account_id},
    )


async def historical_maintenance_outpoints(
    account_id: str, evidence: list[ArkadeIndexerVtxo], conn: Connection | Database
) -> tuple[set[tuple[str, int]], set[tuple[str, int]]]:
    """Identify legacy renewal inputs/outputs for receive credit attribution.

    These records never authorize a spend, verify account backing or earn a
    ledger credit. Exact lineage is only used to avoid counting a replacement
    output as a second receive.
    """
    observed = {(v.txid, v.vout): v for v in evidence}
    unique = len(observed) == len(evidence)
    consumed: set[tuple[str, int]] = set()
    outputs: set[tuple[str, int]] = set()
    for row in await maintenance_rows(account_id, conn):
        try:
            plan = ArkadeMaintenancePlan.parse_raw(row["plan_json"])
        except (ValidationError, ValueError, TypeError):
            continue
        if row["state"] == "planned":
            candidates = [v for v in evidence if v.script == row["script"]]
            outputs.update((v.txid, v.vout) for v in candidates)
            inputs = [observed.get((i.txid, i.vout)) for i in plan.inputs]
            if not unique or len(candidates) != 1 or any(v is None for v in inputs):
                continue
            replacement = candidates[0]
            if replacement.amount_sat != row["amount_sat"] or any(
                v is None
                or v.amount_sat != i.amount_sat
                or not v.settled_by
                or v.settled_by not in replacement.commitment_txids
                for i, v in zip(plan.inputs, inputs, strict=True)
            ):
                continue
            consumed.update((i.txid, i.vout) for i in plan.inputs)
        else:
            if row["output_txid"] is not None and row["output_vout"] is not None:
                outputs.add((row["output_txid"], row["output_vout"]))
            consumed.update((i.txid, i.vout) for i in plan.inputs)
    return consumed, outputs
