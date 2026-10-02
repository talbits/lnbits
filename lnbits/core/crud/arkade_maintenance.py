"""Public, durable lineage for browser-signed VTXO renewals. No ledger credits."""

import json
from datetime import datetime, timezone

from lnbits.core.db import db
from lnbits.core.models.arkade import ArkadeIndexerVtxo, ArkadeMaintenancePlan
from lnbits.db import Connection, Database


async def maintenance_rows(account_id: str, conn: Connection | Database | None = None):
    return await (conn or db).fetchall(
        "SELECT * FROM arkade_maintenance WHERE account_id = :account_id",
        {"account_id": account_id},
    )


async def reconcile_maintenance(
    account_id: str, evidence: list[ArkadeIndexerVtxo], conn: Connection | Database
) -> tuple[set[tuple[str, int]], set[tuple[str, int]], bool]:
    """Match an exact-value replacement to the batch that consumed its inputs.

    The trusted indexer must link every input's settledBy to the replacement's
    commitmentTxids. A signed plan alone is never settlement evidence.
    """
    observed = {(v.txid, v.vout): v for v in evidence}
    unique = len(observed) == len(evidence)
    consumed: set[tuple[str, int]] = set()
    outputs: set[tuple[str, int]] = set()
    newly_verified = False
    for row in await maintenance_rows(account_id, conn):
        plan = ArkadeMaintenancePlan.parse_raw(row["plan_json"])
        if row["state"] == "planned":
            # Do not let a newly indexed replacement be credited as income
            # while its input-side batch attribution is still catching up.
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
            if (
                replacement.is_spent
                or replacement.is_swept
                or replacement.is_unrolled
                or replacement.settled_by
                or replacement.expires_at_height is not None
                or (
                    replacement.expires_at is not None
                    and replacement.expires_at <= datetime.now(timezone.utc)
                )
            ):
                continue
            await conn.execute(
                "UPDATE arkade_maintenance SET state = 'verified', "
                "output_txid = :txid, output_vout = :vout "
                "WHERE operation_id = :id AND state = 'planned'",
                {
                    "txid": replacement.txid,
                    "vout": replacement.vout,
                    "id": row["operation_id"],
                },
            )
            newly_verified = True
            outputs.add((replacement.txid, replacement.vout))
        else:
            outputs.add((row["output_txid"], row["output_vout"]))
        consumed.update((i.txid, i.vout) for i in plan.inputs)
    return consumed, outputs, newly_verified


async def store_maintenance(
    account_id: str, plan: ArkadeMaintenancePlan, conn: Connection
):
    await conn.execute(
        "INSERT INTO arkade_maintenance "
        "(operation_id, account_id, plan_json, script, amount_sat, state) "
        "VALUES (:id, :account, :plan, :script, :amount, 'planned')",
        {
            "id": plan.operation_id,
            "account": account_id,
            "plan": json.dumps(plan.dict()),
            "script": plan.output.script,
            "amount": plan.output.amount_sat,
        },
    )
    for i in plan.inputs:
        await conn.execute(
            "INSERT INTO arkade_maintenance_inputs (txid, vout, operation_id) "
            "VALUES (:txid, :vout, :id)",
            {"txid": i.txid, "vout": i.vout, "id": plan.operation_id},
        )
