"""A pre-Arkade database must survive the payment identity migration.

``m054_add_payment_protocol_identity`` rewrites the core ``apipayments`` table,
and the installation mode is frozen on first start. Existing custodial databases
hold payments whose Lightning identifiers are incomplete, so the upgrade path
needs explicit proof: every stored row must survive, the legacy constraints must
hold, and the database must stay custodial.

Every other test starts from an empty database, which is the one case that cannot
regress. This module builds a real legacy schema by running only the migrations
that existed before the Arkade work.
"""

import re
from pathlib import Path
from types import SimpleNamespace

import pytest

from lnbits.core import migrations as core_migrations
from lnbits.core.crud.payments import get_payment_by_native_id
from lnbits.core.helpers import (
    check_installation_mode,
    initialize_installation_mode,
    run_migration,
)
from lnbits.core.models.misc import DbVersion
from lnbits.db import Database
from lnbits.settings import settings

LEGACY_VERSION = 50
_MIGRATION_NAME = re.compile(r"^m(\d\d\d)_")

# Shapes a pre-Arkade database legitimately holds. Every row carries a
# checking_id (the legacy column was NOT NULL) but not necessarily the Lightning
# identifiers the new validators used to require.
LEGACY_PAYMENTS = [
    ("legacy-paid", 1000, 0, "wallet-a", "paid invoice", "hash-a", "lnbc1legacy"),
    ("internal-empty-bolt11", 500, 0, "wallet-b", "internal", "hash-b", ""),
    ("internal-null-identifiers", 250, 0, "wallet-c", "internal", None, None),
]

_INSERT = """
    INSERT INTO apipayments
        (checking_id, amount, fee, wallet_id, memo, payment_hash, bolt11)
    VALUES
        (:checking_id, :amount, :fee, :wallet_id, :memo, :payment_hash, :bolt11)
"""

_SELECT = """
    SELECT checking_id, amount, fee, wallet_id, memo, payment_hash, bolt11,
           protocol, native_id, arkade_address
    FROM apipayments
    ORDER BY checking_id
"""


def _legacy_migration_module() -> SimpleNamespace:
    """The core migration module as it stood before the Arkade migrations."""
    return SimpleNamespace(
        **{
            name: func
            for name, func in vars(core_migrations).items()
            if (match := _MIGRATION_NAME.match(name))
            and int(match.group(1)) <= LEGACY_VERSION
        }
    )


async def _open_legacy_database(tmp_path: Path) -> Database:
    settings.lnbits_data_folder = str(tmp_path / "data")
    Path(settings.lnbits_data_folder).mkdir(parents=True, exist_ok=True)
    database = Database("legacy_upgrade")
    async with database.connect() as conn:
        await run_migration(conn, _legacy_migration_module(), "core", None)
    return database


async def _upgraded_legacy_database(tmp_path: Path) -> Database:
    """A seeded legacy database, migrated all the way to the branch head."""
    database = await _open_legacy_database(tmp_path)
    async with database.connect() as conn:
        for row in LEGACY_PAYMENTS:
            await conn.execute(
                _INSERT,
                dict(
                    zip(
                        (
                            "checking_id",
                            "amount",
                            "fee",
                            "wallet_id",
                            "memo",
                            "payment_hash",
                            "bolt11",
                        ),
                        row,
                        strict=True,
                    )
                ),
            )
        await initialize_installation_mode(
            conn, configured="custodial", core_version=LEGACY_VERSION
        )
        await run_migration(
            conn,
            core_migrations,
            "core",
            DbVersion(db="core", version=LEGACY_VERSION),
        )
    return database


@pytest.mark.anyio
async def test_legacy_database_upgrades_without_losing_payments(tmp_path: Path):
    original_data_folder = settings.lnbits_data_folder
    try:
        database = await _upgraded_legacy_database(tmp_path)
        async with database.connect() as conn:
            rows = await conn.fetchall(_SELECT)
            views = await conn.fetchall(
                "SELECT name FROM sqlite_master WHERE type='view' AND name='balances'"
            )
    finally:
        settings.lnbits_data_folder = original_data_folder

    assert len(rows) == len(LEGACY_PAYMENTS)
    for row, expected in zip(rows, sorted(LEGACY_PAYMENTS), strict=True):
        assert row["checking_id"] == expected[0]
        assert row["amount"] == expected[1]
        assert row["fee"] == expected[2]
        assert row["wallet_id"] == expected[3]
        assert row["memo"] == expected[4]
        # Identifiers may stay incomplete: the previous schema allowed it.
        assert row["payment_hash"] == expected[5]
        assert row["bolt11"] == expected[6]
        assert row["protocol"] == "lightning"
        # Backfilled for every legacy payment (see the collision test below).
        assert row["native_id"] == expected[0]
        assert row["arkade_address"] is None

    assert views, "the balances view must be recreated"


@pytest.mark.anyio
async def test_legacy_payments_still_load_with_incomplete_identifiers(tmp_path: Path):
    """Incomplete stored identifiers must not break reading a payment back."""
    original_data_folder = settings.lnbits_data_folder
    try:
        database = await _upgraded_legacy_database(tmp_path)
        async with database.connect() as conn:
            parsed = await get_payment_by_native_id(
                "internal-null-identifiers", conn=conn
            )
            parsed_empty = await get_payment_by_native_id(
                "internal-empty-bolt11", conn=conn
            )
    finally:
        settings.lnbits_data_folder = original_data_folder

    assert parsed is not None
    assert parsed.bolt11 is None
    assert parsed.payment_hash is None
    assert parsed_empty is not None
    assert parsed_empty.bolt11 == ""


@pytest.mark.anyio
async def test_arkade_native_id_lookup_also_matches_legacy_payments(tmp_path: Path):
    """Characterises the identity collision created by the migration backfill.

    The migration sets ``native_id = checking_id`` for every legacy payment, while
    ``get_payment_by_native_id`` filters only on ``native_id``. An Arkade intent
    lookup can therefore resolve to a pre-Arkade Lightning payment. This test
    pins the current behaviour so the decision (filter by protocol, or stop
    backfilling) is visible and the guard can be tightened deliberately.
    """
    original_data_folder = settings.lnbits_data_folder
    try:
        database = await _upgraded_legacy_database(tmp_path)
        async with database.connect() as conn:
            found = await get_payment_by_native_id("legacy-paid", conn=conn)
    finally:
        settings.lnbits_data_folder = original_data_folder

    assert found is not None
    # The lookup is not protocol aware, so a Lightning payment answers it.
    assert found.protocol == "lightning"
    assert found.native_id == found.checking_id


@pytest.mark.anyio
async def test_legacy_database_is_frozen_to_custodial(tmp_path: Path):
    original_data_folder = settings.lnbits_data_folder
    try:
        database = await _open_legacy_database(tmp_path)
        async with database.connect() as conn:
            # accounts exists, so the persisted mode is custodial regardless of
            # what the operator configures.
            mode = await initialize_installation_mode(
                conn, configured="arkade_noncustodial", core_version=LEGACY_VERSION
            )
    finally:
        settings.lnbits_data_folder = original_data_folder

    assert mode == "custodial"
    with pytest.raises(RuntimeError, match="INSTALLATION_MODE_MISMATCH"):
        check_installation_mode("arkade_noncustodial", mode)
