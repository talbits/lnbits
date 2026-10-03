import importlib
import re
from typing import Any, cast
from urllib.parse import urlparse, urlsplit, urlunsplit
from uuid import UUID

from coincurve import PublicKeyXOnly
from loguru import logger
from sqlalchemy.exc import SQLAlchemyError

from lnbits.core import migrations as core_migrations
from lnbits.core.crud import (
    get_db_versions,
    get_installed_extensions,
    update_migration_version,
)
from lnbits.core.db import db as core_db
from lnbits.core.models import DbVersion
from lnbits.core.models.extensions import InstallableExtension
from lnbits.core.wasm_ext.storage.crud import migrate_wasm_extension_database
from lnbits.core.wasm_ext.wasm.loader import is_wasm_extension_id
from lnbits.db import SQLITE, Connection
from lnbits.settings import InstallationMode, settings

INSTALLATION_MODE_MIGRATION = 51
INSTALLATION_MODE_CORRUPT = (
    "INSTALLATION_MODE_CORRUPT: the installation mode marker is missing or invalid. "
    "Restore the database from backup; do not recreate or change the marker."
)


def canonical_arkade_server_url(url: str) -> str:  # noqa: C901
    """Return the only URL form accepted in Arkade enrollment statements."""
    if not isinstance(url, str):
        raise RuntimeError("ARKADE_CONFIG_INVALID")
    try:
        url.encode("ascii")
    except UnicodeEncodeError as exc:
        raise RuntimeError("ARKADE_CONFIG_INVALID") from exc
    try:
        parsed = urlsplit(url)
    except ValueError as exc:
        raise RuntimeError("ARKADE_CONFIG_INVALID") from exc
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise RuntimeError("ARKADE_CONFIG_INVALID")
    if ":" in parsed.hostname:
        # IPv6 must be bracketed in an authority. Rejecting it keeps the
        # canonical statement unambiguous until an IPv6 policy is designed.
        raise RuntimeError("ARKADE_CONFIG_INVALID")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise RuntimeError("ARKADE_CONFIG_INVALID")
    try:
        port = parsed.port
    except ValueError as exc:
        raise RuntimeError("ARKADE_CONFIG_INVALID") from exc
    if port is not None and not 1 <= port <= 65535:
        raise RuntimeError("ARKADE_CONFIG_INVALID")
    if any(char.isspace() or ord(char) < 32 or ord(char) == 127 for char in url):
        raise RuntimeError("ARKADE_CONFIG_INVALID")
    if port and not (
        (parsed.scheme == "http" and port == 80)
        or (parsed.scheme == "https" and port == 443)
    ):
        host = f"{parsed.hostname.lower()}:{port}"
    else:
        host = parsed.hostname.lower()
    return urlunsplit((parsed.scheme, host, parsed.path.rstrip("/"), "", ""))


def get_arkade_configuration() -> tuple[str, str, str]:
    network = settings.lnbits_arkade_network
    server_url = settings.lnbits_arkade_server_url
    signer_pubkey = settings.lnbits_arkade_server_pubkey
    if not isinstance(network, str) or not re.fullmatch(
        r"[A-Za-z0-9][A-Za-z0-9._-]{0,31}", network
    ):
        raise RuntimeError("ARKADE_CONFIG_INVALID")
    if not isinstance(server_url, str) or not server_url:
        raise RuntimeError("ARKADE_CONFIG_INVALID")
    canonical_url = canonical_arkade_server_url(server_url)
    if not isinstance(signer_pubkey, str) or not re.fullmatch(
        r"[0-9a-fA-F]{64}", signer_pubkey
    ):
        raise RuntimeError("ARKADE_CONFIG_INVALID")
    signer_pubkey = signer_pubkey.lower()
    try:
        PublicKeyXOnly(bytes.fromhex(signer_pubkey))
    except (TypeError, ValueError) as exc:
        raise RuntimeError("ARKADE_CONFIG_INVALID") from exc
    return network, canonical_url, signer_pubkey


def validate_arkade_configuration() -> None:
    get_arkade_configuration()


async def migrate_extension_database(
    ext: InstallableExtension, current_version: DbVersion | None = None
):
    if is_wasm_extension_id(ext.id):
        await migrate_wasm_extension_database(ext, current_version)
        return
    else:
        await migrate_py_extension_database(ext, current_version)


async def migrate_py_extension_database(
    ext: InstallableExtension, current_version: DbVersion | None = None
):
    try:
        ext_migrations = importlib.import_module(f"{ext.module_name}.migrations")
        ext_db = importlib.import_module(ext.module_name).db
    except ImportError as exc:
        logger.error(exc)
        raise ImportError(f"Cannot import module for extension '{ext.id}'.") from exc

    async with ext_db.connect() as ext_conn:
        await run_migration(ext_conn, ext_migrations, ext.id, current_version)


async def run_migration(
    db: Connection,
    migrations_module: Any,
    db_name: str,
    current_version: DbVersion | None = None,
):
    matcher = re.compile(r"^m(\d\d\d)_")

    for key, migrate in list(migrations_module.__dict__.items()):
        match = matcher.match(key)
        if match:
            version = int(match.group(1))
            if not current_version or version > current_version.version:
                logger.debug(f"running migration {db_name}.{version}")
                print(f"running migration {db_name}.{version}")
                await migrate(db)

                if db.schema is None:
                    await update_migration_version(db, db_name, version)
                else:
                    async with core_db.connect() as conn:
                        await update_migration_version(conn, db_name, version)


def to_valid_user_id(user_id: str) -> UUID:
    if len(user_id) < 32:
        raise ValueError("User ID must have at least 128 bits")
    try:
        int(user_id, 16)
    except Exception as exc:
        raise ValueError("Invalid hex string for User ID.") from exc

    return UUID(hex=user_id[:32], version=4)


async def load_disabled_extension_list() -> None:
    """Update list of extensions that have been explicitly disabled"""
    inactive_extensions = await get_installed_extensions(active=False)
    settings.lnbits_deactivated_extensions.update([e.id for e in inactive_extensions])


async def _table_exists(conn: Connection, table: str) -> bool:
    if conn.type == SQLITE:
        row: dict | None = await conn.fetchone(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = :table",
            {"table": table},
        )
    else:
        row = await conn.fetchone(
            "SELECT 1 FROM information_schema.tables "
            "WHERE table_schema = 'public' AND table_name = :table",
            {"table": table},
        )
    return bool(row)


def check_installation_mode(
    configured: InstallationMode, persisted: InstallationMode
) -> None:
    if configured == persisted:
        return
    raise RuntimeError(
        "INSTALLATION_MODE_MISMATCH: configured mode "
        f"'{configured}' does not match database mode '{persisted}'. "
        f"Restore LNBITS_INSTALLATION_MODE={persisted} to use this database, "
        f"or configure a new empty database for '{configured}'; existing "
        "databases cannot change mode."
    )


async def get_installation_mode(conn: Connection) -> InstallationMode:
    try:
        rows: list[dict] = await conn.fetchall("SELECT id, mode FROM installation_mode")
    except SQLAlchemyError as exc:
        raise RuntimeError(INSTALLATION_MODE_CORRUPT) from exc
    if len(rows) != 1 or rows[0]["id"] != 1:
        raise RuntimeError(INSTALLATION_MODE_CORRUPT)
    mode = rows[0]["mode"]
    if mode not in {"custodial", "arkade_noncustodial"}:
        raise RuntimeError(INSTALLATION_MODE_CORRUPT)
    return cast(InstallationMode, mode)


async def initialize_installation_mode(
    conn: Connection,
    *,
    configured: InstallationMode,
    core_version: int,
) -> InstallationMode:
    table_exists = await _table_exists(conn, "installation_mode")
    if table_exists:
        try:
            rows: list[dict] = await conn.fetchall(
                "SELECT id, mode FROM installation_mode"
            )
        except SQLAlchemyError as exc:
            raise RuntimeError(INSTALLATION_MODE_CORRUPT) from exc
        if rows:
            return await get_installation_mode(conn)

    if core_version >= INSTALLATION_MODE_MIGRATION:
        raise RuntimeError(INSTALLATION_MODE_CORRUPT)

    if not table_exists:
        await core_migrations.m051_create_installation_mode_table(conn)

    mode: InstallationMode = (
        configured if not await _table_exists(conn, "accounts") else "custodial"
    )
    await conn.execute(
        "INSERT INTO installation_mode (id, mode) VALUES (1, :mode) "
        "ON CONFLICT (id) DO NOTHING",
        {"mode": mode},
    )
    return await get_installation_mode(conn)


async def migrate_databases():
    """Creates the necessary databases if they don't exist already; or migrates them."""

    settings.lnbits_effective_installation_mode = None
    async with core_db.connect() as conn:
        exists = await _table_exists(conn, "dbversions")
        current_versions = await get_db_versions(conn) if exists else []
        core_version = next(
            (v for v in current_versions if v.db == "core"),
            DbVersion(db="core", version=0),
        )
        persisted_mode = await initialize_installation_mode(
            conn,
            configured=settings.lnbits_installation_mode,
            core_version=core_version.version,
        )
        check_installation_mode(settings.lnbits_installation_mode, persisted_mode)
        if persisted_mode == "arkade_noncustodial":
            validate_arkade_configuration()
        settings.lnbits_effective_installation_mode = persisted_mode
        if not exists:
            await core_migrations.m000_create_migrations_table(conn)
        await run_migration(conn, core_migrations, "core", core_version)

    # here is the first place we can be sure that the
    # `installed_extensions` table has been created
    await load_disabled_extension_list()

    for ext in await get_installed_extensions():
        current_version = next(
            (v for v in current_versions if v.db == ext.id),
            DbVersion(db=ext.id, version=0),
        )
        if current_version is None:
            logger.warning(
                f"Extension {ext.id} has no migration version. This should not happen."
            )
            continue
        try:
            await migrate_extension_database(ext, current_version)
        except Exception as e:
            logger.exception(f"Error migrating extension {ext.id}: {e}")

    logger.info("✔️ All migrations done.")


def is_valid_url(url):
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except ValueError:
        return False
