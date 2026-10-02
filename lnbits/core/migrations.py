import json
from time import time
from typing import Any

from loguru import logger
from sqlalchemy.exc import OperationalError

from lnbits import bolt11
from lnbits.db import SQLITE, Connection


async def m000_create_migrations_table(db: Connection):
    await db.execute("""
    CREATE TABLE IF NOT EXISTS dbversions (
        db TEXT PRIMARY KEY,
        version INT NOT NULL
    )
    """)


async def m001_initial(db: Connection):
    """
    Initial LNbits tables.
    """
    await db.execute("""
        CREATE TABLE IF NOT EXISTS accounts (
            id TEXT PRIMARY KEY,
            email TEXT,
            pass TEXT
        );
    """)
    await db.execute("""
        CREATE TABLE IF NOT EXISTS extensions (
            "user" TEXT NOT NULL,
            extension TEXT NOT NULL,
            active BOOLEAN DEFAULT false,

            UNIQUE ("user", extension)
        );
    """)
    await db.execute("""
        CREATE TABLE IF NOT EXISTS wallets (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            "user" TEXT NOT NULL,
            adminkey TEXT NOT NULL,
            inkey TEXT
        );
    """)
    await db.execute(f"""
        CREATE TABLE IF NOT EXISTS apipayments (
            payhash TEXT NOT NULL,
            amount {db.big_int} NOT NULL,
            fee INTEGER NOT NULL DEFAULT 0,
            wallet TEXT NOT NULL,
            pending BOOLEAN NOT NULL,
            memo TEXT,
            time TIMESTAMP NOT NULL DEFAULT {db.timestamp_now},
            UNIQUE (wallet, payhash)
        );
    """)

    await db.execute("""
        CREATE VIEW balances AS
        SELECT wallet, COALESCE(SUM(s), 0) AS balance FROM (
            SELECT wallet, SUM(amount) AS s  -- incoming
            FROM apipayments
            WHERE amount > 0 AND pending = false  -- don't sum pending
            GROUP BY wallet
            UNION ALL
            SELECT wallet, SUM(amount + fee) AS s  -- outgoing, sum fees
            FROM apipayments
            WHERE amount < 0  -- do sum pending
            GROUP BY wallet
        )x
        GROUP BY wallet;
    """)


async def m002_add_fields_to_apipayments(db: Connection):
    """
    Adding fields to apipayments for better accounting,
    and renaming payhash to checking_id since that is what it really is.
    """
    try:
        await db.execute("ALTER TABLE apipayments RENAME COLUMN payhash TO checking_id")
        await db.execute("ALTER TABLE apipayments ADD COLUMN hash TEXT")
        await db.execute("CREATE INDEX by_hash ON apipayments (hash)")
        await db.execute("ALTER TABLE apipayments ADD COLUMN preimage TEXT")
        await db.execute("ALTER TABLE apipayments ADD COLUMN bolt11 TEXT")
        await db.execute("ALTER TABLE apipayments ADD COLUMN extra TEXT")

        result = await db.execute("SELECT * FROM apipayments")
        rows = result.mappings().all()
        for row in rows:
            if not row["memo"] or not row["memo"].startswith("#"):
                continue

            for ext in ["withdraw", "events", "lnticket", "paywall", "tpos"]:
                prefix = f"#{ext} "
                if row["memo"].startswith(prefix):
                    new = row["memo"][len(prefix) :]
                    await db.execute(
                        """
                        UPDATE apipayments SET extra = :extra, memo = :memo1
                        WHERE checking_id = :checking_id AND memo = :memo2
                        """,
                        {
                            "extra": json.dumps({"tag": ext}),
                            "memo1": new,
                            "checking_id": row["checking_id"],
                            "memo2": row["memo"],
                        },
                    )
                    break
    except OperationalError:
        # this is necessary now because it may be the case that this migration will
        # run twice in some environments.
        # catching errors like this won't be necessary in anymore now that we
        # keep track of db versions so no migration ever runs twice.
        pass


async def m003_add_invoice_webhook(db: Connection):
    """
    Special column for webhook endpoints that can be assigned
    to each different invoice.
    """

    await db.execute("ALTER TABLE apipayments ADD COLUMN webhook TEXT")
    await db.execute("ALTER TABLE apipayments ADD COLUMN webhook_status TEXT")


async def m004_ensure_fees_are_always_negative(db: Connection):
    """
    Use abs() so wallet backends don't have to care about the sign of the fees.
    """

    await db.execute("DROP VIEW balances")
    await db.execute("""
        CREATE VIEW balances AS
        SELECT wallet, COALESCE(SUM(s), 0) AS balance FROM (
            SELECT wallet, SUM(amount) AS s  -- incoming
            FROM apipayments
            WHERE amount > 0 AND pending = false  -- don't sum pending
            GROUP BY wallet
            UNION ALL
            SELECT wallet, SUM(amount - abs(fee)) AS s  -- outgoing, sum fees
            FROM apipayments
            WHERE amount < 0  -- do sum pending
            GROUP BY wallet
        )x
        GROUP BY wallet;
    """)


async def m005_balance_check_balance_notify(db: Connection):
    """
    Keep track of balanceCheck-enabled lnurl-withdrawals to be consumed by an
    LNbits wallet and of balanceNotify URLs supplied by users to empty their wallets.
    """

    await db.execute("""
        CREATE TABLE IF NOT EXISTS balance_check (
          wallet TEXT NOT NULL REFERENCES wallets (id),
          service TEXT NOT NULL,
          url TEXT NOT NULL,

          UNIQUE(wallet, service)
        );
    """)

    await db.execute("""
        CREATE TABLE IF NOT EXISTS balance_notify (
          wallet TEXT NOT NULL REFERENCES wallets (id),
          url TEXT NOT NULL,

          UNIQUE(wallet, url)
        );
    """)


async def m006_add_invoice_expiry_to_apipayments(db: Connection):
    """
    Adds invoice expiry column to apipayments.
    """
    try:
        await db.execute("ALTER TABLE apipayments ADD COLUMN expiry TIMESTAMP")
    except OperationalError:
        pass


async def m007_set_invoice_expiries(db: Connection):
    """
    Precomputes invoice expiry for existing pending incoming payments.
    """
    try:
        result = await db.execute(
            # Timestamp placeholder is safe from SQL injection (not user input)
            f"""
            SELECT bolt11, checking_id
            FROM apipayments
            WHERE pending = true
            AND amount > 0
            AND bolt11 IS NOT NULL
            AND expiry IS NULL
            AND time < {db.timestamp_now}
            """  # noqa: S608
        )
        rows = result.mappings().all()
        if len(rows):
            logger.info(f"Migration: Checking expiry of {len(rows)} invoices")
        for i, (
            payment_request,
            checking_id,
        ) in enumerate(rows):
            try:
                invoice = bolt11.decode(payment_request)
                if invoice.expiry is None:
                    continue

                expiration_date = invoice.date + invoice.expiry
                logger.info(
                    f"Migration: {i+1}/{len(rows)} setting expiry of invoice"
                    f" {invoice.payment_hash} to {expiration_date}"
                )
                await db.execute(
                    # Timestamp placeholder is safe from SQL injection (not user input)
                    f"""
                    UPDATE apipayments SET expiry = {db.timestamp_placeholder('expiry')}
                    WHERE checking_id = :checking_id AND amount > 0
                    """,  # noqa: S608
                    {"expiry": expiration_date, "checking_id": checking_id},
                )
            except Exception as exc:
                logger.debug(exc)
                continue
    except OperationalError:
        # this is necessary now because it may be the case that this migration will
        # run twice in some environments.
        # catching errors like this won't be necessary in anymore now that we
        # keep track of db versions so no migration ever runs twice.
        pass


async def m008_create_admin_settings_table(db: Connection):
    await db.execute("""
        CREATE TABLE IF NOT EXISTS settings (
            super_user TEXT,
            editable_settings TEXT NOT NULL DEFAULT '{}'
        );
    """)


async def m009_create_tinyurl_table(db: Connection):
    await db.execute(f"""
        CREATE TABLE IF NOT EXISTS tiny_url (
          id TEXT PRIMARY KEY,
          url TEXT,
          endless BOOL NOT NULL DEFAULT false,
          wallet TEXT,
          time TIMESTAMP NOT NULL DEFAULT {db.timestamp_now}
        );
    """)


async def m010_create_installed_extensions_table(db: Connection):
    await db.execute("""
        CREATE TABLE IF NOT EXISTS installed_extensions (
            id TEXT PRIMARY KEY,
            version TEXT NOT NULL,
            name TEXT NOT NULL,
            short_description TEXT,
            icon TEXT,
            stars INT NOT NULL DEFAULT 0,
            active BOOLEAN DEFAULT false,
            meta TEXT NOT NULL DEFAULT '{}'
        );
    """)


async def m011_optimize_balances_view(db: Connection):
    """
    Make the calculation of the balance a single aggregation
    over the payments table instead of 2.
    """
    await db.execute("DROP VIEW balances")
    await db.execute("""
        CREATE VIEW balances AS
        SELECT wallet, SUM(amount - abs(fee)) AS balance
        FROM apipayments
        WHERE (pending = false AND amount > 0) OR amount < 0
        GROUP BY wallet
    """)


async def m012_add_currency_to_wallet(db: Connection):
    await db.execute("""
        ALTER TABLE wallets ADD COLUMN currency TEXT
        """)


async def m013_add_deleted_to_wallets(db: Connection):
    """
    Adds deleted column to wallets.
    """
    try:
        await db.execute(
            "ALTER TABLE wallets ADD COLUMN deleted BOOLEAN NOT NULL DEFAULT false"
        )
    except OperationalError:
        pass


async def m014_set_deleted_wallets(db: Connection):
    """
    Sets deleted column to wallets.
    """
    try:
        result = await db.execute("""
            SELECT *
            FROM wallets
            WHERE user LIKE 'del:%'
            AND adminkey LIKE 'del:%'
            AND inkey LIKE 'del:%'
            """)
        rows = result.mappings().all()

        for row in rows:
            try:
                user = row["user"].split(":")[1]
                adminkey = row["adminkey"].split(":")[1]
                inkey = row["inkey"].split(":")[1]
                await db.execute(
                    """
                    UPDATE wallets SET
                    "user" = :user, adminkey = :adminkey, inkey = :inkey, deleted = true
                    WHERE id = :wallet
                    """,
                    {
                        "user": user,
                        "adminkey": adminkey,
                        "inkey": inkey,
                        "wallet": row.get("id"),
                    },
                )
            except Exception as exc:
                logger.debug(exc)
                continue
    except OperationalError:
        # this is necessary now because it may be the case that this migration will
        # run twice in some environments.
        # catching errors like this won't be necessary in anymore now that we
        # keep track of db versions so no migration ever runs twice.
        pass


async def m015_create_push_notification_subscriptions_table(db: Connection):
    await db.execute(f"""
        CREATE TABLE IF NOT EXISTS webpush_subscriptions (
            endpoint TEXT NOT NULL,
            "user" TEXT NOT NULL,
            data TEXT NOT NULL,
            host TEXT NOT NULL,
            timestamp TIMESTAMP NOT NULL DEFAULT {db.timestamp_now},
            PRIMARY KEY (endpoint, "user")
        );
    """)


async def m016_add_username_column_to_accounts(db: Connection):
    """
    Adds username column to accounts.
    """
    try:
        await db.execute("ALTER TABLE accounts ADD COLUMN username TEXT")
        await db.execute("ALTER TABLE accounts ADD COLUMN extra TEXT")
    except OperationalError:
        pass


async def m017_add_timestamp_columns_to_accounts_and_wallets(db: Connection):
    """
    Adds created_at and updated_at column to accounts and wallets.
    """
    try:
        await db.execute(
            "ALTER TABLE accounts "
            f"ADD COLUMN created_at TIMESTAMP DEFAULT {db.timestamp_column_default}"
        )
        await db.execute(
            "ALTER TABLE accounts "
            f"ADD COLUMN updated_at TIMESTAMP DEFAULT {db.timestamp_column_default}"
        )
        await db.execute(
            "ALTER TABLE wallets "
            f"ADD COLUMN created_at TIMESTAMP DEFAULT {db.timestamp_column_default}"
        )
        await db.execute(
            "ALTER TABLE wallets "
            f"ADD COLUMN updated_at TIMESTAMP DEFAULT {db.timestamp_column_default}"
        )

        # # set their wallets created_at with the first payment
        # await db.execute(
        #     """
        #     UPDATE wallets SET created_at = (
        #         SELECT time FROM apipayments
        #         WHERE apipayments.wallet = wallets.id
        #         ORDER BY time ASC LIMIT 1
        #     )
        #  """
        # )

        # # then set their accounts created_at with the wallet
        # await db.execute(
        #     """
        #     UPDATE accounts SET created_at = (
        #         SELECT created_at FROM wallets
        #         WHERE wallets.user = accounts.id
        #         ORDER BY created_at ASC LIMIT 1
        #     )
        #  """
        # )

        # set all to now where they are null
        now = int(time())
        await db.execute(
            # Timestamp placeholder is safe from SQL injection (not user input)
            f"""
            UPDATE wallets SET created_at = {db.timestamp_placeholder('now')}
            WHERE created_at IS NULL
            """,  # noqa: S608
            {"now": now},
        )
        await db.execute(
            # Timestamp placeholder is safe from SQL injection (not user input)
            f"""
            UPDATE accounts SET created_at = {db.timestamp_placeholder('now')}
            WHERE created_at IS NULL
            """,  # noqa: S608
            {"now": now},
        )

    except OperationalError as exc:
        logger.error(f"Migration 17 failed: {exc}")
        pass


async def m018_balances_view_exclude_deleted(db: Connection):
    """
    Make deleted wallets not show up in the balances view.
    """
    await db.execute("DROP VIEW balances")
    await db.execute("""
        CREATE VIEW balances AS
        SELECT apipayments.wallet,
               SUM(apipayments.amount - ABS(apipayments.fee)) AS balance
        FROM apipayments
        LEFT JOIN wallets ON apipayments.wallet = wallets.id
        WHERE (wallets.deleted = false OR wallets.deleted is NULL)
              AND ((apipayments.pending = false AND apipayments.amount > 0)
              OR apipayments.amount < 0)
        GROUP BY wallet
    """)


async def m019_balances_view_based_on_wallets(db: Connection):
    """
    Make deleted wallets not show up in the balances view.
    Important for querying whole lnbits balances.
    """
    await db.execute("DROP VIEW balances")
    await db.execute("""
        CREATE VIEW balances AS
        SELECT apipayments.wallet,
               SUM(apipayments.amount - ABS(apipayments.fee)) AS balance
        FROM wallets
        LEFT JOIN apipayments ON apipayments.wallet = wallets.id
        WHERE (wallets.deleted = false OR wallets.deleted is NULL)
              AND ((apipayments.pending = false AND apipayments.amount > 0)
              OR apipayments.amount < 0)
        GROUP BY apipayments.wallet
    """)


async def m020_add_column_column_to_user_extensions(db: Connection):
    """
    Adds extra column to user extensions.
    """
    await db.execute("ALTER TABLE extensions ADD COLUMN extra TEXT")


async def m021_add_success_failed_to_apipayments(db: Connection):
    """
    Adds success and failed columns to apipayments.
    """
    await db.execute("ALTER TABLE apipayments ADD COLUMN status TEXT DEFAULT 'pending'")
    #  set all not pending to success true, failed payments were deleted until now
    await db.execute("UPDATE apipayments SET status = 'success' WHERE NOT pending")

    await db.execute("DROP VIEW balances")
    await db.execute("""
        CREATE VIEW balances AS
        SELECT apipayments.wallet,
               SUM(apipayments.amount - ABS(apipayments.fee)) AS balance
        FROM wallets
        LEFT JOIN apipayments ON apipayments.wallet = wallets.id
        WHERE (wallets.deleted = false OR wallets.deleted is NULL)
        AND (
            (apipayments.status = 'success' AND apipayments.amount > 0)
            OR (apipayments.status IN ('success', 'pending') AND apipayments.amount < 0)
        )
        GROUP BY apipayments.wallet
    """)


async def m022_add_pubkey_to_accounts(db: Connection):
    """
    Adds pubkey column to accounts.
    """
    try:
        await db.execute("ALTER TABLE accounts ADD COLUMN pubkey TEXT")
    except OperationalError:
        pass


async def m023_add_column_column_to_apipayments(db: Connection):
    """
    renames hash to payment_hash and drops unused index
    """
    await db.execute("DROP INDEX by_hash")
    await db.execute("ALTER TABLE apipayments RENAME COLUMN hash TO payment_hash")
    await db.execute("ALTER TABLE apipayments RENAME COLUMN wallet TO wallet_id")
    await db.execute("ALTER TABLE accounts RENAME COLUMN pass TO password_hash")

    await db.execute("CREATE INDEX by_hash ON apipayments (payment_hash)")


async def m024_drop_pending(db: Connection):
    await db.execute("ALTER TABLE apipayments DROP COLUMN pending")


async def m025_refresh_view(db: Connection):
    await db.execute("DROP VIEW balances")
    await db.execute("""
        CREATE VIEW balances AS
        SELECT apipayments.wallet_id,
               SUM(apipayments.amount - ABS(apipayments.fee)) AS balance
        FROM wallets
        LEFT JOIN apipayments ON apipayments.wallet_id = wallets.id
        WHERE (wallets.deleted = false OR wallets.deleted is NULL)
        AND (
            (apipayments.status = 'success' AND apipayments.amount > 0)
            OR (apipayments.status IN ('success', 'pending') AND apipayments.amount < 0)
        )
        GROUP BY apipayments.wallet_id
    """)


async def m026_update_payment_table(db: Connection):
    await db.execute("ALTER TABLE apipayments ADD COLUMN tag TEXT")
    await db.execute("ALTER TABLE apipayments ADD COLUMN extension TEXT")
    await db.execute("ALTER TABLE apipayments ADD COLUMN created_at TIMESTAMP")
    await db.execute("ALTER TABLE apipayments ADD COLUMN updated_at TIMESTAMP")


async def m027_update_apipayments_data(db: Connection):
    result = None
    try:
        result = await db.execute("SELECT * FROM apipayments LIMIT 100")
    except Exception as exc:
        logger.warning("Could not select, trying again after cache cleared.")
        logger.debug(exc)
        await db.execute("COMMIT")

    offset = 0
    limit = 1000
    payments: list[dict[Any, Any]] = []
    logger.info("Updating payments")
    while len(payments) > 0 or offset == 0:
        logger.info(f"Updating {offset} to {offset+limit}")

        result = await db.execute(
            # Limit and Offset safe from SQL injection
            # since they are integers and are not user input
            f"""
                SELECT * FROM apipayments
                ORDER BY time LIMIT {int(limit)} OFFSET {int(offset)}
            """  # noqa: S608
        )
        payments = result.mappings().all()
        logger.info(f"Payments count: {len(payments)}")

        for payment in payments:
            tag = None
            created_at = payment.get("time")
            if payment.get("extra"):
                extra = json.loads(str(payment.get("extra")))
                tag = extra.get("tag")
            tsph = db.timestamp_placeholder("created_at")
            await db.execute(
                # Timestamp placeholder is safe from SQL injection (not user input)
                f"""
                UPDATE apipayments
                SET tag = :tag, created_at = {tsph}, updated_at = {tsph}
                WHERE checking_id = :checking_id
                """,  # noqa: S608
                {
                    "tag": tag,
                    "created_at": created_at,
                    "checking_id": payment.get("checking_id"),
                },
            )
        offset += limit
    logger.info("Payments updated")


async def m028_update_settings(db: Connection):

    await db.execute("""
        CREATE TABLE IF NOT EXISTS system_settings (
            id TEXT PRIMARY KEY,
            value TEXT,
            tag TEXT NOT NULL DEFAULT 'core',

            UNIQUE (id, tag)
        );
    """)

    async def _insert_key_value(id_: str, value: Any):
        await db.execute(
            """
            INSERT INTO system_settings (id, value, tag)
            VALUES (:id, :value, :tag)
            """,
            {"id": id_, "value": json.dumps(value), "tag": "core"},
        )

    row: dict = await db.fetchone("SELECT * FROM settings")
    if row:
        await _insert_key_value("super_user", row["super_user"])
        editable_settings = json.loads(row["editable_settings"])

        for key, value in editable_settings.items():
            await _insert_key_value(key, value)

    await db.execute("drop table settings")


async def m029_create_audit_table(db: Connection):
    await db.execute(f"""
        CREATE TABLE IF NOT EXISTS audit (
            component TEXT,
            ip_address TEXT,
            user_id TEXT,
            path TEXT,
            request_type TEXT,
            request_method TEXT,
            request_details TEXT,
            response_code TEXT,
            duration REAL NOT NULL,
            delete_at TIMESTAMP,
            created_at TIMESTAMP NOT NULL DEFAULT {db.timestamp_now}
        );
        """)


async def m030_add_user_api_tokens_column(db: Connection):
    await db.execute("""
        ALTER TABLE accounts ADD COLUMN access_control_list TEXT
        """)


async def m031_add_color_and_icon_to_wallets(db: Connection):
    """
    Adds icon and color columns to wallets.
    """
    await db.execute("ALTER TABLE wallets ADD COLUMN extra TEXT")


async def m032_add_external_id_to_accounts(db: Connection):
    """
    Adds external_id column to accounts.
    Used for external account linking.
    """
    await db.execute("ALTER TABLE accounts ADD COLUMN external_id TEXT")


async def m033_update_payment_table(db: Connection):
    await db.execute("ALTER TABLE apipayments ADD COLUMN fiat_provider TEXT")


async def m034_add_stored_paylinks_to_wallet(db: Connection):
    await db.execute("""
        ALTER TABLE wallets ADD COLUMN stored_paylinks TEXT
        """)


async def m035_add_wallet_type_column(db: Connection):
    await db.execute("""
        ALTER TABLE wallets ADD COLUMN wallet_type TEXT DEFAULT 'lightning'
        """)


async def m036_add_shared_wallet_column(db: Connection):
    await db.execute("""
        ALTER TABLE wallets ADD COLUMN shared_wallet_id TEXT
        """)


async def m037_create_assets_table(db: Connection):
    await db.execute(f"""
        CREATE TABLE IF NOT EXISTS assets (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            mime_type TEXT NOT NULL,
            is_public BOOLEAN NOT NULL DEFAULT false,
            name TEXT NOT NULL,
            size_bytes INT NOT NULL,
            thumbnail_base64 TEXT,
            thumbnail {db.blob},
            data {db.blob} NOT NULL,
            created_at TIMESTAMP NOT NULL DEFAULT {db.timestamp_now}
        );
        """)


async def m038_add_labels_for_payments(db: Connection):
    await db.execute("""
        ALTER TABLE apipayments ADD COLUMN labels TEXT
        """)


async def m039_index_payments(db: Connection):
    indexes = [
        "wallet_id",
        "checking_id",
        "payment_hash",
        "amount",
        "fee",
        "labels",
        "time",
        "status",
        "memo",
        "created_at",
        "updated_at",
    ]
    for index in indexes:
        logger.debug(f"Creating index idx_payments_{index}...")
        await db.execute(f"""
            CREATE INDEX IF NOT EXISTS idx_payments_{index} ON apipayments ({index});
            """)


async def m040_index_wallets(db: Connection):
    indexes = [
        "id",
        "user",
        "deleted",
        "adminkey",
        "inkey",
        "wallet_type",
        "created_at",
        "updated_at",
    ]

    for index in indexes:
        logger.debug(f"Creating index idx_wallets_{index}...")
        await db.execute(f"""
            CREATE INDEX IF NOT EXISTS idx_wallets_{index} ON wallets ("{index}");
            """)


async def m042_index_accounts(db: Connection):
    indexes = [
        "id",
        "email",
        "username",
        "pubkey",
        "external_id",
    ]

    for index in indexes:
        logger.debug(f"Creating index idx_wallets_{index}...")
        await db.execute(f"""
            CREATE INDEX IF NOT EXISTS idx_accounts_{index} ON accounts ("{index}");
            """)


async def m043_add_ui_customization_to_accounts(db: Connection):
    """
    Adds ui_customization column to accounts.
    Used for server side persistence of UI customization settings.
    """
    await db.execute("ALTER TABLE accounts ADD COLUMN ui_customization TEXT")


async def m044_add_activated_to_accounts(db: Connection):
    """
    Adds activated column to accounts.
    Used for account activation status.
    """
    await db.execute("ALTER TABLE accounts ADD COLUMN activated BOOLEAN DEFAULT true")


async def m045_add_external_id_to_payments(db: Connection):
    """
    Adds external_id column to apipayments.
    Used for external payment references.
    """
    await db.execute("ALTER TABLE apipayments ADD COLUMN external_id TEXT")
    logger.debug("Creating index idx_payments_external_id...")
    await db.execute("""
        CREATE INDEX IF NOT EXISTS idx_payments_external_id
        ON apipayments (external_id);
        """)


async def m046_add_permissions_to_installed_extensions(db: Connection):
    """
    Adds granted permissions to installed extensions.
    """
    await db.execute(
        "ALTER TABLE installed_extensions ADD COLUMN permissions TEXT DEFAULT '[]'"
    )


async def m047_create_wasm_invocations_table(db: Connection):
    """
    Tracks WASM extension invocations for runtime monitoring and controls.
    """
    await db.execute(f"""
        CREATE TABLE IF NOT EXISTS wasm_invocations (
            id TEXT PRIMARY KEY,
            extension_id TEXT NOT NULL,
            export_name TEXT NOT NULL,
            trigger_type TEXT NOT NULL DEFAULT 'unknown',
            status TEXT NOT NULL DEFAULT 'running',
            started_at TIMESTAMP NOT NULL DEFAULT {db.timestamp_now},
            finished_at TIMESTAMP,
            duration_ms INT,
            user_id TEXT,
            wallet_id TEXT,
            request_id TEXT,
            method TEXT,
            path TEXT,
            event_type TEXT,
            payment_hash TEXT,
            checking_id TEXT,
            memory_peak_bytes INT,
            request_bytes INT,
            response_bytes INT,
            host_call_count INT NOT NULL DEFAULT 0,
            http_call_count INT NOT NULL DEFAULT 0,
            storage_call_count INT NOT NULL DEFAULT 0,
            wallet_call_count INT NOT NULL DEFAULT 0,
            error_type TEXT,
            error_message TEXT,
            stop_reason TEXT,
            "context" TEXT NOT NULL DEFAULT '{{}}'
        );
        """)
    await db.execute("""
        CREATE INDEX IF NOT EXISTS idx_wasm_invocations_extension_started
        ON wasm_invocations (extension_id, started_at);
        """)
    await db.execute("""
        CREATE INDEX IF NOT EXISTS idx_wasm_invocations_status
        ON wasm_invocations (status);
        """)
    await db.execute("""
        CREATE INDEX IF NOT EXISTS idx_wasm_invocations_started
        ON wasm_invocations (started_at);
        """)


async def m048_add_wasm_runtime_limits_to_installed_extensions(db: Connection):
    """
    Adds per-extension WASM runtime limit overrides.
    """
    await db.execute(
        "ALTER TABLE installed_extensions "
        "ADD COLUMN wasm_runtime_limits TEXT DEFAULT '{}'"
    )


async def m049_add_permissions_to_user_extensions(db: Connection):
    """
    Adds user-level extension permission grants.
    """
    await db.execute("ALTER TABLE extensions ADD COLUMN permissions TEXT DEFAULT '{}'")


async def m050_add_lightning_address_to_wallets(db: Connection):
    """
    Adds a LUD-16 lightning address local-part to wallets.
    """
    await db.execute("ALTER TABLE wallets ADD COLUMN lightning_address TEXT")
    logger.debug("Creating index idx_wallets_lightning_address...")
    await db.execute("""
        CREATE UNIQUE INDEX IF NOT EXISTS idx_wallets_lightning_address
        ON wallets (lightning_address);
        """)


async def m051_create_installation_mode_table(db: Connection):
    await db.execute("""
        CREATE TABLE IF NOT EXISTS installation_mode (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            mode TEXT NOT NULL CHECK (
                mode IN ('custodial', 'arkade_noncustodial')
            )
        )
        """)


async def m052_create_arkade_account_bindings_table(db: Connection):
    await db.execute(f"""
        CREATE TABLE IF NOT EXISTS arkade_account_bindings (
            account_id TEXT PRIMARY KEY REFERENCES accounts (id),
            state TEXT NOT NULL CHECK (state IN ('pending', 'ready')),
            enrollment_id TEXT NOT NULL UNIQUE,
            idempotency_key TEXT UNIQUE,
            challenge_nonce TEXT,
            challenge_expires_at TIMESTAMP,
            network TEXT NOT NULL,
            server_url TEXT NOT NULL,
            server_pubkey TEXT NOT NULL,
            identity_xonly_pubkey TEXT UNIQUE,
            backup_acknowledged_at TIMESTAMP,
            created_at TIMESTAMP NOT NULL DEFAULT {db.timestamp_now},
            updated_at TIMESTAMP NOT NULL DEFAULT {db.timestamp_now},
            ready_at TIMESTAMP,
            CHECK (
                (state = 'pending' AND identity_xonly_pubkey IS NULL
                 AND backup_acknowledged_at IS NULL AND ready_at IS NULL)
                OR
                (state = 'ready' AND identity_xonly_pubkey IS NOT NULL
                 AND backup_acknowledged_at IS NOT NULL AND ready_at IS NOT NULL
                 AND challenge_nonce IS NULL AND challenge_expires_at IS NULL)
            ),
            CHECK (
                (challenge_nonce IS NULL AND challenge_expires_at IS NULL)
                OR (challenge_nonce IS NOT NULL AND challenge_expires_at IS NOT NULL)
            )
        )
        """)


async def m053_create_arkade_receive_tables(db: Connection):
    """Public receive mappings and restart-safe indexer evidence."""
    await db.execute(f"""
        CREATE TABLE IF NOT EXISTS arkade_receive_requests (
            native_request_id TEXT PRIMARY KEY,
            account_id TEXT NOT NULL REFERENCES accounts (id),
            wallet_id TEXT NOT NULL REFERENCES wallets (id),
            idempotency_key TEXT NOT NULL,
            amount_sat {db.big_int} NOT NULL
                CHECK (amount_sat > 0 AND amount_sat <= 2100000000000000),
            "index" INT CHECK ("index" >= 0 AND "index" <= 2147483647),
            address TEXT,
            script TEXT,
            child_xonly_pubkey TEXT,
            network TEXT NOT NULL,
            server_url TEXT NOT NULL,
            server_pubkey TEXT NOT NULL,
            expires_at TIMESTAMP NOT NULL,
            state TEXT NOT NULL CHECK (
                state IN ('pending', 'acknowledged', 'settled',
                          'reconciliation_required')
            ),
            settled_at TIMESTAMP,
            created_at TIMESTAMP NOT NULL DEFAULT {db.timestamp_now},
            updated_at TIMESTAMP NOT NULL DEFAULT {db.timestamp_now},
            UNIQUE (account_id, "index"),
            UNIQUE (account_id, idempotency_key),
            UNIQUE (script),
            UNIQUE (address),
            CHECK (
                (state = 'pending' AND "index" IS NULL AND address IS NULL
                 AND script IS NULL AND child_xonly_pubkey IS NULL
                )
                OR
                (state <> 'pending' AND "index" IS NOT NULL
                 AND address IS NOT NULL AND script IS NOT NULL
                 AND child_xonly_pubkey IS NOT NULL)
            )
        )
        """)
    await db.execute(f"""
        CREATE TABLE IF NOT EXISTS arkade_receive_outpoints (
            account_id TEXT NOT NULL REFERENCES accounts (id),
            native_request_id TEXT REFERENCES arkade_receive_requests
                (native_request_id),
            txid TEXT NOT NULL,
            vout {db.big_int} NOT NULL CHECK (vout >= 0 AND vout <= 4294967295),
            amount_sat {db.big_int} NOT NULL
                CHECK (amount_sat > 0 AND amount_sat <= 2100000000000000),
            script TEXT NOT NULL,
            status TEXT NOT NULL CHECK (
                status IN ('valid', 'unattributed', 'conflict')
            ),
            is_preconfirmed BOOLEAN NOT NULL DEFAULT false,
            is_spent BOOLEAN NOT NULL DEFAULT false,
            is_swept BOOLEAN NOT NULL DEFAULT false,
            spent_by TEXT,
            observed_at TIMESTAMP NOT NULL DEFAULT {db.timestamp_now},
            UNIQUE (txid, vout)
        )
        """)
    await db.execute(f"""
        CREATE TABLE IF NOT EXISTS arkade_reconciliation_state (
            account_id TEXT PRIMARY KEY REFERENCES accounts (id),
            state TEXT NOT NULL CHECK (state IN ('ok', 'reconciliation_required')),
            last_error TEXT CHECK (last_error IS NULL OR last_error IN (
                'ARKADE_OUTPOINT_CONFLICT',
                'ARKADE_UNATTRIBUTED_VALUE',
                'ARKADE_RECEIVE_AMOUNT_CONFLICT',
                'ARKADE_INDEXER_INVALID_RESPONSE',
                'ARKADE_OUTPOINT_TERMINAL_CONFLICT',
                'ARKADE_RECONCILIATION_REQUIRED'
            )),
            observed_at TIMESTAMP,
            updated_at TIMESTAMP NOT NULL DEFAULT {db.timestamp_now}
        )
        """)


async def m054_add_payment_protocol_identity(db: Connection):
    """Add protocol-specific payment identity atomically."""
    async with db.transaction():
        await _m054_add_payment_protocol_identity(db)


async def _m054_add_payment_protocol_identity(
    db: Connection,
):
    """Add protocol-specific identity fields to payments."""
    if db.type != SQLITE:
        await db.execute(
            "ALTER TABLE apipayments ALTER COLUMN checking_id DROP NOT NULL"
        )
        await db.execute(
            "ALTER TABLE apipayments ADD COLUMN protocol TEXT NOT NULL "
            "DEFAULT 'lightning'"
        )
        await db.execute("ALTER TABLE apipayments ADD COLUMN native_id TEXT")
        await db.execute("ALTER TABLE apipayments ADD COLUMN arkade_address TEXT")
        await db.execute(
            "UPDATE apipayments SET native_id = checking_id "
            "WHERE protocol = 'lightning'"
        )
        await db.execute("""
            ALTER TABLE apipayments ADD CONSTRAINT apipayments_protocol_identity
            CHECK (
                (protocol = 'lightning' AND checking_id IS NOT NULL
                 AND arkade_address IS NULL)
                OR
                (protocol = 'arkade' AND native_id IS NOT NULL
                 AND checking_id IS NULL AND bolt11 IS NULL
                 AND payment_hash IS NULL)
            )
        """)
        await db.execute("""
            CREATE UNIQUE INDEX idx_payments_arkade_native_id
            ON apipayments (native_id)
            WHERE protocol = 'arkade' AND native_id IS NOT NULL
        """)
        return

    # SQLite cannot drop NOT NULL from an existing column, so rebuild this
    # table while preserving the current payment data and indexes.
    await db.execute("DROP VIEW IF EXISTS balances")
    for index in [
        "by_hash",
        "idx_payments_wallet_id",
        "idx_payments_checking_id",
        "idx_payments_payment_hash",
        "idx_payments_amount",
        "idx_payments_fee",
        "idx_payments_labels",
        "idx_payments_time",
        "idx_payments_status",
        "idx_payments_memo",
        "idx_payments_created_at",
        "idx_payments_updated_at",
        "idx_payments_external_id",
    ]:
        await db.execute(f"DROP INDEX IF EXISTS {index}")

    await db.execute(f"""
        CREATE TABLE apipayments_new (
            checking_id TEXT,
            amount {db.big_int} NOT NULL,
            fee INTEGER NOT NULL DEFAULT 0,
            wallet_id TEXT NOT NULL,
            memo TEXT,
            time TIMESTAMP NOT NULL DEFAULT {db.timestamp_now},
            payment_hash TEXT,
            preimage TEXT,
            bolt11 TEXT,
            extra TEXT,
            webhook TEXT,
            webhook_status TEXT,
            expiry TIMESTAMP,
            status TEXT DEFAULT 'pending',
            tag TEXT,
            extension TEXT,
            created_at TIMESTAMP,
            updated_at TIMESTAMP,
            fiat_provider TEXT,
            labels TEXT,
            external_id TEXT,
            protocol TEXT NOT NULL DEFAULT 'lightning'
                CHECK (protocol IN ('lightning', 'arkade')),
            native_id TEXT,
            arkade_address TEXT,
            UNIQUE (wallet_id, checking_id),
            CHECK (
                (protocol = 'lightning' AND checking_id IS NOT NULL
                 AND arkade_address IS NULL)
                OR
                (protocol = 'arkade' AND native_id IS NOT NULL
                 AND checking_id IS NULL AND bolt11 IS NULL
                 AND payment_hash IS NULL)
            )
        )
    """)
    await db.execute("""
        INSERT INTO apipayments_new (
            checking_id, amount, fee, wallet_id, memo, time, payment_hash,
            preimage, bolt11, extra, webhook, webhook_status, expiry, status,
            tag, extension, created_at, updated_at, fiat_provider, labels,
            external_id, protocol, native_id, arkade_address
        )
        SELECT checking_id, amount, fee, wallet_id, memo, time, payment_hash,
               preimage, bolt11, extra, webhook, webhook_status, expiry, status,
               tag, extension, created_at, updated_at, fiat_provider, labels,
               external_id, 'lightning', checking_id, NULL
        FROM apipayments
    """)
    await db.execute("DROP TABLE apipayments")
    await db.execute("ALTER TABLE apipayments_new RENAME TO apipayments")

    for index in [
        "wallet_id",
        "checking_id",
        "payment_hash",
        "amount",
        "fee",
        "labels",
        "time",
        "status",
        "memo",
        "created_at",
        "updated_at",
        "external_id",
    ]:
        await db.execute(f"CREATE INDEX idx_payments_{index} ON apipayments ({index})")
    await db.execute("CREATE INDEX by_hash ON apipayments (payment_hash)")
    await db.execute("""
        CREATE UNIQUE INDEX idx_payments_arkade_native_id
        ON apipayments (native_id)
        WHERE protocol = 'arkade' AND native_id IS NOT NULL
    """)
    await db.execute("""
        CREATE VIEW balances AS
        SELECT apipayments.wallet_id,
               SUM(apipayments.amount - ABS(apipayments.fee)) AS balance
        FROM wallets
        LEFT JOIN apipayments ON apipayments.wallet_id = wallets.id
        WHERE (wallets.deleted = false OR wallets.deleted is NULL)
        AND (
            (apipayments.status = 'success' AND apipayments.amount > 0)
            OR (apipayments.status IN ('success', 'pending') AND apipayments.amount < 0)
        )
        GROUP BY apipayments.wallet_id
    """)


async def m055_create_arkade_outgoing_tables(db: Connection):
    """Store browser-authorized Arkade outgoing intent state and input claims."""
    await db.execute(f"""
        CREATE TABLE IF NOT EXISTS arkade_outgoing_intents (
            intent_id TEXT PRIMARY KEY,
            account_id TEXT NOT NULL REFERENCES accounts (id),
            wallet_id TEXT NOT NULL REFERENCES wallets (id),
            amount_msat {db.big_int} NOT NULL CHECK (
                amount_msat > 0 AND amount_msat / 1000 * 1000 = amount_msat
            ),
            max_fee_msat {db.big_int} NOT NULL CHECK (max_fee_msat = 0),
            destination TEXT NOT NULL,
            destination_kind TEXT NOT NULL CHECK (destination_kind = 'arkade_address'),
            status TEXT NOT NULL DEFAULT 'reserved' CHECK (
                status IN ('reserved', 'submitted', 'settled', 'released', 'disputed')
            ),
            arkade_txid TEXT,
            actual_fee_msat {db.big_int},
            expires_at TIMESTAMP NOT NULL,
            created_at TIMESTAMP NOT NULL DEFAULT {db.timestamp_now},
            updated_at TIMESTAMP NOT NULL DEFAULT {db.timestamp_now},
            reserved_at TIMESTAMP NOT NULL DEFAULT {db.timestamp_now},
            submitted_at TIMESTAMP,
            settled_at TIMESTAMP,
            released_at TIMESTAMP,
            disputed_at TIMESTAMP,
            CHECK (actual_fee_msat IS NULL OR actual_fee_msat >= 0),
            CHECK (
                actual_fee_msat IS NULL OR actual_fee_msat <= max_fee_msat
            ),
            CHECK (expires_at > reserved_at)
        )
        """)
    await db.execute(f"""
        CREATE TABLE IF NOT EXISTS arkade_outgoing_intent_inputs (
            intent_id TEXT NOT NULL REFERENCES arkade_outgoing_intents (intent_id),
            txid TEXT NOT NULL,
            vout {db.big_int} NOT NULL CHECK (vout >= 0 AND vout <= 4294967295),
            amount_sat {db.big_int} NOT NULL
                CHECK (amount_sat > 0 AND amount_sat <= 2100000000000000),
            claimed_at TIMESTAMP NOT NULL DEFAULT {db.timestamp_now},
            PRIMARY KEY (intent_id, txid, vout),
            UNIQUE (txid, vout)
        )
        """)
    await db.execute(
        "CREATE INDEX IF NOT EXISTS idx_arkade_outgoing_intents_account_status "
        "ON arkade_outgoing_intents (account_id, status)"
    )
    await db.execute(
        "CREATE INDEX IF NOT EXISTS idx_arkade_outgoing_intents_wallet_status "
        "ON arkade_outgoing_intents (wallet_id, status)"
    )


async def m056_add_arkade_account_descriptor(db: Connection):
    """Store the enrolled account's watch-only Arkade descriptor."""
    await db.execute(
        "ALTER TABLE arkade_account_bindings ADD COLUMN identity_descriptor TEXT"
    )
    await db.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS "
        "idx_arkade_account_bindings_identity_descriptor "
        "ON arkade_account_bindings (identity_descriptor)"
    )


async def m057_add_arkade_outgoing_outputs(db: Connection):
    """Store the exact public output contract committed by the browser."""
    for column, definition in (
        ("destination_script", "TEXT"),
        ("change_index", f"{db.big_int}"),
        ("change_script", "TEXT"),
        ("change_amount_sat", f"{db.big_int}"),
    ):
        await db.execute(
            f"ALTER TABLE arkade_outgoing_intents ADD COLUMN {column} {definition}"
        )
    await db.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS "
        "idx_arkade_outgoing_change_account_index "
        "ON arkade_outgoing_intents (account_id, change_index) "
        "WHERE change_index IS NOT NULL"
    )
    await db.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_arkade_outgoing_change_script "
        "ON arkade_outgoing_intents (change_script) "
        "WHERE change_script IS NOT NULL"
    )


async def m058_add_arkade_lightning_quote_fields(db: Connection):
    """Extend outgoing intents with the browser-validated Lightning quote binding."""
    await db.execute(f"""
        CREATE TABLE arkade_outgoing_intents_new (
            intent_id TEXT PRIMARY KEY,
            account_id TEXT NOT NULL REFERENCES accounts (id),
            wallet_id TEXT NOT NULL REFERENCES wallets (id),
            amount_msat {db.big_int} NOT NULL CHECK (
                amount_msat > 0 AND amount_msat / 1000 * 1000 = amount_msat
            ),
            max_fee_msat {db.big_int} NOT NULL CHECK (
                (destination_kind = 'arkade_address' AND max_fee_msat = 0)
                OR (destination_kind = 'lightning' AND max_fee_msat > 0)
            ),
            destination TEXT NOT NULL,
            destination_kind TEXT NOT NULL CHECK (
                destination_kind IN ('arkade_address', 'lightning')
            ),
            status TEXT NOT NULL DEFAULT 'reserved' CHECK (
                status IN (
                    'reserved', 'quote_ready', 'submitted', 'settled',
                    'refunded', 'released', 'disputed'
                )
            ),
            bolt11 TEXT,
            payment_hash TEXT,
            quote_pair TEXT,
            quote_from_amount_sat {db.big_int},
            quote_to_amount_sat {db.big_int},
            quote_valid_until TIMESTAMP,
            refund_locktime {db.big_int},
            solver_pubkey TEXT,
            swap_rfq_id TEXT,
            lockup_address TEXT,
            arkade_txid TEXT,
            settlement_ark_txid TEXT,
            refund_ark_txid TEXT,
            actual_fee_msat {db.big_int},
            expires_at TIMESTAMP NOT NULL,
            created_at TIMESTAMP NOT NULL DEFAULT {db.timestamp_now},
            updated_at TIMESTAMP NOT NULL DEFAULT {db.timestamp_now},
            reserved_at TIMESTAMP NOT NULL DEFAULT {db.timestamp_now},
            submitted_at TIMESTAMP,
            settled_at TIMESTAMP,
            released_at TIMESTAMP,
            disputed_at TIMESTAMP,
            destination_script TEXT,
            change_index {db.big_int},
            change_script TEXT,
            change_amount_sat {db.big_int},
            CHECK (actual_fee_msat IS NULL OR actual_fee_msat >= 0),
            CHECK (actual_fee_msat IS NULL OR actual_fee_msat <= max_fee_msat),
            CHECK (expires_at > reserved_at)
        )
    """)
    await db.execute(f"""
        CREATE TABLE arkade_outgoing_intent_inputs_backup (
            intent_id TEXT NOT NULL,
            txid TEXT NOT NULL,
            vout {db.big_int} NOT NULL,
            amount_sat {db.big_int} NOT NULL,
            claimed_at TIMESTAMP NOT NULL,
            PRIMARY KEY (intent_id, txid, vout),
            UNIQUE (txid, vout)
        )
    """)
    await db.execute("""
        INSERT INTO arkade_outgoing_intent_inputs_backup
            (intent_id, txid, vout, amount_sat, claimed_at)
        SELECT intent_id, txid, vout, amount_sat, claimed_at
        FROM arkade_outgoing_intent_inputs
    """)
    await db.execute("""
        INSERT INTO arkade_outgoing_intents_new (
            intent_id, account_id, wallet_id, amount_msat, max_fee_msat,
            destination, destination_kind, status, bolt11, payment_hash,
            quote_pair, quote_from_amount_sat, quote_to_amount_sat,
            quote_valid_until, refund_locktime, solver_pubkey, swap_rfq_id,
            lockup_address, arkade_txid, actual_fee_msat, expires_at,
            created_at, updated_at, reserved_at, submitted_at, settled_at,
            released_at, disputed_at, destination_script, change_index,
            change_script, change_amount_sat
        )
        SELECT intent_id, account_id, wallet_id, amount_msat, max_fee_msat,
               destination, destination_kind, status, NULL, NULL, NULL, NULL,
               NULL, NULL, NULL, NULL, NULL, NULL, arkade_txid,
               actual_fee_msat, expires_at, created_at, updated_at, reserved_at,
               submitted_at, settled_at, released_at, disputed_at,
               destination_script, change_index, change_script, change_amount_sat
        FROM arkade_outgoing_intents
    """)
    await db.execute("DROP TABLE arkade_outgoing_intent_inputs")
    await db.execute("DROP TABLE arkade_outgoing_intents")
    await db.execute(
        "ALTER TABLE arkade_outgoing_intents_new RENAME TO arkade_outgoing_intents"
    )
    await db.execute(f"""
        CREATE TABLE arkade_outgoing_intent_inputs (
            intent_id TEXT NOT NULL REFERENCES arkade_outgoing_intents (intent_id),
            txid TEXT NOT NULL,
            vout {db.big_int} NOT NULL CHECK (vout >= 0 AND vout <= 4294967295),
            amount_sat {db.big_int} NOT NULL
                CHECK (amount_sat > 0 AND amount_sat <= 2100000000000000),
            claimed_at TIMESTAMP NOT NULL DEFAULT {db.timestamp_now},
            PRIMARY KEY (intent_id, txid, vout),
            UNIQUE (txid, vout)
        )
    """)
    await db.execute("""
        INSERT INTO arkade_outgoing_intent_inputs
            (intent_id, txid, vout, amount_sat, claimed_at)
        SELECT intent_id, txid, vout, amount_sat, claimed_at
        FROM arkade_outgoing_intent_inputs_backup
    """)
    await db.execute("DROP TABLE arkade_outgoing_intent_inputs_backup")

    for index in (
        "CREATE INDEX IF NOT EXISTS idx_arkade_outgoing_intents_account_status "
        "ON arkade_outgoing_intents (account_id, status)",
        "CREATE INDEX IF NOT EXISTS idx_arkade_outgoing_intents_wallet_status "
        "ON arkade_outgoing_intents (wallet_id, status)",
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_arkade_outgoing_payment_hash "
        "ON arkade_outgoing_intents (payment_hash) "
        "WHERE destination_kind = 'lightning' AND payment_hash IS NOT NULL",
        "CREATE INDEX IF NOT EXISTS idx_arkade_outgoing_solver_pubkey "
        "ON arkade_outgoing_intents (solver_pubkey)",
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_arkade_outgoing_swap_rfq_id "
        "ON arkade_outgoing_intents (swap_rfq_id) "
        "WHERE swap_rfq_id IS NOT NULL",
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_arkade_outgoing_lockup_address "
        "ON arkade_outgoing_intents (lockup_address) "
        "WHERE lockup_address IS NOT NULL",
        "CREATE INDEX IF NOT EXISTS idx_arkade_outgoing_status_refund_locktime "
        "ON arkade_outgoing_intents (status, refund_locktime)",
        "CREATE UNIQUE INDEX IF NOT EXISTS "
        "idx_arkade_outgoing_change_account_index "
        "ON arkade_outgoing_intents (account_id, change_index) "
        "WHERE change_index IS NOT NULL",
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_arkade_outgoing_change_script "
        "ON arkade_outgoing_intents (change_script) "
        "WHERE change_script IS NOT NULL",
    ):
        await db.execute(index)


async def m059_create_arkade_lightning_terminal_events(db: Connection):
    """Persist Lightning terminal notifications for restart-safe delivery."""
    await db.execute(f"""
        CREATE TABLE IF NOT EXISTS arkade_lightning_terminal_events (
            event_id TEXT PRIMARY KEY
                REFERENCES arkade_outgoing_intents (intent_id),
            terminal_state TEXT NOT NULL CHECK (
                terminal_state IN ('settled', 'refunded', 'disputed')
            ),
            payment_payload TEXT NOT NULL,
            attempts {db.big_int} NOT NULL DEFAULT 0 CHECK (attempts >= 0),
            next_attempt_at TIMESTAMP NOT NULL DEFAULT {db.timestamp_now},
            lease_token TEXT,
            lease_until TIMESTAMP,
            listeners_delivered_at TIMESTAMP,
            webhook_delivered_at TIMESTAMP,
            created_at TIMESTAMP NOT NULL DEFAULT {db.timestamp_now}
        )
    """)
    await db.execute(
        "CREATE INDEX IF NOT EXISTS idx_arkade_lightning_terminal_events_due "
        "ON arkade_lightning_terminal_events (next_attempt_at)"
    )


async def m060_add_arkade_lightning_refund_binding(db: Connection):
    """Persist the public browser refund binding used by terminal evidence."""
    await db.execute(
        "ALTER TABLE arkade_outgoing_intents ADD COLUMN sender_pubkey TEXT"
    )
    await db.execute(
        "ALTER TABLE arkade_outgoing_intents ADD COLUMN refund_pk_script TEXT"
    )


async def m061_add_arkade_lightning_failed_state(db: Connection):
    """Allow failed(reason) as a terminal Lightning swap state.

    A swap whose claim was attempted and kept failing is only observable in the
    user's wallet, so the state and its reason arrive as a client report; the
    server keeps `disputed` for contradictory public evidence.
    """
    # Rebuild the terminal-event table first: it references the intents table,
    # which cannot be dropped while a referencing table exists.
    await db.execute(f"""
        CREATE TABLE arkade_lightning_terminal_events_backup (
            event_id TEXT PRIMARY KEY,
            terminal_state TEXT NOT NULL,
            payment_payload TEXT NOT NULL,
            attempts {db.big_int} NOT NULL DEFAULT 0 CHECK (attempts >= 0),
            next_attempt_at TIMESTAMP NOT NULL,
            lease_token TEXT,
            lease_until TIMESTAMP,
            listeners_delivered_at TIMESTAMP,
            webhook_delivered_at TIMESTAMP,
            created_at TIMESTAMP NOT NULL
        )
    """)
    await db.execute("""
        INSERT INTO arkade_lightning_terminal_events_backup
            (event_id, terminal_state, payment_payload, attempts, next_attempt_at,
             lease_token, lease_until, listeners_delivered_at,
             webhook_delivered_at, created_at)
        SELECT event_id, terminal_state, payment_payload, attempts,
               next_attempt_at, lease_token, lease_until,
               listeners_delivered_at, webhook_delivered_at, created_at
        FROM arkade_lightning_terminal_events
    """)
    await db.execute("DROP TABLE arkade_lightning_terminal_events")

    # Rebuild the intents table with the extended status CHECK and the reason.
    await db.execute(f"""
        CREATE TABLE arkade_outgoing_intents_new (
            intent_id TEXT PRIMARY KEY,
            account_id TEXT NOT NULL REFERENCES accounts (id),
            wallet_id TEXT NOT NULL REFERENCES wallets (id),
            amount_msat {db.big_int} NOT NULL CHECK (
                amount_msat > 0 AND amount_msat / 1000 * 1000 = amount_msat
            ),
            max_fee_msat {db.big_int} NOT NULL CHECK (
                (destination_kind = 'arkade_address' AND max_fee_msat = 0)
                OR (destination_kind = 'lightning' AND max_fee_msat > 0)
            ),
            destination TEXT NOT NULL,
            destination_kind TEXT NOT NULL CHECK (
                destination_kind IN ('arkade_address', 'lightning')
            ),
            status TEXT NOT NULL DEFAULT 'reserved' CHECK (
                status IN (
                    'reserved', 'quote_ready', 'submitted', 'settled',
                    'refunded', 'failed', 'released', 'disputed'
                )
            ),
            bolt11 TEXT,
            payment_hash TEXT,
            quote_pair TEXT,
            quote_from_amount_sat {db.big_int},
            quote_to_amount_sat {db.big_int},
            quote_valid_until TIMESTAMP,
            refund_locktime {db.big_int},
            solver_pubkey TEXT,
            swap_rfq_id TEXT,
            lockup_address TEXT,
            arkade_txid TEXT,
            settlement_ark_txid TEXT,
            refund_ark_txid TEXT,
            actual_fee_msat {db.big_int},
            expires_at TIMESTAMP NOT NULL,
            created_at TIMESTAMP NOT NULL DEFAULT {db.timestamp_now},
            updated_at TIMESTAMP NOT NULL DEFAULT {db.timestamp_now},
            reserved_at TIMESTAMP NOT NULL DEFAULT {db.timestamp_now},
            submitted_at TIMESTAMP,
            settled_at TIMESTAMP,
            failed_at TIMESTAMP,
            failure_reason TEXT,
            released_at TIMESTAMP,
            disputed_at TIMESTAMP,
            destination_script TEXT,
            change_index {db.big_int},
            change_script TEXT,
            change_amount_sat {db.big_int},
            sender_pubkey TEXT,
            refund_pk_script TEXT,
            CHECK (actual_fee_msat IS NULL OR actual_fee_msat >= 0),
            CHECK (actual_fee_msat IS NULL OR actual_fee_msat <= max_fee_msat),
            CHECK (expires_at > reserved_at),
            CHECK (
                status <> 'failed'
                OR (failed_at IS NOT NULL AND failure_reason IS NOT NULL)
            )
        )
    """)
    await db.execute(f"""
        CREATE TABLE arkade_outgoing_intent_inputs_backup (
            intent_id TEXT NOT NULL,
            txid TEXT NOT NULL,
            vout {db.big_int} NOT NULL,
            amount_sat {db.big_int} NOT NULL,
            claimed_at TIMESTAMP NOT NULL,
            PRIMARY KEY (intent_id, txid, vout),
            UNIQUE (txid, vout)
        )
    """)
    await db.execute("""
        INSERT INTO arkade_outgoing_intent_inputs_backup
            (intent_id, txid, vout, amount_sat, claimed_at)
        SELECT intent_id, txid, vout, amount_sat, claimed_at
        FROM arkade_outgoing_intent_inputs
    """)
    await db.execute("""
        INSERT INTO arkade_outgoing_intents_new (
            intent_id, account_id, wallet_id, amount_msat, max_fee_msat,
            destination, destination_kind, status, bolt11, payment_hash,
            quote_pair, quote_from_amount_sat, quote_to_amount_sat,
            quote_valid_until, refund_locktime, solver_pubkey, swap_rfq_id,
            lockup_address, arkade_txid, settlement_ark_txid,
            refund_ark_txid, actual_fee_msat, expires_at, created_at,
            updated_at, reserved_at, submitted_at, settled_at, failed_at,
            failure_reason, released_at, disputed_at, destination_script,
            change_index, change_script, change_amount_sat, sender_pubkey,
            refund_pk_script
        )
        SELECT intent_id, account_id, wallet_id, amount_msat, max_fee_msat,
               destination, destination_kind, status, bolt11, payment_hash,
               quote_pair, quote_from_amount_sat, quote_to_amount_sat,
               quote_valid_until, refund_locktime, solver_pubkey, swap_rfq_id,
               lockup_address, arkade_txid, settlement_ark_txid,
               refund_ark_txid, actual_fee_msat, expires_at, created_at,
               updated_at, reserved_at, submitted_at, settled_at, NULL,
               NULL, released_at, disputed_at, destination_script,
               change_index, change_script, change_amount_sat, sender_pubkey,
               refund_pk_script
        FROM arkade_outgoing_intents
    """)
    await db.execute("DROP TABLE arkade_outgoing_intent_inputs")
    await db.execute("DROP TABLE arkade_outgoing_intents")
    await db.execute(
        "ALTER TABLE arkade_outgoing_intents_new RENAME TO arkade_outgoing_intents"
    )
    await db.execute(f"""
        CREATE TABLE arkade_outgoing_intent_inputs (
            intent_id TEXT NOT NULL REFERENCES arkade_outgoing_intents (intent_id),
            txid TEXT NOT NULL,
            vout {db.big_int} NOT NULL CHECK (vout >= 0 AND vout <= 4294967295),
            amount_sat {db.big_int} NOT NULL
                CHECK (amount_sat > 0 AND amount_sat <= 2100000000000000),
            claimed_at TIMESTAMP NOT NULL DEFAULT {db.timestamp_now},
            PRIMARY KEY (intent_id, txid, vout),
            UNIQUE (txid, vout)
        )
    """)
    await db.execute("""
        INSERT INTO arkade_outgoing_intent_inputs
            (intent_id, txid, vout, amount_sat, claimed_at)
        SELECT intent_id, txid, vout, amount_sat, claimed_at
        FROM arkade_outgoing_intent_inputs_backup
    """)
    await db.execute("DROP TABLE arkade_outgoing_intent_inputs_backup")

    for index in (
        "CREATE INDEX IF NOT EXISTS idx_arkade_outgoing_intents_account_status "
        "ON arkade_outgoing_intents (account_id, status)",
        "CREATE INDEX IF NOT EXISTS idx_arkade_outgoing_intents_wallet_status "
        "ON arkade_outgoing_intents (wallet_id, status)",
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_arkade_outgoing_payment_hash "
        "ON arkade_outgoing_intents (payment_hash) "
        "WHERE destination_kind = 'lightning' AND payment_hash IS NOT NULL",
        "CREATE INDEX IF NOT EXISTS idx_arkade_outgoing_solver_pubkey "
        "ON arkade_outgoing_intents (solver_pubkey)",
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_arkade_outgoing_swap_rfq_id "
        "ON arkade_outgoing_intents (swap_rfq_id) "
        "WHERE swap_rfq_id IS NOT NULL",
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_arkade_outgoing_lockup_address "
        "ON arkade_outgoing_intents (lockup_address) "
        "WHERE lockup_address IS NOT NULL",
        "CREATE INDEX IF NOT EXISTS idx_arkade_outgoing_status_refund_locktime "
        "ON arkade_outgoing_intents (status, refund_locktime)",
        "CREATE UNIQUE INDEX IF NOT EXISTS "
        "idx_arkade_outgoing_change_account_index "
        "ON arkade_outgoing_intents (account_id, change_index) "
        "WHERE change_index IS NOT NULL",
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_arkade_outgoing_change_script "
        "ON arkade_outgoing_intents (change_script) "
        "WHERE change_script IS NOT NULL",
    ):
        await db.execute(index)

    await db.execute(f"""
        CREATE TABLE arkade_lightning_terminal_events (
            event_id TEXT PRIMARY KEY
                REFERENCES arkade_outgoing_intents (intent_id),
            terminal_state TEXT NOT NULL CHECK (
                terminal_state IN ('settled', 'refunded', 'failed', 'disputed')
            ),
            payment_payload TEXT NOT NULL,
            attempts {db.big_int} NOT NULL DEFAULT 0 CHECK (attempts >= 0),
            next_attempt_at TIMESTAMP NOT NULL DEFAULT {db.timestamp_now},
            lease_token TEXT,
            lease_until TIMESTAMP,
            listeners_delivered_at TIMESTAMP,
            webhook_delivered_at TIMESTAMP,
            created_at TIMESTAMP NOT NULL DEFAULT {db.timestamp_now}
        )
    """)
    await db.execute("""
        INSERT INTO arkade_lightning_terminal_events
            (event_id, terminal_state, payment_payload, attempts, next_attempt_at,
             lease_token, lease_until, listeners_delivered_at,
             webhook_delivered_at, created_at)
        SELECT event_id, terminal_state, payment_payload, attempts,
               next_attempt_at, lease_token, lease_until,
               listeners_delivered_at, webhook_delivered_at, created_at
        FROM arkade_lightning_terminal_events_backup
    """)
    await db.execute("DROP TABLE arkade_lightning_terminal_events_backup")
    await db.execute(
        "CREATE INDEX IF NOT EXISTS idx_arkade_lightning_terminal_events_due "
        "ON arkade_lightning_terminal_events (next_attempt_at)"
    )


async def m062_extend_arkade_reconciliation_errors(db: Connection):
    """Admit the Lightning terminal codes into the reconciliation error set.

    `last_error` is a fixed code enum, so the client-reported swap reason stays
    on the intent (`failure_reason`) and the account flag carries a code.
    """
    await db.execute(f"""
        CREATE TABLE arkade_reconciliation_state_new (
            account_id TEXT PRIMARY KEY REFERENCES accounts (id),
            state TEXT NOT NULL CHECK (state IN ('ok', 'reconciliation_required')),
            last_error TEXT CHECK (last_error IS NULL OR last_error IN (
                'ARKADE_OUTPOINT_CONFLICT',
                'ARKADE_UNATTRIBUTED_VALUE',
                'ARKADE_RECEIVE_AMOUNT_CONFLICT',
                'ARKADE_INDEXER_INVALID_RESPONSE',
                'ARKADE_OUTPOINT_TERMINAL_CONFLICT',
                'ARKADE_RECONCILIATION_REQUIRED',
                'ARKADE_LIGHTNING_SWAP_FAILED',
                'ARKADE_LIGHTNING_EVIDENCE_CONTRADICTORY'
            )),
            observed_at TIMESTAMP,
            updated_at TIMESTAMP NOT NULL DEFAULT {db.timestamp_now}
        )
    """)
    await db.execute("""
        INSERT INTO arkade_reconciliation_state_new
            (account_id, state, last_error, observed_at, updated_at)
        SELECT account_id, state, last_error, observed_at, updated_at
        FROM arkade_reconciliation_state
    """)
    await db.execute("DROP TABLE arkade_reconciliation_state")
    await db.execute(
        "ALTER TABLE arkade_reconciliation_state_new "
        "RENAME TO arkade_reconciliation_state"
    )


async def m063_arkade_outgoing_retryable_invoice(db: Connection):
    """Only a live intent holds an invoice's payment_hash.

    The unique index used to cover every intent, so a released, refunded or
    failed attempt kept the invoice unusable forever.
    """
    await db.execute("DROP INDEX IF EXISTS idx_arkade_outgoing_payment_hash")
    await db.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_arkade_outgoing_payment_hash "
        "ON arkade_outgoing_intents (payment_hash) "
        "WHERE destination_kind = 'lightning' AND payment_hash IS NOT NULL "
        "AND status IN ('reserved', 'quote_ready', 'submitted', 'disputed', "
        "'settled')"
    )


async def m064_arkade_maintenance(db: Connection):
    await db.execute("""
        CREATE TABLE arkade_maintenance (
            operation_id TEXT PRIMARY KEY,
            account_id TEXT NOT NULL REFERENCES accounts(id),
            plan_json TEXT NOT NULL,
            script TEXT NOT NULL UNIQUE,
            amount_sat BIGINT NOT NULL CHECK (amount_sat > 0),
            state TEXT NOT NULL CHECK (state IN ('planned', 'verified')),
            output_txid TEXT,
            output_vout INTEGER,
            UNIQUE (output_txid, output_vout)
        )
    """)
    await db.execute("""
        CREATE TABLE arkade_maintenance_inputs (
            txid TEXT NOT NULL,
            vout INTEGER NOT NULL,
            operation_id TEXT NOT NULL REFERENCES arkade_maintenance(operation_id),
            PRIMARY KEY (txid, vout)
        )
    """)
    await db.execute(
        "CREATE UNIQUE INDEX idx_arkade_maintenance_pending "
        "ON arkade_maintenance (account_id) WHERE state = 'planned'"
    )
