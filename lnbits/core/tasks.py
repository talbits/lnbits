import asyncio

from loguru import logger

from lnbits.core.crud import create_audit_entry
from lnbits.core.crud.arkade_lightning_events import (
    acknowledge_arkade_lightning_terminal_event,
    claim_arkade_lightning_terminal_events,
    retry_arkade_lightning_terminal_event,
)
from lnbits.core.crud.payments import get_payments_status_count
from lnbits.core.crud.users import get_accounts
from lnbits.core.crud.wallets import get_wallet, get_wallets_count
from lnbits.core.db import db
from lnbits.core.models import Payment
from lnbits.core.models.audit import AuditEntry
from lnbits.core.models.extensions import InstallableExtension
from lnbits.core.models.notifications import NotificationType
from lnbits.core.services.funding_source import get_balance_delta
from lnbits.core.services.notifications import (
    dispatch_webhook,
    enqueue_admin_notification,
    send_payment_notification_in_background,
)
from lnbits.core.services.payments import check_pending_payments
from lnbits.db import Filters
from lnbits.settings import settings
from lnbits.task_manager import task_manager
from lnbits.utils.cache import cache
from lnbits.utils.exchange_rates import btc_price_from_aggregator, btc_rates

audit_queue: asyncio.Queue[AuditEntry] = asyncio.Queue()


async def reconcile_arkade_events():
    """Reconcile pending Arkade payments once per registered task interval.

    The reference wallet discovers Arkade activity by polling verified
    evidence. The SDK's `/v1/txs` server-sent event stream is optional and
    is not implemented by the Mutinynet server, so reconciliation must not
    depend on it.
    """
    if settings.lnbits_effective_installation_mode != "arkade_noncustodial":
        return
    await check_pending_payments()


async def dispatch_arkade_lightning_terminal_events() -> None:  # noqa: C901
    if settings.lnbits_effective_installation_mode != "arkade_noncustodial":
        return
    while True:
        async with db.connect() as connection:
            async with connection.transaction():
                events = await claim_arkade_lightning_terminal_events(
                    connection, limit=1
                )
        if not events:
            break
        event = events[0]
        if not event.lease_token:
            continue
        try:
            payment = Payment.parse_raw(event.payment_payload)
            wallet = await get_wallet(payment.wallet_id)
            if not wallet:
                raise ValueError("ARKADE_TERMINAL_EVENT_WALLET_NOT_FOUND")
            if event.listeners_delivered_at is None:
                task = send_payment_notification_in_background(
                    wallet,
                    payment,
                    strict=True,
                    include_webhook=False,
                    include_payment_alerts=event.terminal_state == "settled",
                )
                if task is None:
                    raise RuntimeError("ARKADE_TERMINAL_EVENT_NOTIFICATION_FAILED")
                await task
                if event.terminal_state == "settled":
                    for listener in tuple(task_manager.tasks):
                        # Core notifications were awaited above; do not replay them.
                        if (
                            listener.invoice_listener
                            and listener.name != "core_invoice_listener"
                        ):
                            await listener.invoice_listener(payment)
                async with db.connect() as connection:
                    async with connection.transaction():
                        if not await acknowledge_arkade_lightning_terminal_event(
                            event.event_id,
                            "listeners",
                            event.lease_token,
                            connection,
                        ):
                            raise RuntimeError("ARKADE_TERMINAL_EVENT_LEASE_LOST")
            if event.webhook_delivered_at is None:
                await dispatch_webhook(payment, strict=True)
                async with db.connect() as connection:
                    async with connection.transaction():
                        if not await acknowledge_arkade_lightning_terminal_event(
                            event.event_id,
                            "webhook",
                            event.lease_token,
                            connection,
                        ):
                            raise RuntimeError("ARKADE_TERMINAL_EVENT_LEASE_LOST")
        except Exception as exc:
            logger.warning(
                f"Arkade Lightning terminal notification failed for "
                f"{event.event_id}: {exc!s}"
            )
            async with db.connect() as connection:
                async with connection.transaction():
                    await retry_arkade_lightning_terminal_event(
                        event.event_id,
                        event.lease_token,
                        min(2 ** min(event.attempts, 16), 60 * 60),
                        connection,
                    )


async def process_next_audit_entry() -> None:
    """
    Waits for audit entries to be pushed to the queue.
    Then it inserts the entries into the DB.
    """
    data = await audit_queue.get()
    await create_audit_entry(data)


async def refresh_extension_cache() -> None:
    # only refreshes every 10 minutes
    await InstallableExtension.get_installable_extensions()


async def notify_server_status() -> None:
    accounts = await get_accounts(filters=Filters(limit=0))
    wallets_count = await get_wallets_count()
    payments = await get_payments_status_count()
    status = await get_balance_delta()
    values = {
        "up_time": settings.lnbits_server_up_time,
        "accounts_count": accounts.total,
        "wallets_count": wallets_count,
        "in_payments_count": payments.incoming,
        "out_payments_count": payments.outgoing,
        "pending_payments_count": payments.pending,
        "failed_payments_count": payments.failed,
        "delta_sats": status.delta_sats,
        "lnbits_balance_sats": status.lnbits_balance_sats,
        "node_balance_sats": status.node_balance_sats,
    }
    enqueue_admin_notification(NotificationType.server_status, values)


async def collect_exchange_rates_data() -> None:
    """
    Collect exchange rates data. Used for monitoring only.
    """
    currency = settings.lnbits_default_accounting_currency or "USD"
    max_history_size = settings.lnbits_exchange_history_size
    try:
        if (
            settings.lnbits_price_aggregator_enabled
            and settings.lnbits_price_aggregator_url
        ):
            price = await btc_price_from_aggregator(currency)
            if price:
                cache.set(
                    f"btc-price-{currency}",
                    price,
                    expiry=settings.lnbits_exchange_rate_cache_seconds,
                )
                settings.append_exchange_rate_datapoint(
                    {"Aggregator": price}, max_history_size
                )
        else:
            rates = await btc_rates(currency)
            if rates:
                rates_values = [r[1] for r in rates]
                lnbits_rate = sum(rates_values) / len(rates_values)
                rates.append(("LNbits", lnbits_rate))
                cache.set(
                    f"btc-price-{currency}",
                    lnbits_rate,
                    expiry=settings.lnbits_exchange_rate_cache_seconds,
                )
            settings.append_exchange_rate_datapoint(dict(rates), max_history_size)
    except Exception as ex:
        logger.warning(ex)
