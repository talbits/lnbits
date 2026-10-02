import asyncio
from unittest.mock import AsyncMock

import pytest

from lnbits.core import tasks
from lnbits.settings import settings


@pytest.mark.anyio
@pytest.mark.parametrize("fallback", [False, True])
async def test_events_and_timeout_run_one_serial_check(monkeypatch, fallback):
    monkeypatch.setattr(
        settings, "lnbits_effective_installation_mode", "arkade_noncustodial"
    )
    calls = AsyncMock()
    monkeypatch.setattr(tasks, "check_pending_payments", calls)
    tasks.arkade_changed.set()

    async def wait(awaitable, timeout):
        assert timeout == 30
        if fallback:
            awaitable.close()
            raise TimeoutError
        await awaitable

    async def stop(delay):
        assert 0 <= delay <= 5
        raise asyncio.CancelledError

    monkeypatch.setattr(tasks.asyncio, "wait_for", wait)
    monkeypatch.setattr(tasks.asyncio, "sleep", stop)
    with pytest.raises(asyncio.CancelledError):
        await tasks.reconcile_arkade_events()
    calls.assert_awaited_once()
    assert not tasks.arkade_changed.is_set()
