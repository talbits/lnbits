from unittest.mock import AsyncMock

import pytest

from lnbits.core import tasks
from lnbits.settings import settings


@pytest.mark.anyio
@pytest.mark.parametrize("mode", ["arkade_noncustodial", "custodial"])
async def test_reconcile_runs_one_pending_check_in_arkade_mode(monkeypatch, mode):
    monkeypatch.setattr(settings, "lnbits_effective_installation_mode", mode)
    calls = AsyncMock()
    monkeypatch.setattr(tasks, "check_pending_payments", calls)

    await tasks.reconcile_arkade_events()

    if mode == "arkade_noncustodial":
        calls.assert_awaited_once()
    else:
        calls.assert_not_awaited()
