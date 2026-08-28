from pathlib import Path


def test_service_worker_only_caches_explicit_static_assets():
    source = Path("lnbits/templates/service-worker.js").read_text()

    assert "url.pathname.startsWith('/static/')" in source
    assert "url.pathname === '/favicon.ico'" in source
    assert "CURRENT_CACHE + 'static'" in source
    assert "getApiKey" not in source
    assert "'/api/'" not in source
