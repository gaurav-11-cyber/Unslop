import pytest


@pytest.fixture(autouse=True)
def _no_cache(monkeypatch):
    monkeypatch.setenv("UNSLOP_NO_CACHE", "1")   # tests must never touch ~/.cache or the network cache
