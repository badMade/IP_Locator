from types import SimpleNamespace
import importlib.util
import pathlib
import sys

import pandas as pd
import pytest

MODULE_PATH = pathlib.Path(__file__).resolve().parents[1] / "src" / "ip_services.py"
SPEC = importlib.util.spec_from_file_location("ip_services", MODULE_PATH)
ip_services = importlib.util.module_from_spec(SPEC)
sys.modules["ip_services"] = ip_services
SPEC.loader.exec_module(ip_services)


def _dummy_widgets():
    progress = {}

    class DummyLabel:
        def __init__(self):
            self.last_config = None

        def config(self, **kwargs):
            self.last_config = kwargs

    class DummyRoot:
        def __init__(self):
            self.update_calls = 0

        def update_idletasks(self):
            self.update_calls += 1

    return progress, DummyLabel(), DummyRoot()


@pytest.fixture(autouse=True)
def reset_counters(monkeypatch):
    ip_services.cache_hits = 0
    ip_services.cache_misses = 0
    monkeypatch.setattr(ip_services.messagebox, "showerror", lambda *_, **__: None)


def test_fetch_ipinfo_details_counters_increment(monkeypatch):
    dummy_details = SimpleNamespace(
        city="City",
        region="Region",
        country="Country",
        postal="12345",
        timezone="UTC",
        latitude=1.0,
        longitude=2.0,
    )
    monkeypatch.setattr(ip_services.ipinfo_handler, "getDetails", lambda _: dummy_details)

    progress, label, root = _dummy_widgets()
    cache = {}
    result = ip_services.fetch_ipinfo_details("1.1.1.1", cache, progress, label, root)

    assert isinstance(result, pd.DataFrame)
    assert ip_services.cache_hits == 0
    assert ip_services.cache_misses == 1
    assert cache["1.1.1.1"] is dummy_details


def test_fetch_ipinfo_details_cache_hit_and_miss(monkeypatch):
    dummy_details = SimpleNamespace(
        city="City",
        region="Region",
        country="Country",
        postal="12345",
        timezone="UTC",
        latitude=1.0,
        longitude=2.0,
    )

    monkeypatch.setattr(ip_services.ipinfo_handler, "getDetails", lambda _: dummy_details)

    progress, label, root = _dummy_widgets()
    cache = {}
    result = ip_services.fetch_ipinfo_details("1.1.1.1\n1.1.1.1", cache, progress, label, root)

    assert isinstance(result, pd.DataFrame)
    assert len(result) == 2
    assert ip_services.cache_misses == 1
    assert ip_services.cache_hits == 1


def test_fetch_ipapi_details_counters_increment(monkeypatch):
    class DummyResponse:
        def json(self):
            return {
                "city": "City",
                "region": "Region",
                "country_name": "Country",
                "postal": "12345",
                "timezone": "UTC",
                "latitude": 1.0,
                "longitude": 2.0,
            }

    monkeypatch.setattr(ip_services.requests, "get", lambda _: DummyResponse())

    progress, label, root = _dummy_widgets()
    cache = {}
    result = ip_services.fetch_ipapi_details("1.1.1.1", cache, progress, label, root)

    assert isinstance(result, pd.DataFrame)
    assert ip_services.cache_hits == 0
    assert ip_services.cache_misses == 1
    assert cache["1.1.1.1"]["city"] == "City"


def test_fetch_geoip2_details_counters_increment(monkeypatch):
    class DummyGeoResponse:
        def __init__(self):
            self.city = SimpleNamespace(name="City")
            self.subdivisions = SimpleNamespace(most_specific=SimpleNamespace(name="Region"))
            self.country = SimpleNamespace(name="Country")
            self.postal = SimpleNamespace(code="12345")
            self.location = SimpleNamespace(
                time_zone="UTC",
                latitude=1.0,
                longitude=2.0,
            )

    class DummyReader:
        def __init__(self, _):
            self.closed = False

        def city(self, _):
            return DummyGeoResponse()

        def close(self):
            self.closed = True

    monkeypatch.setattr(ip_services.geoip2.database, "Reader", DummyReader)

    progress, label, root = _dummy_widgets()
    cache = {}
    result = ip_services.fetch_geoip2_details("1.1.1.1", cache, progress, label, root)

    assert isinstance(result, pd.DataFrame)
    assert ip_services.cache_hits == 0
    assert ip_services.cache_misses == 1
    assert isinstance(cache["1.1.1.1"], DummyGeoResponse)

