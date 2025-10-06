"""Public package interface for IP_Locator."""

from src import (  # type: ignore[F401]
    create_tooltip,
    fetch_geoip2_details,
    fetch_ipapi_details,
    fetch_ipinfo_details,
)
from src.ip_location_finder import IPFinderApp

# Backwards compatibility alias
IPLocationFinderApp = IPFinderApp

__all__ = [
    "IPFinderApp",
    "IPLocationFinderApp",
    "create_tooltip",
    "fetch_ipinfo_details",
    "fetch_ipapi_details",
    "fetch_geoip2_details",
]
