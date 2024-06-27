import unittest
from src.ip_services import fetch_ipinfo_details, fetch_ipapi_details, fetch_geoip2_details

class TestIPLocationFinder(unittest.TestCase):
    def setUp(self):
        self.cache = {}
        self.progress = None
        self.status_label = None
        self.root = None

    def test_fetch_ipinfo_details(self):
        ip_addresses = "8.8.8.8"
        df = fetch_ipinfo_details(ip_addresses, self.cache, self.progress, self.status_label, self.root)
        self.assertFalse(df.empty)
        self.assertIn("IP Address", df.columns)
        self.assertIn("City", df.columns)
        self.assertIn("Region", df.columns)
        self.assertIn("Country", df.columns)

    def test_fetch_ipapi_details(self):
        ip_addresses = "8.8.8.8"
        df = fetch_ipapi_details(ip_addresses, self.cache, self.progress, self.status_label, self.root)
        self.assertFalse(df.empty)
        self.assertIn("IP Address", df.columns)
        self.assertIn("City", df.columns)
        self.assertIn("Region", df.columns)
        self.assertIn("Country", df.columns)

    def test_fetch_geoip2_details(self):
        ip_addresses = "8.8.8.8"
        df = fetch_geoip2_details(ip_addresses, self.cache, self.progress, self.status_label, self.root)
        self.assertFalse(df.empty)
        self.assertIn("IP Address", df.columns)
        self.assertIn("City", df.columns)
        self.assertIn("Region", df.columns)
        self.assertIn("Country", df.columns)

if __name__ == '__main__':
    unittest.main()
