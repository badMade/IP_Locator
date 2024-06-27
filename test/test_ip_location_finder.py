import os
import unittest
from unittest.mock import patch, mock_open, MagicMock
import requests
import subprocess
from ip_location_finder import (
    download_file, save_to_file, extract_gzip, fetch_country_asn_details, COUNTRY_ASN_DB_PATH,
    EXTRACTED_CSV_PATH, EXTRACTED_JSON_PATH
)

class TestIPLocationFinder(unittest.TestCase):

    @patch('ip_location_finder.requests.get')
    def test_download_file(self, mock_get):
        url = "https://example.com/file"
        output_path = "test_output/test_file"
        mock_get.return_value = MagicMock(status_code=200, content=b'file content')

        download_file(url, output_path)

        mock_get.assert_called_once_with(url)
        self.assertTrue(os.path.exists(output_path))
        with open(output_path, 'rb') as file:
            self.assertEqual(file.read(), b'file content')
        
        if os.path.exists("test_output"):
            os.remove(output_path)
            os.rmdir("test_output")

    @patch('ip_location_finder.os.makedirs')
    @patch('ip_location_finder.pd.DataFrame.to_csv')
    def test_save_to_file(self, mock_to_csv, mock_makedirs):
        data = [{'IP': '127.0.0.1', 'Hostname': 'localhost'}]
        file_path = 'output/ip_lookup_results.csv'

        save_to_file(data)

        mock_makedirs.assert_called_once_with(os.path.dirname(file_path), exist_ok=True)
        mock_to_csv.assert_called_once()
        mock_to_csv.assert_called_with(file_path, index=False)

    @patch('ip_location_finder.subprocess.run')
    @patch('builtins.open', new_callable=mock_open, read_data=b'\x1f\x8b')
    def test_extract_gzip(self, mock_file, mock_run):
        input_path = "test_input.gz"
        output_path = "test_output.txt"
        
        extract_gzip(input_path, output_path)
        
        mock_file.assert_called_once_with(input_path, 'rb')
        mock_run.assert_called_once_with(f"gunzip -c {input_path} > {output_path}", shell=True, check=True)

    @patch('ip_location_finder.os.path.exists')
    @patch('ip_location_finder.geoip2.database.Reader')
    def test_fetch_country_asn_details(self, mock_reader, mock_exists):
        mock_exists.side_effect = lambda path: path == COUNTRY_ASN_DB_PATH
        mock_reader.return_value.asn.return_value.autonomous_system_number = 12345
        mock_reader.return_value.asn.return_value.autonomous_system_organization = 'Test Org'
        mock_reader.return_value.country.return_value.country.name = 'Test Country'
        mock_reader.return_value.country.return_value.country.iso_code = 'TC'
        
        ip_address = "8.8.8.8"
        result = fetch_country_asn_details(ip_address)

        expected_result = {
            'ASN': 12345,
            'ASN Org': 'Test Org',
            'Country': 'Test Country',
            'Country ISO Code': 'TC'
        }

        self.assertEqual(result, expected_result)
        mock_reader.return_value.close.assert_called_once()

if __name__ == '__main__':
    unittest.main()
