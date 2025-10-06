import os
import unittest
from unittest.mock import patch, mock_open, MagicMock
import requests
import subprocess
import pandas as pd
from ip_location_finder import (
    download_file, save_to_file, extract_gzip, fetch_country_asn_details, COUNTRY_ASN_DB_PATH,
    EXTRACTED_CSV_PATH, EXTRACTED_JSON_PATH
)

class TestIPLocationFinder(unittest.TestCase):
    """Unit tests for the IP Location Finder application."""

    @patch('ip_location_finder.requests.get')
    def test_download_file(self, mock_get):
        """Tests the download_file function."""
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
        """Tests the save_to_file function."""
        data = [{'IP': '127.0.0.1', 'Hostname': 'localhost'}]
        file_path = 'output/ip_lookup_results.csv'

        save_to_file(data, file_path)

        mock_makedirs.assert_called_once_with(os.path.dirname(file_path), exist_ok=True)
        mock_to_csv.assert_called_once()
        mock_to_csv.assert_called_with(file_path, index=False)

    @patch('ip_location_finder.os.path.isfile', return_value=True)
    @patch('ip_location_finder.os.path.exists', return_value=True)
    @patch('ip_location_finder.subprocess.run')
    @patch('builtins.open', new_callable=mock_open, read_data=b'\x1f\x8b')
    def test_extract_gzip(self, mock_file, mock_run, mock_exists, mock_isfile):
        """Tests the extract_gzip function."""
        input_path = "test_input.gz"
        output_path = "test_output.txt"
        
        extract_gzip(input_path, output_path)
        
        mock_file.assert_called_once_with(input_path, 'rb')
        mock_run.assert_called_once_with(f"gunzip -c {input_path} > {output_path}", shell=True, check=True)

    @patch('ip_location_finder.os.path.exists')
    @patch('ip_location_finder.geoip2.database.Reader')
    def test_fetch_country_asn_details(self, mock_reader, mock_exists):
        """Tests the fetch_country_asn_details function."""
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

    # New tests for save_to_file function
    def setUp(self):
        """Set up test data and output file."""
        self.test_data = [
            {'IP': '1.1.1.1', 'Hostname': 'one.one.one.one', 'City': 'Some City', 'Region': 'Some Region', 'Country': 'Some Country', 'Location': '1.1,1.1', 'Organization': 'Some Org', 'Postal Code': '12345', 'Timezone': 'Some/Timezone'},
            {'IP': '2.2.2.2', 'Hostname': 'two.two.two.two', 'City': 'Another City', 'Region': 'Another Region', 'Country': 'Another Country', 'Location': '2.2,2.2', 'Organization': 'Another Org', 'Postal Code': '67890', 'Timezone': 'Another/Timezone'}
        ]
        self.output_file = 'test_output/ip_lookup_results.csv'
        os.makedirs(os.path.dirname(self.output_file), exist_ok=True)

    def tearDown(self):
        """Clean up created files and directories."""
        if os.path.exists(self.output_file):
            os.remove(self.output_file)
        if os.path.exists(os.path.dirname(self.output_file)):
            os.rmdir(os.path.dirname(self.output_file))

    def test_save_to_file_creates_file(self):
        """Tests if save_to_file creates an output file."""
        save_to_file(self.test_data, self.output_file)
        self.assertTrue(os.path.exists(self.output_file))

    def test_save_to_file_correct_columns(self):
        """Tests if the saved CSV file has the correct columns."""
        save_to_file(self.test_data, self.output_file)
        df = pd.read_csv(self.output_file)
        expected_columns = ['IP', 'Hostname', 'City', 'Region', 'Country', 'Location', 'Organization', 'Postal Code', 'Timezone']
        self.assertEqual(list(df.columns), expected_columns)

    def test_save_to_file_correct_data(self):
        """Tests if the saved CSV file contains the correct data."""
        save_to_file(self.test_data, self.output_file)
        df = pd.read_csv(self.output_file)
        self.assertEqual(df.iloc[0]['IP'], '1.1.1.1')
        self.assertEqual(df.iloc[1]['IP'], '2.2.2.2')

    def test_save_to_file_empty_data(self):
        """Tests saving empty data to a CSV file."""
        save_to_file([], self.output_file)
        df = pd.read_csv(self.output_file)
        self.assertTrue(df.empty)

    def test_save_to_file_malformed_data(self):
        """Tests saving malformed data to a CSV file."""
        malformed_data = [{'IP': '1.1.1.1'}, {'Hostname': 'two.two.two.two'}]
        save_to_file(malformed_data, self.output_file)
        df = pd.read_csv(self.output_file)
        self.assertTrue('IP' in df.columns)
        self.assertTrue('Hostname' in df.columns)
        self.assertEqual(df.iloc[0]['IP'], '1.1.1.1')
        self.assertTrue(pd.isna(df.iloc[0]['Hostname']))
        self.assertEqual(df.iloc[1]['Hostname'], 'two.two.two.two')
        self.assertTrue(pd.isna(df.iloc[1]['IP']))

    def test_save_to_file_invalid_data_types(self):
        """Tests saving data with invalid types to a CSV file."""
        invalid_data = [{'IP': 12345, 'Hostname': 67890}]
        save_to_file(invalid_data, self.output_file)
        df = pd.read_csv(self.output_file)
        self.assertEqual(df.iloc[0]['IP'], 12345.0)
        self.assertEqual(df.iloc[0]['Hostname'], 67890.0)

if __name__ == '__main__':
    unittest.main()
