import os
import sys
import subprocess
import requests
import geoip2.database
import logging
import json
import pandas as pd
import tkinter as tk
from tkinter import messagebox, filedialog, ttk
import csv
from typing import List, Dict, Any

# API Keys and Database URLs
API_KEYS = {
    'ipinfo': '5a09f3d1f03715',
    'ipstack': '6224df9c0c0e3cc8f80be8d79e7d094b'
}

COUNTRY_ASN_DB_URL = f'https://ipinfo.io/data/free/country_asn.mmdb?token={API_KEYS["ipinfo"]}'
COUNTRY_ASN_CSV_URL = f'https://ipinfo.io/data/free/country_asn.csv.gz?token={API_KEYS["ipinfo"]}'
COUNTRY_ASN_JSON_URL = f'https://ipinfo.io/data/free/country_asn.json.gz?token={API_KEYS["ipinfo"]}'
COUNTRY_ASN_DB_PATH = 'data/country_asn.mmdb'
COUNTRY_ASN_CSV_PATH = 'data/country_asn.csv.gz'
COUNTRY_ASN_JSON_PATH = 'data/country_asn.json.gz'
EXTRACTED_CSV_PATH = 'data/country_asn.csv'
EXTRACTED_JSON_PATH = 'data/country_asn.json'

REQUIRED_PACKAGES = [
    'requests',
    'geoip2',
    'pandas',
    'tk',
]

def install_and_log_packages(packages: List[str]) -> None:
    """Installs and logs the installation of required packages.

    This function checks if a list of specified Python packages is already installed.
    If a package is not installed, it attempts to install it using pip.
    All actions are logged.

    Args:
        packages (List[str]): A list of package names to be installed.
    """
    for package in packages:
        try:
            __import__(package)
            logging.info(f"Package '{package}' is already installed.")
        except ImportError:
            logging.info(f"Package '{package}' not found. Installing...")
            subprocess.check_call([sys.executable, '-m', 'pip', 'install', package])
            logging.info(f"Package '{package}' installed successfully.")

def download_file(url: str, output_path: str) -> None:
    """Downloads a file from a URL and saves it to a specified path.

    This function sends a GET request to the specified URL and saves the response
    content to a local file. It creates the output directory if it does not
    already exist. Errors during download or file saving are logged.

    Args:
        url (str): The URL of the file to download.
        output_path (str): The path where the downloaded file will be saved.
    """
    try:
        response = requests.get(url)
        response.raise_for_status()
        directory = os.path.dirname(output_path)
        if directory:
            os.makedirs(directory, exist_ok=True)
        with open(output_path, 'wb') as file:
            file.write(response.content)
        logging.info(f"Downloaded file from {url} to {output_path}")
    except requests.exceptions.RequestException as e:
        logging.error(f"Failed to download file from {url}. Error: {e}")
    except OSError as e:
        logging.error(f"Failed to create directory for {output_path}. Error: {e}")

def download_country_asn_db() -> None:
    """Downloads the Country ASN MMDB file if it doesn't already exist.

    This function checks for the existence of the 'data' directory and creates it
    if it's missing. It then checks if the Country ASN MMDB file exists and,
    if not, downloads it from the specified URL.
    """
    if not os.path.exists('data'):
        os.makedirs('data')
    
    if not os.path.exists(COUNTRY_ASN_DB_PATH):
        try:
            download_file(COUNTRY_ASN_DB_URL, COUNTRY_ASN_DB_PATH)
        except Exception as e:
            logging.error(f"Failed to download MMDB file: {e}")
    else:
        logging.info("Country + ASN database already exists.")

def download_country_asn_csv() -> None:
    """Downloads the Country ASN CSV file if it doesn't already exist.

    This function ensures the 'data' directory exists, creating it if necessary.
    It then checks for the presence of the Country ASN CSV file and downloads it
    if it is not found.
    """
    if not os.path.exists('data'):
        os.makedirs('data')
    
    if not os.path.exists(COUNTRY_ASN_CSV_PATH):
        try:
            download_file(COUNTRY_ASN_CSV_URL, COUNTRY_ASN_CSV_PATH)
        except Exception as e:
            logging.error(f"Failed to download CSV file: {e}")
    else:
        logging.info("Country + ASN CSV already exists.")

def download_country_asn_json() -> None:
    """Downloads the Country ASN JSON file if it doesn't already exist.

    This function ensures the 'data' directory exists, creating it if necessary.
    It then checks for the presence of the Country ASN JSON file and downloads it
    if it is not found.
    """
    if not os.path.exists('data'):
        os.makedirs('data')
    
    if not os.path.exists(COUNTRY_ASN_JSON_PATH):
        try:
            download_file(COUNTRY_ASN_JSON_URL, COUNTRY_ASN_JSON_PATH)
        except Exception as e:
            logging.error(f"Failed to download JSON file: {e}")
    else:
        logging.info("Country + ASN JSON already exists.")

def fetch_country_asn_details(ip_address: str) -> Dict[str, Any]:
    """Fetches country and ASN details for a given IP address.

    This function attempts to retrieve country and ASN information for a specific
    IP address. It prioritizes using a local MMDB database file. If the
    database is unavailable, it falls back to using pre-extracted CSV or JSON
    files.

    Args:
        ip_address (str): The IP address to look up.

    Returns:
        Dict[str, Any]: A dictionary containing the country and ASN details,
        or an empty dictionary if the lookup fails across all available data
        sources.
    """
    try:
        if os.path.exists(COUNTRY_ASN_DB_PATH):
            reader = geoip2.database.Reader(COUNTRY_ASN_DB_PATH)
            response = reader.asn(ip_address)
            country_response = reader.country(ip_address)
            reader.close()
            logging.info(f"Fetched details from MMDB for IP: {ip_address}")
            return {
                'ASN': response.autonomous_system_number,
                'ASN Org': response.autonomous_system_organization,
                'Country': country_response.country.name,
                'Country ISO Code': country_response.country.iso_code
            }
        elif os.path.exists(EXTRACTED_CSV_PATH):
            return fetch_country_asn_details_from_csv(ip_address)
        elif os.path.exists(EXTRACTED_JSON_PATH):
            return fetch_country_asn_details_from_json(ip_address)
        else:
            logging.error("No valid data source available for Country + ASN details.")
            return {}
    except Exception as e:
        logging.error(f"Error fetching Country + ASN details for IP: {ip_address}. Error: {e}")
        return {}

def fetch_country_asn_details_from_csv(ip_address: str) -> Dict[str, Any]:
    """Fetches country and ASN details from the extracted CSV file.

    This function reads a CSV file to find a matching IP address and returns the
    corresponding details. It assumes the first column of the CSV is the IP
    address.

    Args:
        ip_address (str): The IP address to look up.

    Returns:
        Dict[str, Any]: A dictionary containing the details from the CSV row,
        or an empty dictionary if the IP address is not found or the file is
        empty.
    """
    with open(EXTRACTED_CSV_PATH, 'r') as file:
        reader = csv.reader(file)
        try:
            headers = next(reader)
        except StopIteration:
            return {}  # Empty file
        for values in reader:
            if values and values[0] == ip_address:
                logging.info(f"Fetched details from CSV for IP: {ip_address}")
                return dict(zip(headers, values))
    return {}

def fetch_country_asn_details_from_json(ip_address: str) -> Dict[str, Any]:
    """Fetches country and ASN details from the extracted JSON file.

    This function loads a JSON file and looks up the details for a given IP
    address, which is expected to be a key in the JSON object.

    Args:
        ip_address (str): The IP address to look up.

    Returns:
        Dict[str, Any]: A dictionary containing the details associated with the
        IP address, or an empty dictionary if the IP is not found in the JSON
        data.
    """
    with open(EXTRACTED_JSON_PATH, 'r') as file:
        data = json.load(file)
        if ip_address in data:
            logging.info(f"Fetched details from JSON for IP: {ip_address}")
            return data[ip_address]
        else:
            return {}

def extract_gzip(file_path: str, output_path: str) -> None:
    """Extracts a GZIP file to a specified output path.

    This function first validates the existence and format of the input GZIP file.
    It then uses the 'gunzip' command to decompress the file and write the
    output to the specified path.

    Args:
        file_path (str): The path to the GZIP file.
        output_path (str): The path to save the extracted file.
    """
    if not os.path.exists(file_path):
        logging.error(f"File {file_path} does not exist.")
        return
    if not os.path.isfile(file_path):
        logging.error(f"Path {file_path} is not a file.")
        return

    with open(file_path, 'rb') as file:
        if file.read(2) != b'\x1f\x8b':
            logging.error(f"File {file_path} is not in gzip format.")
            return

    command = f"gunzip -c {file_path} > {output_path}"
    try:
        subprocess.run(command, shell=True, check=True)
        logging.info(f"Extracted {file_path} to {output_path}")
    except subprocess.CalledProcessError as e:
        logging.error(f"Failed to extract {file_path}. Error: {e}")

def fetch_ipinfo_details(ip_address: str) -> Dict[str, Any]:
    """Fetches IP details from the IPinfo API.

    This function sends a request to the IPinfo API to retrieve details for a
    given IP address. It includes an API token for authentication.

    Args:
        ip_address (str): The IP address to look up.

    Returns:
        Dict[str, Any]: A dictionary containing the IP details, or an empty
        dictionary if the request fails.
    """
    url = f'https://ipinfo.io/{ip_address}/json?token={API_KEYS["ipinfo"]}'
    try:
        response = requests.get(url)
        response.raise_for_status()
        logging.info(f"Fetched details from IPinfo for IP: {ip_address}")
        return response.json()
    except requests.exceptions.RequestException as e:
        logging.error(f"IPinfo: Error fetching details for IP: {ip_address}. Error: {e}")
        return {}

def fetch_ipstack_details(ip_address: str, hostname: int = 0, security: int = 0, fields: str = None, language: str = None, output_format: str = 'json') -> Dict[str, Any]:
    """Fetches IP details from the IPstack API.

    This function constructs a URL to query the IPstack API, including the
    API access key and optional parameters. It then sends a GET request and
    returns the JSON response.

    Args:
        ip_address (str): The IP address to look up.
        hostname (int, optional): Whether to include hostname information.
            Defaults to 0.
        security (int, optional): Whether to include security information.
            Defaults to 0.
        fields (str, optional): Specific fields to request. Defaults to None.
        language (str, optional): The language for the response.
            Defaults to None.
        output_format (str, optional): The output format for the response.
            Defaults to 'json'.

    Returns:
        Dict[str, Any]: A dictionary containing the IP details, or an empty
        dictionary if the request fails.
    """
    url = f'http://api.ipstack.com/{ip_address}?access_key={API_KEYS["ipstack"]}&hostname={hostname}&security={security}&output={output_format}'
    if fields:
        url += f'&fields={fields}'
    if language:
        url += f'&language={language}'
    
    try:
        response = requests.get(url)
        response.raise_for_status()
        logging.info(f"Fetched details from IPstack for IP: {ip_address}")
        return response.json()
    except requests.exceptions.RequestException as e:
        logging.error(f"IPStack: Error fetching details for IP: {ip_address}. Error: {e}")
        return {}

def fetch_asn_details(asn: str) -> Dict[str, Any]:
    """Fetches ASN details from the IPinfo API.

    This function queries the IPinfo API for details about a specific
    Autonomous System Number (ASN). It includes an API token for authentication.

    Args:
        asn (str): The ASN to look up.

    Returns:
        Dict[str, Any]: A dictionary containing the ASN details, or an empty
        dictionary if the request fails.
    """
    url = f'https://ipinfo.io/{asn}/json?token={API_KEYS["ipinfo"]}'
    try:
        response = requests.get(url)
        response.raise_for_status()
        logging.info(f"Fetched details from IPinfo for ASN: {asn}")
        return response.json()
    except requests.exceptions.RequestException as e:
        logging.error(f"IPinfo: Error fetching details for ASN: {asn}. Error: {e}")
        return {}

def setup_logging() -> None:
    """Sets up logging for the application.

    This function configures the logging for the application, creating a 'logs'
    directory if it doesn't exist. Log messages are saved to a file named
    'ip_location_finder.log' within this directory, with a specified format.
    """
    log_directory = "logs"
    try:
        os.makedirs(log_directory, exist_ok=True)
        logging.basicConfig(filename=f'{log_directory}/ip_location_finder.log', level=logging.INFO,
                            format='%(asctime)s - %(levelname)s - %(message)s')
        logging.info("Logging initialized.")
    except OSError as e:
        logging.error(f"Failed to create log directory. Error: {e}")

def download_using_curl(url: str, output_path: str) -> None:
    """Downloads a file using the curl command.

    This function executes the 'curl' command in a subprocess to download a file
    from a given URL and save it to a specified local path.

    Args:
        url (str): The URL of the file to download.
        output_path (str): The path to save the downloaded file.
    """
    command = f"curl -L {url} -o {output_path}"
    try:
        subprocess.run(command, shell=True, check=True)
        logging.info(f"Downloaded file from {url} to {output_path}")
    except subprocess.CalledProcessError as e:
        logging.error(f"Failed to download file from {url}. Error: {e}")

def filter_country_from_csv(input_csv: str, country_code: str, output_csv: str) -> None:
    """Filters data for a specific country from a CSV file.

    This function uses shell commands to filter a CSV file based on a country
    code. It preserves the header of the input CSV and includes all rows
    that contain the specified country code.

    Args:
        input_csv (str): The path to the input CSV file.
        country_code (str): The country code to filter by.
        output_csv (str): The path to save the filtered CSV file.
    """
    if not os.path.exists(input_csv):
        logging.error(f"Input CSV file {input_csv} does not exist.")
        return
    if not os.path.isfile(input_csv):
        logging.error(f"Path {input_csv} is not a file.")
        return
    command = f"(head -1 {input_csv}; grep ',{country_code},' {input_csv}) > {output_csv}"
    try:
        subprocess.run(command, shell=True, check=True)
        logging.info(f"Filtered {country_code} data to {output_csv}")
    except subprocess.CalledProcessError as e:
        logging.error(f"Failed to filter {country_code} data from {input_csv}. Error: {e}")

def filter_multiple_countries(input_csv: str, countries_file: str, output_csv: str) -> None:
    """Filters data for multiple countries from a CSV file.

    This function uses shell commands, including 'grep', to filter rows from a
    CSV file based on a list of country codes provided in a separate file.
    The header of the input CSV is retained in the output.

    Args:
        input_csv (str): The path to the input CSV file.
        countries_file (str): A file containing a list of country codes to
            filter by.
        output_csv (str): The path to save the filtered CSV file.
    """
    if not os.path.exists(input_csv):
        logging.error(f"Input CSV file {input_csv} does not exist.")
        return
    if not os.path.isfile(input_csv):
        logging.error(f"Path {input_csv} is not a file.")
        return
    if not os.path.exists(countries_file):
        logging.error(f"Countries file {countries_file} does not exist.")
        return
    if not os.path.isfile(countries_file):
        logging.error(f"Path {countries_file} is not a file.")
        return
    command = f"(head -1 {input_csv}; grep -f {countries_file} {input_csv}) > {output_csv}"
    try:
        subprocess.run(command, shell=True, check=True)
        logging.info(f"Filtered multiple countries data to {output_csv}")
    except subprocess.CalledProcessError as e:
        logging.error(f"Failed to filter multiple countries data from {input_csv}. Error: {e}")

def display_ipinfo_data(data: Dict[str, Any]) -> str:
    """Formats IPinfo data for display.

    This function takes a dictionary of IP details from the IPinfo service and
    formats it into a human-readable string. It includes various sections like
    basic location, ASN, privacy, carrier, company, domains, and abuse info.

    Args:
        data (Dict[str, Any]): A dictionary containing IP details from IPinfo.

    Returns:
        str: A formatted string of the IP details.
    """
    result = ""
    if 'ip' in data:
        result += f"IP: {data['ip']}\n"
    if 'hostname' in data:
        result += f"Hostname: {data['hostname']}\n"
    if 'city' in data:
        result += f"City: {data['city']}\n"
    if 'region' in data:
        result += f"Region: {data['region']}\n"
    if 'country' in data:
        result += f"Country: {data['country']}\n"
    if 'loc' in data:
        result += f"Location: {data['loc']}\n"
    if 'org' in data:
        result += f"Organization: {data['org']}\n"
    if 'postal' in data:
        result += f"Postal Code: {data['postal']}\n"
    if 'timezone' in data:
        result += f"Timezone: {data['timezone']}\n"
    if 'asn' in data:
        result += f"ASN: {data['asn']['asn']}\n"
        result += f"ASN Name: {data['asn']['name']}\n"
        result += f"ASN Domain: {data['asn']['domain']}\n"
        result += f"ASN Route: {data['asn']['route']}\n"
        result += f"ASN Type: {data['asn']['type']}\n"
    if 'privacy' in data:
        result += f"VPN: {data['privacy']['vpn']}\n"
        result += f"Proxy: {data['privacy']['proxy']}\n"
        result += f"Tor: {data['privacy']['tor']}\n"
        result += f"Relay: {data['privacy']['relay']}\n"
        result += f"Hosting: {data['privacy']['hosting']}\n"
    if 'carrier' in data:
        result += f"Carrier Name: {data['carrier']['name']}\n"
        result += f"Carrier MCC: {data['carrier']['mcc']}\n"
        result += f"Carrier MNC: {data['carrier']['mnc']}\n"
    if 'company' in data:
        result += f"Company Name: {data['company']['name']}\n"
        result += f"Company Domain: {data['company']['domain']}\n"
        result += f"Company Type: {data['company']['type']}\n"
    if 'domains' in data:
        result += f"Total Domains: {data['domains']['total']}\n"
        result += "Domains: " + ", ".join(data['domains']['domains'][:5]) + "\n"
    if 'abuse' in data:
        result += f"Abuse Contact Name: {data['abuse']['name']}\n"
        result += f"Abuse Contact Network: {data['abuse']['network']}\n"
        result += f"Abuse Contact Email: {data['abuse']['email']}\n"
        result += f"Abuse Contact Phone: {data['abuse']['phone']}\n"
        result += f"Abuse Contact Address: {data['abuse']['address']}\n"
    if 'bogon' in data:
        result += f"Bogon: {data['bogon']}\n"
    if 'anycast' in data:
        result += f"Anycast: {data['anycast']}\n"
    return result

def display_asn_data(data: Dict[str, Any]) -> str:
    """Formats ASN data for display.

    This function takes a dictionary of ASN details and formats it into a
    human-readable string, including information about prefixes for both IPv4
    and IPv6.

    Args:
        data (Dict[str, Any]): A dictionary containing ASN details.

    Returns:
        str: A formatted string of the ASN details.
    """
    result = f"ASN: {data['asn']}\n"
    result += f"Name: {data['name']}\n"
    result += f"Country: {data['country']}\n"
    result += f"Allocated: {data['allocated']}\n"
    result += f"Registry: {data['registry']}\n"
    result += f"Domain: {data['domain']}\n"
    result += f"Number of IPs: {data['num_ips']}\n"
    result += f"Type: {data['type']}\n"
    result += "Prefixes:\n"
    for prefix in data['prefixes']:
        result += f"  Netblock: {prefix['netblock']}, ID: {prefix['id']}, Name: {prefix['name']}, Country: {prefix['country']}\n"
    result += "IPv6 Prefixes:\n"
    for prefix6 in data['prefixes6']:
        result += f"  Netblock: {prefix6['netblock']}, ID: {prefix6['id']}, Name: {prefix6['name']}, Country: {prefix6['country']}\n"
    return result

def perform_ip_lookup(ip_addresses: str) -> List[Dict[str, Any]]:
    """Performs an IP lookup for a list of IP addresses.

    This function takes a string of IP addresses, parses them, and then fetches
    details for each one. It aggregates data from multiple sources, including
    local databases and online APIs.

    Args:
        ip_addresses (str): A string of IP addresses separated by commas, tabs,
            or newlines.

    Returns:
        List[Dict[str, Any]]: A list of dictionaries, each containing details
        for an IP address. If a lookup fails, the dictionary will contain an
        error message.
    """
    ip_list = [ip.strip() for ip in ip_addresses.replace(',', ' ').replace('\t', ' ').replace('\n', ' ').split()]
    results = []
    for ip in ip_list:
        country_asn_data = fetch_country_asn_details(ip)
        data = fetch_ipinfo_details(ip)
        if not data:
            data = fetch_ipstack_details(ip)
        if data:
            if country_asn_data:
                data.update(country_asn_data)
            results.append(data)
        else:
            results.append({'ip': ip, 'error': 'Failed to retrieve IP information from all sources.'})
    return results

def perform_asn_lookup(asn: str) -> List[Dict[str, Any]]:
    """Performs an ASN lookup.

    This function fetches details for a given ASN from the IPinfo API.

    Args:
        asn (str): The ASN to look up.

    Returns:
        List[Dict[str, Any]]: A list containing a dictionary of ASN details,
        or an error message if the lookup fails.
    """
    data = fetch_asn_details(asn)
    if data:
        return [data]
    else:
        return [{'asn': asn, 'error': 'Failed to retrieve details for ASN.'}]

def save_to_file(data: List[Dict[str, Any]], file_path: str) -> None:
    """Saves a list of dictionaries to a CSV file.

    This function takes a list of dictionaries and saves it as a CSV file at
    the specified path. It uses pandas to create a DataFrame and then writes
    it to CSV format. The output directory is created if it does not exist.

    Args:
        data (List[Dict[str, Any]]): The data to save.
        file_path (str): The path to the output CSV file.
    """
    columns = ['IP', 'Hostname', 'City', 'Region', 'Country', 'Location', 'Organization', 'Postal Code', 'Timezone']
    lowercase_to_columns = {
        'ip': 'IP',
        'hostname': 'Hostname',
        'city': 'City',
        'region': 'Region',
        'country': 'Country',
        'loc': 'Location',
        'org': 'Organization',
        'postal': 'Postal Code',
        'timezone': 'Timezone',
    }

    normalised_rows: List[Dict[str, Any]] = []
    for entry in data:
        row: Dict[str, Any] = {}
        if not isinstance(entry, dict):
            for column in columns:
                row[column] = None
            normalised_rows.append(row)
            continue

        for lowercase_key, column_name in lowercase_to_columns.items():
            if column_name in entry:
                row[column_name] = entry.get(column_name)
            else:
                row[column_name] = entry.get(lowercase_key)
        normalised_rows.append(row)

    df = pd.DataFrame(normalised_rows, columns=columns)
    try:
        directory = os.path.dirname(file_path)
        if directory:
            os.makedirs(directory, exist_ok=True)
        df.to_csv(file_path, index=False)
        logging.info(f"Results saved to {file_path}")
    except OSError as e:
        logging.error(f"Failed to create directory for {file_path}. Error: {e}")
    except Exception as e:
        logging.error(f"Failed to save results to {file_path}. Error: {e}")

class IPFinderApp(tk.Tk):
    """The main application class for the IP Location Finder.

    This class initializes the main Tkinter window and sets up the GUI for the
    IP Location Finder application. It handles user interactions, such as input
    for IP addresses or ASNs, and displays the lookup results.

    Attributes:
        option_var (tk.StringVar): A Tkinter variable to hold the selected
            lookup type ('IP Address' or 'ASN').
        tree (ttk.Treeview): The treeview widget used to display lookup results.
    """
    def __init__(self):
        """Initializes the main application window and sets up its components.

        This constructor sets the title and size of the main window and then
        calls the `create_widgets` method to build the user interface.
        """
        super().__init__()
        self.title("IP Location Finder")
        self.geometry("800x600")
        
        self.create_widgets()
        
    def create_widgets(self) -> None:
        """Creates and arranges the widgets in the main window.

        This method sets up all the GUI elements, including labels, radio buttons
        for lookup type selection, a text input area, a lookup button, a results
        display area, and a save button.
        """
        self.label = tk.Label(self, text="Select Lookup Type:")
        self.label.pack(pady=10)

        self.option_var = tk.StringVar(value="1")
        self.ip_radiobutton = tk.Radiobutton(self, text="IP Address", variable=self.option_var, value="1")
        self.ip_radiobutton.pack(pady=5)
        self.asn_radiobutton = tk.Radiobutton(self, text="ASN", variable=self.option_var, value="2")
        self.asn_radiobutton.pack(pady=5)
        
        self.input_label = tk.Label(self, text="Enter the IP addresses or ASN to look up (comma, tab, or newline separated):")
        self.input_label.pack(pady=10)
        
        self.input_text = tk.Text(self, height=5, width=70)
        self.input_text.pack(pady=5)
        
        self.lookup_button = tk.Button(self, text="Look Up", command=self.lookup)
        self.lookup_button.pack(pady=20)
        
        self.result_frame = tk.Frame(self)
        self.result_frame.pack(pady=10, fill='both', expand=True)
        
        self.tree = ttk.Treeview(self.result_frame, columns=('IP', 'Hostname', 'City', 'Region', 'Country', 'Location', 'Organization', 'Postal Code', 'Timezone'), show='headings')
        for col in self.tree['columns']:
            self.tree.heading(col, text=col)
            self.tree.column(col, width=100)
        self.tree.pack(fill='both', expand=True)
        
        self.save_csv_button = tk.Button(self, text="Save as CSV", command=self.save_results)
        self.save_csv_button.pack(side='left', padx=10, pady=10)
        
    def lookup(self) -> None:
        """Handles the lookup button click event.

        It retrieves the user input, performs the selected lookup (IP or ASN), and displays the results in the treeview.
        """
        option = self.option_var.get()
        input_value = self.input_text.get("1.0", tk.END)
        
        if option == '1':
            results = perform_ip_lookup(input_value)
        elif option == '2':
            results = perform_asn_lookup(input_value.strip())
        else:
            messagebox.showerror("Error", "Invalid option. Please select IP lookup or ASN lookup.")
            return
        
        self.tree.delete(*self.tree.get_children())
        
        for result in results:
            self.tree.insert("", "end", values=(result.get('ip', ''),
                                                result.get('hostname', ''),
                                                result.get('city', ''),
                                                result.get('region', ''),
                                                result.get('country', ''),
                                                result.get('loc', ''),
                                                result.get('org', ''),
                                                result.get('postal', ''),
                                                result.get('timezone', '')))
        
    def save_results(self) -> None:
        """Handles the 'Save as CSV' button click event.

        Opens a file dialog for the user to select a save location and then saves the results to a CSV file.
        """
        file_path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV files", "*.csv")])
        if not file_path:
            return

        data = [
            {col: self.tree.item(item, "values")[i] for i, col in enumerate(self.tree["columns"])}
            for item in self.tree.get_children()
        ]
        try:
            save_to_file(data, file_path)
            messagebox.showinfo("Success", f"Results saved successfully to {file_path}.")
        except Exception as e:
            logging.error(f"Failed to save results. Error: {e}")
            messagebox.showerror("Error", f"Failed to save results. Error: {e}")

def main() -> None:
    """The main entry point of the application.

    This function initializes the application by setting up logging, installing
    any required packages, and downloading necessary data files. It then creates
    an instance of the IPFinderApp and starts the Tkinter main loop.
    """
    setup_logging()
    logging.info("Data source: IPinfo (https://ipinfo.io)")
    install_and_log_packages(REQUIRED_PACKAGES)
    
    download_country_asn_db()
    if not os.path.exists(COUNTRY_ASN_DB_PATH):
        logging.info("Falling back to CSV and JSON files.")
        download_country_asn_csv()
        extract_gzip(COUNTRY_ASN_CSV_PATH, EXTRACTED_CSV_PATH)
        if not os.path.exists(EXTRACTED_CSV_PATH):
            download_country_asn_json()
            extract_gzip(COUNTRY_ASN_JSON_PATH, EXTRACTED_JSON_PATH)
    
    app = IPFinderApp()
    app.mainloop()

if __name__ == '__main__':
    main()
