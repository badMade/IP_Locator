import os
import requests
import geoip2.database
import logging
import subprocess
import json
import tkinter as tk
from tkinter import messagebox, filedialog

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

def download_file(url, output_path):
    response = requests.get(url)
    response.raise_for_status()  # Ensure we notice bad responses
    with open(output_path, 'wb') as file:
        file.write(response.content)
    logging.info(f"Downloaded file from {url} to {output_path}")

def download_country_asn_db():
    if not os.path.exists('data'):
        os.makedirs('data')
    
    if not os.path.exists(COUNTRY_ASN_DB_PATH):
        try:
            download_file(COUNTRY_ASN_DB_URL, COUNTRY_ASN_DB_PATH)
        except Exception as e:
            logging.error(f"Failed to download MMDB file: {e}")
    else:
        logging.info("Country + ASN database already exists.")

def download_country_asn_csv():
    if not os.path.exists('data'):
        os.makedirs('data')
    
    if not os.path.exists(COUNTRY_ASN_CSV_PATH):
        try:
            download_file(COUNTRY_ASN_CSV_URL, COUNTRY_ASN_CSV_PATH)
        except Exception as e:
            logging.error(f"Failed to download CSV file: {e}")
    else:
        logging.info("Country + ASN CSV already exists.")

def download_country_asn_json():
    if not os.path.exists('data'):
        os.makedirs('data')
    
    if not os.path.exists(COUNTRY_ASN_JSON_PATH):
        try:
            download_file(COUNTRY_ASN_JSON_URL, COUNTRY_ASN_JSON_PATH)
        except Exception as e:
            logging.error(f"Failed to download JSON file: {e}")
    else:
        logging.info("Country + ASN JSON already exists.")

def fetch_country_asn_details(ip_address):
    if os.path.exists(COUNTRY_ASN_DB_PATH):
        try:
            reader = geoip2.database.Reader(COUNTRY_ASN_DB_PATH)
            response = reader.asn(ip_address)
            country_response = reader.country(ip_address)
            reader.close()
            return {
                'ASN': response.autonomous_system_number,
                'ASN Org': response.autonomous_system_organization,
                'Country': country_response.country.name,
                'Country ISO Code': country_response.country.iso_code
            }
        except Exception as e:
            logging.error(f"Error fetching Country + ASN details for IP: {ip_address}. Error: {e}")
            return None
    elif os.path.exists(EXTRACTED_CSV_PATH):
        return fetch_country_asn_details_from_csv(ip_address)
    elif os.path.exists(EXTRACTED_JSON_PATH):
        return fetch_country_asn_details_from_json(ip_address)
    else:
        logging.error("No valid data source available for Country + ASN details.")
        return None

def fetch_country_asn_details_from_csv(ip_address):
    with open(EXTRACTED_CSV_PATH, 'r') as file:
        headers = file.readline().strip().split(',')
        for line in file:
            values = line.strip().split(',')
            if values[0] == ip_address:
                return dict(zip(headers, values))
    return None

def fetch_country_asn_details_from_json(ip_address):
    with open(EXTRACTED_JSON_PATH, 'r') as file:
        data = json.load(file)
        if ip_address in data:
            return data[ip_address]
        else:
            return None

def extract_gzip(file_path, output_path):
    if not os.path.exists(file_path):
        logging.error(f"File {file_path} does not exist.")
        return
    if not os.path.isfile(file_path):
        logging.error(f"Path {file_path} is not a file.")
        return

    # Verify if the file is a valid gzip file
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

def fetch_ipinfo_details(ip_address):
    url = f'https://ipinfo.io/{ip_address}/json?token={API_KEYS["ipinfo"]}'
    try:
        response = requests.get(url)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        logging.error(f"IPinfo: Error fetching details for IP: {ip_address}. Error: {e}")
        return None

def fetch_ipstack_details(ip_address, hostname=0, security=0, fields=None, language=None, output_format='json'):
    url = f'http://api.ipstack.com/{ip_address}?access_key={API_KEYS["ipstack"]}&hostname={hostname}&security={security}&output={output_format}'
    if fields:
        url += f'&fields={fields}'
    if language:
        url += f'&language={language}'
    
    try:
        response = requests.get(url)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        logging.error(f"IPStack: Error fetching details for IP: {ip_address}. Error: {e}")
        return None

def fetch_asn_details(asn):
    url = f'https://ipinfo.io/{asn}/json?token={API_KEYS["ipinfo"]}'
    try:
        response = requests.get(url)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        logging.error(f"IPinfo: Error fetching details for ASN: {asn}. Error: {e}")
        return None

def setup_logging():
    log_directory = "logs"
    if not os.path.exists(log_directory):
        os.makedirs(log_directory)
    logging.basicConfig(filename=f'{log_directory}/ip_location_finder.log', level=logging.INFO,
                        format='%(asctime)s - %(levelname)s - %(message)s')
    logging.info("Logging initialized.")
    logging.info("Data source: IPinfo (https://ipinfo.io)")

def download_using_curl(url, output_path):
    command = f"curl -L {url} -o {output_path}"
    try:
        subprocess.run(command, shell=True, check=True)
        logging.info(f"Downloaded file from {url} to {output_path}")
    except subprocess.CalledProcessError as e:
        logging.error(f"Failed to download file from {url}. Error: {e}")

def filter_country_from_csv(input_csv, country_code, output_csv):
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

def filter_multiple_countries(input_csv, countries_file, output_csv):
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

def display_ipinfo_data(data):
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
        result += "Domains: " + ", ".join(data['domains']['domains'][:5]) + "\n"  # Display only first 5 domains
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

def display_asn_data(data):
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

def perform_ip_lookup(ip_address):
    country_asn_data = fetch_country_asn_details(ip_address)
    
    # Try IPinfo first
    data = fetch_ipinfo_details(ip_address)
    if not data:  # Fallback to IPStack if IPinfo fails
        data = fetch_ipstack_details(ip_address)
    
    if data:
        if country_asn_data:
            data.update(country_asn_data)
        return display_ipinfo_data(data)
    else:
        return "Failed to retrieve IP information from all sources."

def perform_asn_lookup(asn):
    data = fetch_asn_details(asn)
    if data:
        return display_asn_data(data)
    else:
        return f"Failed to retrieve details for ASN: {asn}"

class IPFinderApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("IP Location Finder")
        self.geometry("600x400")
        
        self.create_widgets()
        
    def create_widgets(self):
        self.label = tk.Label(self, text="Enter 1 for IP lookup, 2 for ASN lookup:")
        self.label.pack(pady=10)
        
        self.option_var = tk.StringVar()
        self.option_entry = tk.Entry(self, textvariable=self.option_var)
        self.option_entry.pack(pady=5)
        
        self.input_label = tk.Label(self, text="Enter the IP address or ASN to look up:")
        self.input_label.pack(pady=10)
        
        self.input_var = tk.StringVar()
        self.input_entry = tk.Entry(self, textvariable=self.input_var)
        self.input_entry.pack(pady=5)
        
        self.lookup_button = tk.Button(self, text="Look Up", command=self.lookup)
        self.lookup_button.pack(pady=20)
        
        self.result_text = tk.Text(self, height=10, width=70)
        self.result_text.pack(pady=10)
        
    def lookup(self):
        option = self.option_var.get()
        input_value = self.input_var.get()
        
        if option == '1':
            result = perform_ip_lookup(input_value)
        elif option == '2':
            result = perform_asn_lookup(input_value)
        else:
            result = "Invalid option. Please enter 1 for IP lookup or 2 for ASN lookup."
        
        self.result_text.delete(1.0, tk.END)
        self.result_text.insert(tk.END, result)

def main():
    setup_logging()
    logging.info("Data source: IPinfo (https://ipinfo.io)")
    
    # Attempt to download MMDB first
    download_country_asn_db()
    if not os.path.exists(COUNTRY_ASN_DB_PATH):
        logging.info("Falling back to CSV and JSON files.")
        # Attempt to download CSV if MMDB is not available
        download_country_asn_csv()
        extract_gzip(COUNTRY_ASN_CSV_PATH, EXTRACTED_CSV_PATH)
        # Attempt to download JSON if both MMDB and CSV are not available
        if not os.path.exists(EXTRACTED_CSV_PATH):
            download_country_asn_json()
            extract_gzip(COUNTRY_ASN_JSON_PATH, EXTRACTED_JSON_PATH)
    
    app = IPFinderApp()
    app.mainloop()

if __name__ == '__main__':
    main()
