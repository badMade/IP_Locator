import os
import requests
import geoip2.database
import logging
import subprocess
import json
import pandas as pd
import tkinter as tk
from tkinter import messagebox, filedialog, ttk
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

def download_file(url: str, output_path: str) -> None:
    try:
        response = requests.get(url)
        response.raise_for_status()
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        with open(output_path, 'wb') as file:
            file.write(response.content)
        logging.info(f"Downloaded file from {url} to {output_path}")
    except requests.exceptions.RequestException as e:
        logging.error(f"Failed to download file from {url}. Error: {e}")
    except OSError as e:
        logging.error(f"Failed to create directory for {output_path}. Error: {e}")

def download_country_asn_db() -> None:
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
    with open(EXTRACTED_CSV_PATH, 'r') as file:
        headers = file.readline().strip().split(',')
        for line in file:
            values = line.strip().split(',')
            if values[0] == ip_address:
                logging.info(f"Fetched details from CSV for IP: {ip_address}")
                return dict(zip(headers, values))
    return {}

def fetch_country_asn_details_from_json(ip_address: str) -> Dict[str, Any]:
    with open(EXTRACTED_JSON_PATH, 'r') as file:
        data = json.load(file)
        if ip_address in data:
            logging.info(f"Fetched details from JSON for IP: {ip_address}")
            return data[ip_address]
        else:
            return {}

def extract_gzip(file_path: str, output_path: str) -> None:
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
    log_directory = "logs"
    try:
        os.makedirs(log_directory, exist_ok=True)
        logging.basicConfig(filename=f'{log_directory}/ip_location_finder.log', level=logging.INFO,
                            format='%(asctime)s - %(levelname)s - %(message)s')
        logging.info("Logging initialized.")
    except OSError as e:
        logging.error(f"Failed to create log directory. Error: {e}")

def download_using_curl(url: str, output_path: str) -> None:
    command = f"curl -L {url} -o {output_path}"
    try:
        subprocess.run(command, shell=True, check=True)
        logging.info(f"Downloaded file from {url} to {output_path}")
    except subprocess.CalledProcessError as e:
        logging.error(f"Failed to download file from {url}. Error: {e}")

def filter_country_from_csv(input_csv: str, country_code: str, output_csv: str) -> None:
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
    data = fetch_asn_details(asn)
    if data:
        return [data]
    else:
        return [{'asn': asn, 'error': 'Failed to retrieve details for ASN.'}]

def save_to_file(data: List[Dict[str, Any]], file_path: str) -> None:
    columns = ['IP', 'Hostname', 'City', 'Region', 'Country', 'Location', 'Organization', 'Postal Code', 'Timezone']
    df = pd.DataFrame(data, columns=columns)
    try:
        os.makedirs(os.path.dirname(file_path), exist_ok=True)
        df.to_csv(file_path, index=False)
        logging.info(f"Results saved to {file_path}")
    except OSError as e:
        logging.error(f"Failed to create directory for {file_path}. Error: {e}")
    except Exception as e:
        logging.error(f"Failed to save results to {file_path}. Error: {e}")

class IPFinderApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("IP Location Finder")
        self.geometry("800x600")
        
        self.create_widgets()
        
    def create_widgets(self) -> None:
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
    setup_logging()
    logging.info("Data source: IPinfo (https://ipinfo.io)")
    
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
