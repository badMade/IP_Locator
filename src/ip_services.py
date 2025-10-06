import ipinfo
import requests
import geoip2.database
import pandas as pd
from requests.exceptions import RequestException
import logging
from tkinter import messagebox

# Replace 'your_access_token' with your actual access token
IPINFO_ACCESS_TOKEN = 'your_access_token'
GEOIP2_DB_PATH = 'data/GeoLite2-City.mmdb'  # Adjust this path

cache_hits = 0
cache_misses = 0

ipinfo_handler = ipinfo.getHandler(IPINFO_ACCESS_TOKEN)

def fetch_ipinfo_details(ip_addresses, cache, progress, status_label, root):
    """Fetches IP address details from the IPinfo service.

    Args:
        ip_addresses (str): A string containing IP addresses, separated by commas, tabs, or newlines.
        cache (dict): A dictionary to cache results and avoid redundant API calls.
        progress (ttk.Progressbar): The progress bar widget to update during the fetching process.
        status_label (tk.Label): The label widget to display the current status.
        root (tk.Tk): The root Tkinter window to update the UI.

    Returns:
        pd.DataFrame: A DataFrame containing the location details for the IP addresses.
    """
    global cache_hits, cache_misses
    ip_list = [ip.strip() for ip in ip_addresses.replace(',', ' ').replace('\t', ' ').replace('\n', ' ').split()]
    data = []
    total_ips = len(ip_list)
    
    for i, ip in enumerate(ip_list):
        if ip in cache:
            details = cache[ip]
            cache_hits += 1
            logging.info(f"Cache hit for IP: {ip}")
        else:
            try:
                details = ipinfo_handler.getDetails(ip)
                cache[ip] = details
                cache_misses += 1
                logging.info(f"Fetched details for IP: {ip}")
            except (RequestException, ValueError) as e:
                logging.error(f"Error fetching details for IP: {ip}. Error: {e}")
                messagebox.showerror("Error", f"Error fetching details for IP: {ip}. Error: {e}")
                continue

        data.append({
            'IP Address': ip,
            'City': details.city,
            'Region': details.region,
            'Country': details.country,
            'Postal': details.postal,
            'Timezone': details.timezone,
            'Latitude': details.latitude,
            'Longitude': details.longitude
        })
        status_label.config(text=f"Fetching details for {ip}... ({i+1}/{total_ips})")
        progress['value'] = (i + 1) / total_ips * 100
        root.update_idletasks()
        
    return pd.DataFrame(data)

def fetch_ipapi_details(ip_addresses, cache, progress, status_label, root):
    """Fetches IP address details from the IPAPI service.

    Args:
        ip_addresses (str): A string containing IP addresses, separated by commas, tabs, or newlines.
        cache (dict): A dictionary to cache results and avoid redundant API calls.
        progress (ttk.Progressbar): The progress bar widget to update during the fetching process.
        status_label (tk.Label): The label widget to display the current status.
        root (tk.Tk): The root Tkinter window to update the UI.

    Returns:
        pd.DataFrame: A DataFrame containing the location details for the IP addresses.
    """
    global cache_hits, cache_misses
    ip_list = [ip.strip() for ip in ip_addresses.replace(',', ' ').replace('\t', ' ').replace('\n', ' ').split()]
    data = []
    total_ips = len(ip_list)
    
    for i, ip in enumerate(ip_list):
        if ip in cache:
            details = cache[ip]
            cache_hits += 1
            logging.info(f"Cache hit for IP: {ip}")
        else:
            try:
                response = requests.get(f'https://ipapi.co/{ip}/json/')
                details = response.json()
                cache[ip] = details
                cache_misses += 1
                logging.info(f"Fetched details for IP: {ip}")
            except (RequestException, ValueError) as e:
                logging.error(f"Error fetching details for IP: {ip}. Error: {e}")
                messagebox.showerror("Error", f"Error fetching details for IP: {ip}. Error: {e}")
                continue

        data.append({
            'IP Address': ip,
            'City': details.get('city'),
            'Region': details.get('region'),
            'Country': details.get('country_name'),
            'Postal': details.get('postal'),
            'Timezone': details.get('timezone'),
            'Latitude': details.get('latitude'),
            'Longitude': details.get('longitude')
        })
        status_label.config(text=f"Fetching details for {ip}... ({i+1}/{total_ips})")
        progress['value'] = (i + 1) / total_ips * 100
        root.update_idletasks()
    
    return pd.DataFrame(data)

def fetch_geoip2_details(ip_addresses, cache, progress, status_label, root):
    """Fetches IP address details from a local GeoIP2 database.

    Args:
        ip_addresses (str): A string containing IP addresses, separated by commas, tabs, or newlines.
        cache (dict): A dictionary to cache results and avoid redundant database lookups.
        progress (ttk.Progressbar): The progress bar widget to update during the fetching process.
        status_label (tk.Label): The label widget to display the current status.
        root (tk.Tk): The root Tkinter window to update the UI.

    Returns:
        pd.DataFrame: A DataFrame containing the location details for the IP addresses.
    """
    global cache_hits, cache_misses
    ip_list = [ip.strip() for ip in ip_addresses.replace(',', ' ').replace('\t', ' ').replace('\n', ' ').split()]
    data = []
    total_ips = len(ip_list)
    reader = geoip2.database.Reader(GEOIP2_DB_PATH)
    
    for i, ip in enumerate(ip_list):
        if ip in cache:
            response = cache[ip]
            cache_hits += 1
            logging.info(f"Cache hit for IP: {ip}")
        else:
            try:
                response = reader.city(ip)
                cache[ip] = response
                cache_misses += 1
                logging.info(f"Fetched details for IP: {ip}")
            except (geoip2.errors.AddressNotFoundError, ValueError) as e:
                logging.error(f"Error fetching details for IP: {ip}. Error: {e}")
                messagebox.showerror("Error", f"Error fetching details for IP: {ip}. Error: {e}")
                continue

        data.append({
            'IP Address': ip,
            'City': response.city.name,
            'Region': response.subdivisions.most_specific.name,
            'Country': response.country.name,
            'Postal': response.postal.code,
            'Timezone': response.location.time_zone,
            'Latitude': response.location.latitude,
            'Longitude': response.location.longitude
        })
        status_label.config(text=f"Fetching details for {ip}... ({i+1}/{total_ips})")
        progress['value'] = (i + 1) / total_ips * 100
        root.update_idletasks()
    
    reader.close()
    return pd.DataFrame(data)
