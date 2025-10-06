# IP Location Finder

## Overview
This application provides a graphical user interface (GUI) to fetch and display location details for IP addresses and Autonomous System Numbers (ASNs). It utilizes various online and local data sources to provide comprehensive information.

## Features
- **IP and ASN Lookup**: Perform lookups for single or multiple IP addresses, or a single ASN.
- **Multiple Data Sources**: Fetches data from IPinfo, IPstack, and a local GeoIP2 database for comprehensive results.
- **User-Friendly GUI**: An intuitive interface built with Tkinter for easy input and clear display of results.
- **Data Caching**: Caches results to speed up repeated queries and reduce API calls.
- **Export Results**: Save lookup results to a CSV file for further analysis.
- **Automatic Setup**: Automatically downloads required data files on first launch.

## Setup
1.  **Clone the repository:**
    ```sh
    git clone <repository_url>
    cd <repository_directory>
    ```
2.  **Install the required dependencies:**
    The application requires several Python packages. You can install them using pip and the `requirements.txt` file.
    ```sh
    pip install -r requirements.txt
    ```
3.  **API Keys**:
    The application uses API keys for services like IPinfo and IPstack. These are pre-configured in `src/ip_location_finder.py` and `src/ip_services.py`. If you wish to use your own keys, you can replace the placeholder values in the source code.

## Usage
1.  **Run the application:**
    ```sh
    python src/ip_location_finder.py
    ```
2.  **Using the GUI:**
    - On launch, the application will automatically download the necessary data files (e.g., GeoIP database) if they are not found. This might take a moment.
    - **Select Lookup Type**: Choose between "IP Address" and "ASN" lookup.
    - **Enter Input**:
        - For IP lookup, enter one or more IP addresses, separated by commas, spaces, tabs, or newlines.
        - For ASN lookup, enter a single ASN (e.g., AS15169).
    - **Look Up**: Click the "Look Up" button to fetch the details.
    - **View Results**: The results will be displayed in the table.
    - **Save Results**: Click the "Save as CSV" button to export the displayed results to a CSV file.

## Data Sources
The application aggregates data from the following sources:
- **IPinfo (ipinfo.io)**: Provides detailed IP and ASN information.
- **IPstack (ipstack.com)**: An alternative source for IP geolocation data.
- **Local GeoIP2/ASN Database**: Uses a local MMDB file for fast, offline lookups of country and ASN data.