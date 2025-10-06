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

## Project Structure
- `src/ip_location_finder.py`: The main application file containing the GUI and core logic.
- `src/ip_services.py`: Contains functions for fetching data from external IP and ASN lookup services.
- `src/utils.py`: Utility functions used across the application.
- `data/`: Directory for storing data files, such as GeoIP databases.
- `logs/`: Directory for storing log files.
- `output/`: Directory for storing exported CSV files.
- `test/`: Contains unit tests for the application.

## Dependencies
The application requires the following Python packages:
- `requests`
- `geoip2`
- `pandas`
- `ipinfo`

You can install them using the `requirements.txt` file.

## Setup
1.  **Clone the repository:**
    ```sh
    git clone <repository_url>
    cd <repository_directory>
    ```

2.  **Install the required dependencies:**
    It is recommended to use a virtual environment.
    ```sh
    python -m venv venv
    source venv/bin/activate  # On Windows use `venv\Scripts\activate`
    pip install -r requirements.txt
    ```

3.  **API Keys**:
    The application uses API keys for services like IPinfo and IPstack. You will need to obtain your own API keys from the respective services.
    - **IPinfo**: Get your free API token from [ipinfo.io](https://ipinfo.io/signup).
    - **IPstack**: Get your free API key from [ipstack.com](https://ipstack.com/signup/free).

    Once you have your keys, you need to add them to the source code:
    - In `src/ip_location_finder.py`, update the `API_KEYS` dictionary.
    - In `src/ip_services.py`, update the `IPINFO_ACCESS_TOKEN` variable.

## Usage
1.  **Run the application:**
    ```sh
    python src/ip_location_finder.py
    ```
2.  **Using the GUI:**
    - On the first launch, the application will automatically download necessary data files (e.g., GeoIP database) if they are not found. This might take a moment.
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

## Contributing
Contributions are welcome! If you have suggestions for improvements or find any bugs, please open an issue or submit a pull request.

1. Fork the repository.
2. Create a new branch (`git checkout -b feature/your-feature-name`).
3. Make your changes.
4. Commit your changes (`git commit -m 'Add some feature'`).
5. Push to the branch (`git push origin feature/your-feature-name`).
6. Open a pull request.

## License
This project is licensed under the MIT License.