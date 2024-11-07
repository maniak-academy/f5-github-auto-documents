import requests
import csv
import time
import os
import sys
import urllib3
import json
import datetime
import logging
import matplotlib.pyplot as plt  # For generating the chart
from urllib.parse import quote
from collections import defaultdict

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Define variables
device_list_file = "list.txt"  # The file containing the list of BIG-IP device IPs

# Get username and password from environment variables
bigip_username = os.environ.get('BIGIP_USERNAME')
bigip_password = os.environ.get('BIGIP_PASSWORD')

if not bigip_username or not bigip_password:
    print("Error: BIGIP_USERNAME or BIGIP_PASSWORD environment variables are not set.")
    sys.exit(1)

# Read the list of devices from the file
if os.path.exists(device_list_file):
    with open(device_list_file, 'r') as f:
        bigip_addresses = [line.strip() for line in f if line.strip()]
else:
    print(f"Device list file '{device_list_file}' not found.")
    sys.exit(1)

# Generate a timestamp for the current run
timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
output_dir = f"run_{timestamp}"
overview_dir = "Overview"

# Create the timestamped folder and overview directory
os.makedirs(output_dir, exist_ok=True)
os.makedirs(overview_dir, exist_ok=True)
print(f"Created output directory: {output_dir}")
print(f"Created overview directory: {overview_dir}")

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.FileHandler(os.path.join(output_dir, "execution_log.txt")),
        logging.StreamHandler(sys.stdout)
    ]
)

logging.info(f"Script executed on: {timestamp}\n")

# Overview collection for all virtual servers
all_virtual_servers = []

# Function to authenticate and get auth token
def get_auth_token(bigip_address):
    base_uri = f"https://{bigip_address}/mgmt"
    auth_url = f"{base_uri}/shared/authn/login"
    auth_body = {
        "username": bigip_username,
        "password": bigip_password,
        "loginProviderName": "tmos"
    }
    headers = {'Content-Type': 'application/json'}
    try:
        logging.info(f"Attempting to authenticate with {bigip_address}...")
        response = requests.post(auth_url, json=auth_body, headers=headers, verify=False)
        response.raise_for_status()
        auth_response = response.json()
        logging.info(f"Authentication successful with {bigip_address}.")
        return auth_response['token']['token']
    except Exception as e:
        logging.error(f"Failed to authenticate with {bigip_address}: {e}")
        return None

# Function to logout
def logout(bigip_address, auth_token):
    base_uri = f"https://{bigip_address}/mgmt"
    logout_url = f"{base_uri}/shared/authz/logout"
    headers = {'X-F5-Auth-Token': auth_token}
    try:
        logging.info(f"Logging out from {bigip_address}...")
        requests.post(logout_url, headers=headers, verify=False)
    except Exception as e:
        logging.error(f"Logout failed for {bigip_address}: {e}")

# Function to retrieve device hostname
def get_device_hostname(bigip_address, auth_token):
    base_uri = f"https://{bigip_address}/mgmt"
    hostname_url = f"{base_uri}/tm/sys/global-settings"
    headers = {'X-F5-Auth-Token': auth_token}
    try:
        logging.info(f"Retrieving hostname from {bigip_address}...")
        response = requests.get(hostname_url, headers=headers, verify=False)
        response.raise_for_status()
        global_settings = response.json()
        hostname = global_settings.get('hostname', 'Unknown')
        logging.info(f"Hostname for {bigip_address} is {hostname}.")
        return hostname
    except Exception as e:
        logging.error(f"Failed to retrieve hostname from {bigip_address}: {e}")
        return 'Unknown'

# Dictionaries to keep track of virtual servers and pool members per device
virtual_servers_by_device = defaultdict(list)
pool_members_by_device_vs = defaultdict(lambda: defaultdict(list))
hostnames_by_device = {}
problematic_vs = []

# Iterate over the BIG-IP addresses and collect stats from each
for bigip_address in bigip_addresses:
    logging.info(f"Processing BIG-IP device at {bigip_address}...")
    auth_token = get_auth_token(bigip_address)
    if auth_token:
        base_uri = f"https://{bigip_address}/mgmt"
        headers = {'X-F5-Auth-Token': auth_token}

        # Retrieve device hostname
        hostname = get_device_hostname(bigip_address, auth_token)
        hostnames_by_device[bigip_address] = hostname

        # Retrieve virtual server list
        try:
            logging.info(f"Retrieving virtual server list from {bigip_address}...")
            vs_list_url = f"{base_uri}/tm/ltm/virtual"
            response = requests.get(vs_list_url, headers=headers, verify=False)
            response.raise_for_status()
            vs_list_response = response.json()
            time.sleep(0.2)  # Pause to prevent rate limiting
            virtual_servers = vs_list_response.get('items', [])
        except Exception as e:
            logging.error(f"Failed to retrieve virtual server list from {bigip_address}: {e}")
            logout(bigip_address, auth_token)
            continue

        for vs in virtual_servers:
            vs_name = vs['name']
            # URL-encode the virtual server name
            vs_name_encoded = quote(vs_name, safe='')

            # Log the constructed URL
            vs_config_url = f"{base_uri}/tm/ltm/virtual/{vs_name_encoded}?options=pool"
            logging.info(f"Constructed URL: {vs_config_url}")

            try:
                logging.info(f"Retrieving virtual server configuration for {vs_name}...")
                response = requests.get(vs_config_url, headers=headers, verify=False)
                response.raise_for_status()
                vs_config_response = response.json()
                time.sleep(0.2)
                pool_name = vs_config_response.get('pool', '').replace('/Common/', '')

                # Retrieve virtual server status
                vs_status_url = f"{base_uri}/tm/ltm/virtual/{vs_name_encoded}/stats"
                logging.info(f"Retrieving virtual server status for {vs_name}...")
                response = requests.get(vs_status_url, headers=headers, verify=False)
                response.raise_for_status()
                vs_status_response = response.json()
                time.sleep(0.2)

                # Extract status
                entries = vs_status_response.get('entries', {})
                vs_status_entry = next(iter(entries.values()))
                vs_status = vs_status_entry['nestedStats']['entries']['status.availabilityState']['description']

                # Extract connections and max connections
                connections = vs_status_entry['nestedStats']['entries'].get('clientside.curConns', {}).get('description', 'N/A')
                max_connections = vs_status_entry['nestedStats']['entries'].get('clientside.maxConns', {}).get('description', 'N/A')

                # Create an entry for this virtual server for the Overview files
                all_virtual_servers.append({
                    'Device': bigip_address,
                    'Hostname': hostname,
                    'VirtualServerName': vs_name,
                    'Status': vs_status,
                    'Connections': connections,
                    'MaxConnections': max_connections,
                    'Pool': pool_name or 'No Pool'
                })

            except Exception as e:
                logging.error(f"Failed to retrieve configuration or status for virtual server {vs_name} on {bigip_address}: {e}")
                # Add the problematic virtual server to the list
                problematic_vs.append({
                    'Device': bigip_address,
                    'VirtualServer': vs_name,
                    'ErrorMessage': str(e)
                })
                continue

        # Logout to invalidate the authentication token
        logout(bigip_address, auth_token)
    else:
        logging.warning(f"Skipping {bigip_address} due to authentication failure.")

# Generate the consolidated overview CSV file
overview_csv_path = os.path.join(overview_dir, "all_virtual_servers_overview.csv")
with open(overview_csv_path, 'w', newline='', encoding='utf-8') as csvfile:
    fieldnames = ['Device', 'Hostname', 'VirtualServerName', 'Status', 'Connections', 'MaxConnections', 'Pool']
    writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
    writer.writeheader()
    for vs_stat in all_virtual_servers:
        writer.writerow(vs_stat)

logging.info(f"Overview CSV file generated: {overview_csv_path}")

# Generate the chart for the top virtual servers by max connections
top_virtual_servers = sorted(all_virtual_servers, key=lambda x: int(x['MaxConnections']) if x['MaxConnections'] != 'N/A' else 0, reverse=True)[:10]
vs_names = [vs['VirtualServerName'] for vs in top_virtual_servers]
max_conns = [int(vs['MaxConnections']) if vs['MaxConnections'] != 'N/A' else 0 for vs in top_virtual_servers]

plt.figure(figsize=(10, 6))
plt.barh(vs_names, max_conns)
plt.xlabel('Max Connections')
plt.ylabel('Virtual Server Name')
plt.title('Top 10 Virtual Servers by Max Connections')
plt.gca().invert_yaxis()
chart_path = os.path.join(overview_dir, "top_virtual_servers_chart.png")
plt.savefig(chart_path)
plt.close()

logging.info(f"Chart generated and saved at {chart_path}")

# Generate the consolidated overview Markdown file with chart
overview_md_path = os.path.join(overview_dir, "all_virtual_servers_overview.md")
with open(overview_md_path, 'w', encoding='utf-8') as mdfile:
    mdfile.write("# Overview of All Virtual Servers\n\n")
    mdfile.write(f"![Top 10 Virtual Servers by Max Connections]({chart_path})\n\n")
    mdfile.write("| Device IP | Hostname | Virtual Server Name | Status | Connections | Max Connections | Pool |\n")
    mdfile.write("|-----------|----------|---------------------|--------|-------------|-----------------|------|\n")
    for vs_stat in all_virtual_servers:
        mdfile.write(f"| {vs_stat['Device']} | {vs_stat['Hostname']} | {vs_stat['VirtualServerName']} | {vs_stat['Status']} | {vs_stat['Connections']} | {vs_stat['MaxConnections']} | {vs_stat['Pool']} |\n")

logging.info(f"Overview Markdown file generated: {overview_md_path}")
logging.info("Script execution completed.")
