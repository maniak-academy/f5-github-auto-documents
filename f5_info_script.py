import requests
import csv
import time
import os
import sys
import urllib3
import json
import datetime  # New import for handling timestamps
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

# Create the timestamped folder
os.makedirs(output_dir, exist_ok=True)
print(f"Created output directory: {output_dir}")

# Optional: Initialize a log file
log_file = os.path.join(output_dir, "execution_log.txt")
with open(log_file, 'w', encoding='utf-8') as logfile:
    logfile.write(f"Script executed on: {timestamp}\n\n")

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
        print(f"Attempting to authenticate with {bigip_address}...")
        logfile.write(f"Attempting to authenticate with {bigip_address}...\n")
        response = requests.post(auth_url, json=auth_body, headers=headers, verify=False)
        response.raise_for_status()
        auth_response = response.json()
        print(f"Authentication successful with {bigip_address}.")
        logfile.write(f"Authentication successful with {bigip_address}.\n")
        return auth_response['token']['token']
    except Exception as e:
        print(f"Failed to authenticate with {bigip_address}: {e}")
        logfile.write(f"Failed to authenticate with {bigip_address}: {e}\n")
        return None

# Function to logout
def logout(bigip_address, auth_token):
    base_uri = f"https://{bigip_address}/mgmt"
    logout_url = f"{base_uri}/shared/authz/logout"
    headers = {'X-F5-Auth-Token': auth_token}
    try:
        print(f"Logging out from {bigip_address}...")
        logfile.write(f"Logging out from {bigip_address}...\n")
        requests.post(logout_url, headers=headers, verify=False)
    except Exception as e:
        print(f"Logout failed for {bigip_address}: {e}")
        logfile.write(f"Logout failed for {bigip_address}: {e}\n")

# Function to retrieve device hostname
def get_device_hostname(bigip_address, auth_token):
    base_uri = f"https://{bigip_address}/mgmt"
    hostname_url = f"{base_uri}/tm/sys/global-settings"
    headers = {'X-F5-Auth-Token': auth_token}
    try:
        print(f"Retrieving hostname from {bigip_address}...")
        logfile.write(f"Retrieving hostname from {bigip_address}...\n")
        response = requests.get(hostname_url, headers=headers, verify=False)
        response.raise_for_status()
        global_settings = response.json()
        hostname = global_settings.get('hostname', 'Unknown')
        print(f"Hostname for {bigip_address} is {hostname}.")
        logfile.write(f"Hostname for {bigip_address} is {hostname}.\n")
        return hostname
    except Exception as e:
        print(f"Failed to retrieve hostname from {bigip_address}: {e}")
        logfile.write(f"Failed to retrieve hostname from {bigip_address}: {e}\n")
        return 'Unknown'

# Dictionaries to keep track of virtual servers and pool members per device
virtual_servers_by_device = defaultdict(list)
pool_members_by_device_vs = defaultdict(lambda: defaultdict(list))
hostnames_by_device = {}
problematic_vs = []

# Iterate over the BIG-IP addresses and collect stats from each
for bigip_address in bigip_addresses:
    print(f"Processing BIG-IP device at {bigip_address}...")
    logfile.write(f"Processing BIG-IP device at {bigip_address}...\n")
    auth_token = get_auth_token(bigip_address)
    if auth_token:
        base_uri = f"https://{bigip_address}/mgmt"
        headers = {'X-F5-Auth-Token': auth_token}

        # Retrieve device hostname
        hostname = get_device_hostname(bigip_address, auth_token)
        hostnames_by_device[bigip_address] = hostname

        # Retrieve virtual server list
        try:
            print(f"Retrieving virtual server list from {bigip_address}...")
            logfile.write(f"Retrieving virtual server list from {bigip_address}...\n")
            vs_list_url = f"{base_uri}/tm/ltm/virtual"
            response = requests.get(vs_list_url, headers=headers, verify=False)
            response.raise_for_status()
            vs_list_response = response.json()
            time.sleep(0.2)  # Pause to prevent rate limiting
            virtual_servers = vs_list_response.get('items', [])
        except Exception as e:
            print(f"Failed to retrieve virtual server list from {bigip_address}: {e}")
            logfile.write(f"Failed to retrieve virtual server list from {bigip_address}: {e}\n")
            logout(bigip_address, auth_token)
            continue

        for vs in virtual_servers:
            vs_name = vs['name']
            # URL-encode the virtual server name
            vs_name_encoded = quote(vs_name, safe='')

            # Log the constructed URL
            vs_config_url = f"{base_uri}/tm/ltm/virtual/{vs_name_encoded}?options=pool"
            print(f"Constructed URL: {vs_config_url}")
            logfile.write(f"Constructed URL: {vs_config_url}\n")

            try:
                print(f"Retrieving virtual server configuration for {vs_name}...")
                logfile.write(f"Retrieving virtual server configuration for {vs_name}...\n")
                response = requests.get(vs_config_url, headers=headers, verify=False)
                response.raise_for_status()
                vs_config_response = response.json()
                time.sleep(0.2)
                pool_name = vs_config_response.get('pool', '').replace('/Common/', '')

                # Retrieve virtual server status
                vs_status_url = f"{base_uri}/tm/ltm/virtual/{vs_name_encoded}/stats"
                print(f"Retrieving virtual server status for {vs_name}...")
                logfile.write(f"Retrieving virtual server status for {vs_name}...\n")
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

                # Updated vs_stat dictionary without Destination, IPProtocol, and Enabled
                vs_stat = {
                    'Device': bigip_address,
                    'Hostname': hostname,
                    'VirtualServerName': vs_config_response.get('fullPath', ''),
                    'Status': vs_status,
                    'Connections': connections,           # New field
                    'MaxConnections': max_connections,   # New field
                    'Pool': pool_name or 'No Pool'
                }
                virtual_servers_by_device[bigip_address].append(vs_stat)  # Collecting virtual servers per device
                logfile.write(f"Collected stats for virtual server {vs_stat['VirtualServerName']}.\n")
            except Exception as e:
                print(f"Failed to retrieve configuration or status for virtual server {vs_name} on {bigip_address}: {e}")
                logfile.write(f"Failed to retrieve configuration or status for virtual server {vs_name} on {bigip_address}: {e}\n")
                # Add the problematic virtual server to the list
                problematic_vs.append({
                    'Device': bigip_address,
                    'VirtualServer': vs_name,
                    'ErrorMessage': str(e)
                })
                continue

            # Retrieve pool member information if there is an associated pool
            if pool_name and pool_name != 'No Pool':
                # URL-encode the pool name
                pool_name_encoded = quote(pool_name, safe='')
                pool_members_url = f"{base_uri}/tm/ltm/pool/{pool_name_encoded}/members"
                print(f"Constructed URL for pool members: {pool_members_url}")
                logfile.write(f"Constructed URL for pool members: {pool_members_url}\n")

                try:
                    print(f"Retrieving pool member information for pool {pool_name}...")
                    logfile.write(f"Retrieving pool member information for pool {pool_name}...\n")
                    response = requests.get(pool_members_url, headers=headers, verify=False)
                    response.raise_for_status()
                    pool_members_response = response.json()
                    time.sleep(0.2)

                    for member in pool_members_response.get('items', []):
                        member_stat = {
                            'Device': bigip_address,
                            'Hostname': hostname,
                            'VirtualServerName': vs_config_response.get('fullPath', ''),
                            'PoolName': pool_name,
                            'MemberName': member.get('fullPath', ''),
                            'Address': member.get('address', ''),
                            'State': member.get('state', ''),
                            'Session': member.get('session', ''),
                            'MonitorStatus': member.get('monitorStatus', ''),
                            'Enabled': member.get('enabled', '')
                        }
                        pool_members_by_device_vs[bigip_address][vs_config_response.get('fullPath', '')].append(member_stat)
                    logfile.write(f"Collected pool members for pool {pool_name}.\n")
                except Exception as e:
                    print(f"Failed to retrieve pool members for pool {pool_name} on {bigip_address}: {e}")
                    logfile.write(f"Failed to retrieve pool members for pool {pool_name} on {bigip_address}: {e}\n")
                    continue
            else:
                print(f"Virtual server {vs_name} does not have an associated pool.")
                logfile.write(f"Virtual server {vs_name} does not have an associated pool.\n")

        # Logout to invalidate the authentication token
        logout(bigip_address, auth_token)
    else:
        print(f"Skipping {bigip_address} due to authentication failure.")
        logfile.write(f"Skipping {bigip_address} due to authentication failure.\n")

# Generate the main Markdown file
main_md_file = os.path.join(output_dir, "README.md")  # Change from "index.md" to "README.md"
with open(main_md_file, 'w', encoding='utf-8') as mdfile:
    mdfile.write("# F5 Devices Overview\n\n")
    mdfile.write("| Device IP | Hostname | Virtual Server Count |\n")
    mdfile.write("|-----------|----------|----------------------|\n")
    for device_ip in bigip_addresses:
        hostname = hostnames_by_device.get(device_ip, 'Unknown')
        vs_count = len(virtual_servers_by_device[device_ip])
        device_md_filename = f"device_{device_ip.replace('.', '_')}.md"
        device_md_filepath = os.path.join(output_dir, device_md_filename)
        mdfile.write(f"| [{device_ip}]({device_md_filename}) | {hostname} | {vs_count} |\n")

print(f"Main Markdown file generated: {main_md_file}")
with open(log_file, 'a', encoding='utf-8') as logfile:
    logfile.write(f"Main Markdown file generated: {main_md_file}\n")

# Generate Markdown and CSV files per device
for device_ip in bigip_addresses:
    hostname = hostnames_by_device.get(device_ip, 'Unknown')
    device_md_filename = os.path.join(output_dir, f"device_{device_ip.replace('.', '_')}.md")
    vs_csv_filename = os.path.join(output_dir, f"virtual_servers_{device_ip.replace('.', '_')}.csv")
    pool_csv_filename = os.path.join(output_dir, f"pool_members_{device_ip.replace('.', '_')}.csv")

    # Generate Markdown file for the device
    with open(device_md_filename, 'w', encoding='utf-8') as mdfile:
        mdfile.write(f"# Device: {hostname} ({device_ip})\n\n")

        # Virtual Servers Table
        mdfile.write("## Virtual Servers\n\n")
        # Updated table headers to exclude Destination, IP Protocol, and Enabled
        mdfile.write("| Virtual Server Name | Status | Connections | Max Connections | Pool |\n")
        mdfile.write("|---------------------|--------|-------------|-----------------|------|\n")

        for vs_stat in virtual_servers_by_device[device_ip]:
            vs_name_anchor = vs_stat['VirtualServerName'].replace('/', '_').replace(' ', '_')
            mdfile.write(f"| [{vs_stat['VirtualServerName']}](#{vs_name_anchor}) | {vs_stat['Status']} | {vs_stat['Connections']} | {vs_stat['MaxConnections']} | {vs_stat['Pool']} |\n")

        mdfile.write("\n")

        # Detailed Pool Member Sections
        mdfile.write("## Pool Member Details\n\n")

        for vs_stat in virtual_servers_by_device[device_ip]:
            vs_name = vs_stat['VirtualServerName']
            vs_name_anchor = vs_name.replace('/', '_').replace(' ', '_')
            mdfile.write(f"### {vs_name}\n")
            mdfile.write(f"<a id='{vs_name_anchor}'></a>\n\n")
            pool_members = pool_members_by_device_vs[device_ip].get(vs_name, [])
            if pool_members:
                mdfile.write("| Pool Name | Member Name | Address | State | Session | Monitor Status | Enabled |\n")
                mdfile.write("|-----------|-------------|---------|-------|---------|----------------|---------|\n")
                for member_stat in pool_members:
                    mdfile.write(f"| {member_stat['PoolName']} | {member_stat['MemberName']} | {member_stat['Address']} | {member_stat['State']} | {member_stat['Session']} | {member_stat['MonitorStatus']} | {member_stat['Enabled']} |\n")
                mdfile.write("\n")
            else:
                mdfile.write("No pool members associated with this virtual server.\n\n")

    print(f"Markdown file for device {device_ip} generated: {device_md_filename}")
    with open(log_file, 'a', encoding='utf-8') as logfile:
        logfile.write(f"Markdown file for device {device_ip} generated: {device_md_filename}\n")

    # Export virtual server stats to CSV
    if virtual_servers_by_device[device_ip]:
        with open(vs_csv_filename, 'w', newline='', encoding='utf-8') as csvfile:
            # Updated fieldnames to exclude Destination, IPProtocol, and Enabled
            fieldnames = ['Device', 'Hostname', 'VirtualServerName', 'Status', 'Connections', 'MaxConnections', 'Pool']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            for vs_stat in virtual_servers_by_device[device_ip]:
                writer.writerow(vs_stat)
        print(f"Virtual server CSV for device {device_ip} exported: {vs_csv_filename}")
        with open(log_file, 'a', encoding='utf-8') as logfile:
            logfile.write(f"Virtual server CSV for device {device_ip} exported: {vs_csv_filename}\n")

    # Export pool member stats to CSV
    pool_members = []
    for vs_name, members in pool_members_by_device_vs[device_ip].items():
        pool_members.extend(members)
    if pool_members:
        with open(pool_csv_filename, 'w', newline='', encoding='utf-8') as csvfile:
            fieldnames = ['Device', 'Hostname', 'VirtualServerName', 'PoolName', 'MemberName', 'Address', 'State', 'Session', 'MonitorStatus', 'Enabled']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            for member_stat in pool_members:
                writer.writerow(member_stat)
        print(f"Pool member CSV for device {device_ip} exported: {pool_csv_filename}")
        with open(log_file, 'a', encoding='utf-8') as logfile:
            logfile.write(f"Pool member CSV for device {device_ip} exported: {pool_csv_filename}\n")

# Generate the main Markdown file content
with open(main_md_file, 'a', encoding='utf-8') as mdfile:
    mdfile.write("\n")
print(f"Main Markdown file generated: {main_md_file}")
with open(log_file, 'a', encoding='utf-8') as logfile:
    logfile.write(f"Main Markdown file generated: {main_md_file}\n")

# Export list of problematic virtual servers if any
if problematic_vs:
    problematic_vs_output_file = os.path.join(output_dir, "problematic_virtual_servers.csv")
    with open(problematic_vs_output_file, 'w', newline='', encoding='utf-8') as csvfile:
        fieldnames = ['Device', 'VirtualServer', 'ErrorMessage']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for entry in problematic_vs:
            writer.writerow(entry)
    print(f"List of problematic virtual servers exported to {problematic_vs_output_file}.")
    with open(log_file, 'a', encoding='utf-8') as logfile:
        logfile.write(f"List of problematic virtual servers exported to {problematic_vs_output_file}.\n")

print("Script execution completed.")
with open(log_file, 'a', encoding='utf-8') as logfile:
    logfile.write("Script execution completed.\n")
