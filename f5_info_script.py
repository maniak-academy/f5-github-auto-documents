import requests
import csv
import time
import os
import sys
import urllib3
import json
from urllib.parse import quote
from collections import defaultdict
import getpass

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Define variables
device_list_file = "list.txt"  # The file containing the list of BIG-IP device IPs

# Get username and password from environment variables or prompt
if 'BIGIP_USERNAME' in os.environ and 'BIGIP_PASSWORD' in os.environ:
    bigip_username = os.environ.get('BIGIP_USERNAME')
    bigip_password = os.environ.get('BIGIP_PASSWORD')
else:
    # Prompt for username and password
    bigip_username = input("Enter BIG-IP username: ")
    bigip_password = getpass.getpass("Enter BIG-IP password: ")

# Read the list of devices from the file
if os.path.exists(device_list_file):
    with open(device_list_file, 'r') as f:
        bigip_addresses = [line.strip() for line in f if line.strip()]
else:
    print(f"Device list file '{device_list_file}' not found.")
    sys.exit(1)

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
        response = requests.post(auth_url, json=auth_body, headers=headers, verify=False)
        response.raise_for_status()
        auth_response = response.json()
        print(f"Authentication successful with {bigip_address}.")
        return auth_response['token']['token']
    except Exception as e:
        print(f"Failed to authenticate with {bigip_address}: {e}")
        return None

# Function to logout
def logout(bigip_address, auth_token):
    base_uri = f"https://{bigip_address}/mgmt"
    logout_url = f"{base_uri}/shared/authz/logout"
    headers = {'X-F5-Auth-Token': auth_token}
    try:
        print(f"Logging out from {bigip_address}...")
        requests.post(logout_url, headers=headers, verify=False)
    except Exception as e:
        print(f"Logout failed for {bigip_address}: {e}")

# Function to retrieve device hostname
def get_device_hostname(bigip_address, auth_token):
    base_uri = f"https://{bigip_address}/mgmt"
    hostname_url = f"{base_uri}/tm/sys/global-settings"
    headers = {'X-F5-Auth-Token': auth_token}
    try:
        print(f"Retrieving hostname from {bigip_address}...")
        response = requests.get(hostname_url, headers=headers, verify=False)
        response.raise_for_status()
        global_settings = response.json()
        hostname = global_settings.get('hostname', 'Unknown')
        print(f"Hostname for {bigip_address} is {hostname}.")
        return hostname
    except Exception as e:
        print(f"Failed to retrieve hostname from {bigip_address}: {e}")
        return 'Unknown'

# Dictionaries to keep track of virtual servers and pool members per device
virtual_servers_by_device = defaultdict(list)
pool_members_by_device_vs = defaultdict(lambda: defaultdict(list))
hostnames_by_device = {}
problematic_vs = []

# Iterate over the BIG-IP addresses and collect stats from each
for bigip_address in bigip_addresses:
    print(f"Processing BIG-IP device at {bigip_address}...")
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
            vs_list_url = f"{base_uri}/tm/ltm/virtual"
            response = requests.get(vs_list_url, headers=headers, verify=False)
            response.raise_for_status()
            vs_list_response = response.json()
            time.sleep(0.2)  # Pause to prevent rate limiting
            virtual_servers = vs_list_response.get('items', [])
        except Exception as e:
            print(f"Failed to retrieve virtual server list from {bigip_address}: {e}")
            logout(bigip_address, auth_token)
            continue

        for vs in virtual_servers:
            vs_name = vs['name']
            # URL-encode the virtual server name
            vs_name_encoded = quote(vs_name, safe='')

            # Log the constructed URL
            vs_config_url = f"{base_uri}/tm/ltm/virtual/{vs_name_encoded}?options=pool"
            print(f"Constructed URL: {vs_config_url}")

            try:
                print(f"Retrieving virtual server configuration for {vs_name}...")
                response = requests.get(vs_config_url, headers=headers, verify=False)
                response.raise_for_status()
                vs_config_response = response.json()
                time.sleep(0.2)
                pool_name = vs_config_response.get('pool', '').replace('/Common/', '')

                # Retrieve virtual server status
                vs_status_url = f"{base_uri}/tm/ltm/virtual/{vs_name_encoded}/stats"
                print(f"Retrieving virtual server status for {vs_name}...")
                response = requests.get(vs_status_url, headers=headers, verify=False)
                response.raise_for_status()
                vs_status_response = response.json()
                time.sleep(0.2)

                # Extract status
                entries = vs_status_response.get('entries', {})
                vs_status_entry = next(iter(entries.values()))
                vs_status = vs_status_entry['nestedStats']['entries']['status.availabilityState']['description']

                vs_stat = {
                    'Device': bigip_address,
                    'Hostname': hostname,
                    'VirtualServerName': vs_config_response.get('fullPath', ''),
                    'Destination': vs_config_response.get('destination', ''),
                    'IPProtocol': vs_config_response.get('ipProtocol', ''),
                    'Enabled': vs_config_response.get('enabled', ''),
                    'Status': vs_status,
                    'Pool': pool_name or 'No Pool'
                }
                virtual_servers_by_device[bigip_address].append(vs_stat)  # Collecting virtual servers per device
            except Exception as e:
                print(f"Failed to retrieve configuration or status for virtual server {vs_name} on {bigip_address}: {e}")
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

                try:
                    print(f"Retrieving pool member information for pool {pool_name}...")
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
                except Exception as e:
                    print(f"Failed to retrieve pool members for pool {pool_name} on {bigip_address}: {e}")
                    continue
            else:
                print(f"Virtual server {vs_name} does not have an associated pool.")

        # Logout to invalidate the authentication token
        logout(bigip_address, auth_token)
    else:
        print(f"Skipping {bigip_address} due to authentication failure.")

# Generate the main Markdown file
main_md_file = "README.md"  # Change from "index.md" to "README.md"
with open(main_md_file, 'w', encoding='utf-8') as mdfile:
    mdfile.write("# F5 Devices Overview\n\n")
    mdfile.write("| Device IP | Hostname | Virtual Server Count |\n")
    mdfile.write("|-----------|----------|----------------------|\n")
    for device_ip in bigip_addresses:
        hostname = hostnames_by_device.get(device_ip, 'Unknown')
        vs_count = len(virtual_servers_by_device[device_ip])
        device_md_filename = f"device_{device_ip.replace('.', '_')}.md"
        mdfile.write(f"| [{device_ip}]({device_md_filename}) | {hostname} | {vs_count} |\n")

print(f"Main Markdown file generated: {main_md_file}")

# Generate Markdown and CSV files per device
for device_ip in bigip_addresses:
    hostname = hostnames_by_device.get(device_ip, 'Unknown')
    device_md_filename = f"device_{device_ip.replace('.', '_')}.md"
    vs_csv_filename = f"virtual_servers_{device_ip.replace('.', '_')}.csv"
    pool_csv_filename = f"pool_members_{device_ip.replace('.', '_')}.csv"

    # Generate Markdown file for the device
    with open(device_md_filename, 'w', encoding='utf-8') as mdfile:
        mdfile.write(f"# Device: {hostname} ({device_ip})\n\n")

        # Virtual Servers Table
        mdfile.write("## Virtual Servers\n\n")
        mdfile.write("| Virtual Server Name | Destination | IP Protocol | Enabled | Status | Pool |\n")
        mdfile.write("|---------------------|-------------|-------------|---------|--------|------|\n")

        for vs_stat in virtual_servers_by_device[device_ip]:
            vs_name_anchor = vs_stat['VirtualServerName'].replace('/', '_').replace(' ', '_')
            mdfile.write(f"| [{vs_stat['VirtualServerName']}](#{vs_name_anchor}) | {vs_stat['Destination']} | {vs_stat['IPProtocol']} | {vs_stat['Enabled']} | {vs_stat['Status']} | {vs_stat['Pool']} |\n")

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

    # Export virtual server stats to CSV
    if virtual_servers_by_device[device_ip]:
        with open(vs_csv_filename, 'w', newline='', encoding='utf-8') as csvfile:
            fieldnames = ['Device', 'Hostname', 'VirtualServerName', 'Destination', 'IPProtocol', 'Enabled', 'Status', 'Pool']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            for vs_stat in virtual_servers_by_device[device_ip]:
                writer.writerow(vs_stat)
        print(f"Virtual server CSV for device {device_ip} exported: {vs_csv_filename}")

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

# Export list of problematic virtual servers if any
if problematic_vs:
    problematic_vs_output_file = "problematic_virtual_servers.csv"
    with open(problematic_vs_output_file, 'w', newline='', encoding='utf-8') as csvfile:
        fieldnames = ['Device', 'VirtualServer', 'ErrorMessage']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for entry in problematic_vs:
            writer.writerow(entry)
    print(f"List of problematic virtual servers exported to {problematic_vs_output_file}.")

print("Script execution completed.")
