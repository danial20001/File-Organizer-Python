import requests
import json
import subprocess
import time

# Disable SSL warnings (only for testing, not recommended in production)
requests.packages.urllib3.disable_warnings()

TOKEN = None
F5_HOST = None
TOKEN_TIMESTAMP = None
TOKEN_EXPIRY = 1200  # 20 minutes (set a bit lower for safety, e.g., 18 minutes)

def get_new_token():
    global TOKEN, F5_HOST, TOKEN_TIMESTAMP

    if not F5_HOST:
        F5_HOST = input("Enter F5 management IP/hostname: ")
    username = input("Enter your username: ")
    password = input("Enter your password: ")

    url = f"https://{F5_HOST}/mgmt/shared/authn/login"
    headers = {"Content-Type": "application/json"}
    payload = {"username": username, "password": password, "loginProviderName": "tmos"}

    response = requests.post(url, headers=headers, json=payload, verify=False)
    if response.status_code == 200:
        print("✅ Successfully logged in!")
        TOKEN = response.json().get("token", {}).get("token")
        TOKEN_TIMESTAMP = time.time()  # Store the time when the token was obtained
    else:
        print(f"❌ Login failed: {response.status_code} - {response.text}")
        TOKEN = None

def refresh_token_if_needed():
    global TOKEN, TOKEN_TIMESTAMP
    # Check if there is no token or if it is older than (TOKEN_EXPIRY - 120) seconds (i.e. ~18 minutes)
    if TOKEN is None or (time.time() - TOKEN_TIMESTAMP) > (TOKEN_EXPIRY - 120):
        print("🔄 Token expired or near expiry. Refreshing...")
        get_new_token()

def run_curl_command(command):
    """
    Run a command via an interactive login shell.
    This ensures that the environment on your jump server (with its default
    headers, proxy settings, etc.) is loaded.
    
    Note: We no longer call refresh_token_if_needed() here because the
    command is built with TOKEN. Instead, each caller must ensure the token is fresh.
    """
    full_cmd = ["bash", "-l", "-c", command]
    try:
        print("Running command:", command)
        result = subprocess.run(full_cmd, capture_output=True, text=True, check=True)
        if result.stderr:
            print("stderr:", result.stderr)
        return result.stdout
    except subprocess.CalledProcessError as e:
        print("Command failed with error:", e.stderr)
        return None

def get_wide_ips():
    refresh_token_if_needed()  # Check token right before building the curl command
    url = f"https://{F5_HOST}/mgmt/tm/gtm/wideip/a?$expand=all-properties"
    command = f'curl -vk -H "X-F5-Auth-Token: {TOKEN}" "{url}"'
    output = run_curl_command(command)
    if not output:
        print("No output received for wide IPs.")
        return []
    try:
        data = json.loads(output)
        return data.get("items", [])
    except json.JSONDecodeError as e:
        print("Error decoding JSON for wide IPs:", e)
        return []

def get_pool_details(pool_name):
    refresh_token_if_needed()  # Check token right before building the command
    url = f"https://{F5_HOST}/mgmt/tm/gtm/pool/a/{pool_name}?$expand=all-properties"
    command = f'curl -vk -H "X-F5-Auth-Token: {TOKEN}" "{url}"'
    output = run_curl_command(command)
    if not output:
        print(f"No output received for pool '{pool_name}'.")
        return None
    try:
        return json.loads(output)
    except json.JSONDecodeError as e:
        print(f"Error decoding JSON for pool '{pool_name}':", e)
        return None

def extract_pool_members(pool_details):
    members = []
    for member in pool_details.get("members", []):
        raw_address = member.get("name", "")
        ip_address = raw_address.split(":")[0]
        member_order = member.get("member-order", "Unknown")
        members.append({
            "raw": raw_address,
            "ip": ip_address,
            "order": member_order
        })
    return members

def collect_wide_ip_data():
    get_new_token()  # Ensure we start with a valid token

    wide_ips = get_wide_ips()
    if not wide_ips:
        print("No Wide IPs were fetched.")
        return

    wide_ip_data = []
    for wide_ip in wide_ips:
        wide_ip_entry = {
            "name": wide_ip.get("name"),
            "pool_lb_mode": wide_ip.get("pool-lb-mode", "Unknown"),
            "pools": []
        }
        for pool in wide_ip.get("pools", []):
            pool_name = pool.get("name")
            print(f"Fetching details for pool: {pool_name}")
            pool_details = get_pool_details(pool_name)
            if pool_details:
                pool_entry = {
                    "name": pool_name,
                    "fallback_method": pool_details.get("fallback", "Unknown"),
                    "load_balancing_mode": pool_details.get("load-balancing-mode", "Unknown"),
                    "members": extract_pool_members(pool_details)
                }
                wide_ip_entry["pools"].append(pool_entry)
        wide_ip_data.append(wide_ip_entry)

    with open("f5_wide_ip_data.json", "w") as f:
        json.dump(wide_ip_data, f, indent=4)

    print("✅ Data successfully saved in f5_wide_ip_data.json")

if __name__ == "__main__":
    collect_wide_ip_data()





import requests
import json
import subprocess
import time

# Disable SSL warnings (only for testing, not recommended in production)
requests.packages.urllib3.disable_warnings()

TOKEN = None
F5_HOST = None
TOKEN_TIMESTAMP = None
TOKEN_EXPIRY = 1200  # 20 minutes
TOKEN_REFRESH_THRESHOLD = 1080  # 18 minutes (1200 - 120)

def get_new_token():
    """Gets a new F5 authentication token and updates global variables."""
    global TOKEN, F5_HOST, TOKEN_TIMESTAMP

    if not F5_HOST:
        F5_HOST = input("Enter F5 management IP/hostname: ")
    username = input("Enter your username: ")
    password = input("Enter your password: ")

    url = f"https://{F5_HOST}/mgmt/shared/authn/login"
    headers = {"Content-Type": "application/json"}
    payload = {"username": username, "password": password, "loginProviderName": "tmos"}

    response = requests.post(url, headers=headers, json=payload, verify=False)
    
    if response.status_code == 200:
        print("✅ Successfully logged in!")
        TOKEN = response.json().get("token", {}).get("token")
        TOKEN_TIMESTAMP = time.time()  # Store the timestamp when token was obtained
    else:
        print(f"❌ Login failed: {response.status_code} - {response.text}")
        TOKEN = None

def check_token_validity():
    """Checks if the token is older than 18 minutes and refreshes if needed."""
    global TOKEN, TOKEN_TIMESTAMP
    if TOKEN is None or (time.time() - TOKEN_TIMESTAMP) > TOKEN_REFRESH_THRESHOLD:
        print("🔄 Token is older than 18 minutes. Refreshing...")
        get_new_token()

def run_curl_command(command):
    """
    Runs a curl command. Before running, checks token validity.
    """
    check_token_validity()  # Ensure token is not older than 18 minutes before running

    full_cmd = ["bash", "-l", "-c", command]
    try:
        print("Running command:", command)
        result = subprocess.run(full_cmd, capture_output=True, text=True, check=True)

        return result.stdout
    except subprocess.CalledProcessError as e:
        print("Command failed with error:", e.stderr)
        return None

def get_wide_ips():
    """Fetches wide IPs from the F5."""
    check_token_validity()
    url = f"https://{F5_HOST}/mgmt/tm/gtm/wideip/a?$expand=all-properties"
    command = f'curl -vk -H "X-F5-Auth-Token: {TOKEN}" "{url}"'
    output = run_curl_command(command)
    
    if not output:
        print("No output received for wide IPs.")
        return []
    
    try:
        data = json.loads(output)
        return data.get("items", [])
    except json.JSONDecodeError as e:
        print("Error decoding JSON for wide IPs:", e)
        return []

def get_pool_details(pool_name):
    """Fetches details for a specific pool."""
    check_token_validity()
    url = f"https://{F5_HOST}/mgmt/tm/gtm/pool/a/{pool_name}?$expand=all-properties"
    command = f'curl -vk -H "X-F5-Auth-Token: {TOKEN}" "{url}"'
    output = run_curl_command(command)
    
    if not output:
        print(f"No output received for pool '{pool_name}'.")
        return None
    
    try:
        return json.loads(output)
    except json.JSONDecodeError as e:
        print(f"Error decoding JSON for pool '{pool_name}':", e)
        return None

def extract_pool_members(pool_details):
    """Extracts pool members from pool details."""
    members = []
    for member in pool_details.get("members", []):
        raw_address = member.get("name", "")
        ip_address = raw_address.split(":")[0]
        member_order = member.get("member-order", "Unknown")
        members.append({
            "raw": raw_address,
            "ip": ip_address,
            "order": member_order
        })
    return members

def collect_wide_ip_data():
    """Main function to collect wide IP and pool details."""
    get_new_token()  # Get initial token

    wide_ips = get_wide_ips()
    if not wide_ips:
        print("No Wide IPs were fetched.")
        return

    wide_ip_data = []
    for wide_ip in wide_ips:
        wide_ip_entry = {
            "name": wide_ip.get("name"),
            "pool_lb_mode": wide_ip.get("pool-lb-mode", "Unknown"),
            "pools": []
        }

        for pool in wide_ip.get("pools", []):
            pool_name = pool.get("name")
            print(f"Fetching details for pool: {pool_name}")
            pool_details = get_pool_details(pool_name)
            
            if pool_details:
                pool_entry = {
                    "name": pool_name,
                    "fallback_method": pool_details.get("fallback", "Unknown"),
                    "load_balancing_mode": pool_details.get("load-balancing-mode", "Unknown"),
                    "members": extract_pool_members(pool_details)
                }
                wide_ip_entry["pools"].append(pool_entry)

        wide_ip_data.append(wide_ip_entry)

    with open("f5_wide_ip_data.json", "w") as f:
        json.dump(wide_ip_data, f, indent=4)

    print("✅ Data successfully saved in f5_wide_ip_data.json")

if __name__ == "__main__":
    collect_wide_ip_data()



-----
import requests
import json
import subprocess
import time

# Disable SSL warnings (only for testing, not recommended in production)
requests.packages.urllib3.disable_warnings()

TOKEN = None
F5_HOST = None
TOKEN_TIMESTAMP = None
TOKEN_EXPIRY = 1200  # 20 minutes (set a bit lower for safety, e.g., 18 minutes)

def get_new_token():
    global TOKEN, F5_HOST, TOKEN_TIMESTAMP

    if not F5_HOST:
        F5_HOST = input("Enter F5 management IP/hostname: ")
    username = input("Enter your username: ")
    password = input("Enter your password: ")

    url = f"https://{F5_HOST}/mgmt/shared/authn/login"
    headers = {"Content-Type": "application/json"}
    payload = {"username": username, "password": password, "loginProviderName": "tmos"}

    response = requests.post(url, headers=headers, json=payload, verify=False)
    if response.status_code == 200:
        print("✅ Successfully logged in!")
        TOKEN = response.json().get("token", {}).get("token")
        TOKEN_TIMESTAMP = time.time()  # Store the time when the token was obtained
    else:
        print(f"❌ Login failed: {response.status_code} - {response.text}")
        TOKEN = None

def refresh_token_if_needed():
    global TOKEN, TOKEN_TIMESTAMP
    if TOKEN is None or (time.time() - TOKEN_TIMESTAMP) > (TOKEN_EXPIRY - 120):  # Refresh ~2 mins before expiry
        print("🔄 Token expired or near expiry. Refreshing...")
        get_new_token()

def run_curl_command(command):
    """
    Run a command via an interactive login shell.
    This ensures that the environment on your jump server (with its default
    headers, proxy settings, etc.) is loaded.
    """
    refresh_token_if_needed()
    full_cmd = ["bash", "-l", "-c", command]
    try:
        print("Running command:", command)
        result = subprocess.run(full_cmd, capture_output=True, text=True, check=True)
        if result.stderr:
            print("stderr:", result.stderr)
        return result.stdout
    except subprocess.CalledProcessError as e:
        print("Command failed with error:", e.stderr)
        return None

def get_wide_ips():
    refresh_token_if_needed()
    url = f"https://{F5_HOST}/mgmt/tm/gtm/wideip/a?$expand=all-properties"
    command = f'curl -vk -H "X-F5-Auth-Token: {TOKEN}" "{url}"'
    output = run_curl_command(command)
    if not output:
        print("No output received for wide IPs.")
        return []
    try:
        data = json.loads(output)
        return data.get("items", [])
    except json.JSONDecodeError as e:
        print("Error decoding JSON for wide IPs:", e)
        return []

def collect_wide_ip_data():
    get_new_token()  # Ensure we start with a valid token

    wide_ips = get_wide_ips()
    if not wide_ips:
        print("No Wide IPs were fetched.")
        return

    wide_ip_data = []
    for wide_ip in wide_ips:
        wide_ip_entry = {
            "name": wide_ip.get("name"),
            "pool_lb_mode": wide_ip.get("pool-lb-mode", "Unknown"),
            "pools": []
        }
        for pool in wide_ip.get("pools", []):
            pool_name = pool.get("name")
            print(f"Fetching details for pool: {pool_name}")
            pool_details = get_pool_details(pool_name)
            if pool_details:
                pool_entry = {
                    "name": pool_name,
                    "fallback_method": pool_details.get("fallback", "Unknown"),
                    "load_balancing_mode": pool_details.get("load-balancing-mode", "Unknown"),
                    "members": extract_pool_members(pool_details)
                }
                wide_ip_entry["pools"].append(pool_entry)
        wide_ip_data.append(wide_ip_entry)

    with open("f5_wide_ip_data.json", "w") as f:
        json.dump(wide_ip_data, f, indent=4)

    print("✅ Data successfully saved in f5_wide_ip_data.json")

if __name__ == "__main__":
    collect_wide_ip_data()
