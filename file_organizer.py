import requests
import json
import subprocess
import time
from threading import Thread, Event

# Disable SSL warnings (only for testing, not recommended in production)
requests.packages.urllib3.disable_warnings()

def login_to_f5():
    global token, f5_host
    f5_host = input("Enter F5 management IP/hostname: ")
    username = input("Enter your username: ")
    password = input("Enter your password: ")

    url = f"https://{f5_host}/mgmt/shared/authn/login"
    headers = {"Content-Type": "application/json"}
    payload = {
        "username": username,
        "password": password,
        "loginProviderName": "tmos"
    }

    response = requests.post(url, headers=headers, json=payload, verify=False)
    if response.status_code == 200:
        print("✅ Successfully logged in!")
        token = response.json().get("token", {}).get("token")
        return token
    else:
        print(f"❌ Login failed: {response.status_code} - {response.text}")
        return None

def refresh_token(stop_event):
    global token
    while not stop_event.is_set():
        time.sleep(900)  # Refresh every 15 minutes
        print("🔄 Refreshing token...")
        token = login_to_f5()
        if not token:
            print("❌ Token refresh failed! Exiting.")
            stop_event.set()

def run_curl_command(command):
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
    url = f"https://{f5_host}/mgmt/tm/gtm/wideip/a?$expand=all-properties"
    command = f'curl -vk -H "X-F5-Auth-Token: {token}" "{url}"'
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
    url = f"https://{f5_host}/mgmt/tm/gtm/pool/a/{pool_name}?$expand=all-properties"
    command = f'curl -vk -H "X-F5-Auth-Token: {token}" "{url}"'
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
    return [
        {
            "raw": member.get("name", ""),
            "ip": member.get("name", "").split(":")[0],
            "order": member.get("member-order", "Unknown")
        }
        for member in pool_details.get("members", [])
    ]

def collect_wide_ip_data():
    global token
    token = login_to_f5()
    if not token:
        return

    stop_event = Event()
    refresh_thread = Thread(target=refresh_token, args=(stop_event,), daemon=True)
    refresh_thread.start()

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
            pool_order = pool.get("order", "Unknown")
            print(f"Fetching details for pool: {pool_name}")
            pool_details = get_pool_details(pool_name)
            if pool_details:
                wide_ip_entry["pools"].append({
                    "name": pool_name,
                    "order": pool_order,
                    "fallback_method": pool_details.get("fallback", "Unknown"),
                    "load_balancing_mode": pool_details.get("load-balancing-mode", "Unknown"),
                    "members": extract_pool_members(pool_details)
                })
        wide_ip_data.append(wide_ip_entry)
    
    with open("f5_wide_ip_data.json", "w") as f:
        json.dump(wide_ip_data, f, indent=4)
    
    print("✅ Data successfully saved in f5_wide_ip_data.json")
    stop_event.set()
    refresh_thread.join()

if __name__ == "__main__":
    collect_wide_ip_data()


]]]]]]]]]]]
import requests
import json
import subprocess
import time

# Disable SSL warnings (only for testing, not recommended in production)
requests.packages.urllib3.disable_warnings()

# Global variables for token and credential management
GLOBAL_F5_HOST = None
GLOBAL_USERNAME = None
GLOBAL_PASSWORD = None
GLOBAL_TOKEN = None
GLOBAL_TOKEN_TIME = None

# Constants for token validity and refresh threshold
TOKEN_VALIDITY_SECONDS = 15 * 60   # 15 minutes
REFRESH_BEFORE_EXPIRY = 3 * 60       # refresh 3 minutes before expiry

# Function to log in and get an authentication token.
# Also stores the credentials and token timestamp globally.
def login_to_f5(f5_host=None, username=None, password=None):
    global GLOBAL_F5_HOST, GLOBAL_USERNAME, GLOBAL_PASSWORD, GLOBAL_TOKEN, GLOBAL_TOKEN_TIME

    # Prompt for credentials only if not already provided.
    if f5_host is None:
        f5_host = input("Enter F5 management IP/hostname: ")
    if username is None:
        username = input("Enter your username: ")
    if password is None:
        password = input("Enter your password: ")

    # Store credentials globally (so they can be re-used on token refresh).
    GLOBAL_F5_HOST = f5_host
    GLOBAL_USERNAME = username
    GLOBAL_PASSWORD = password

    url = f"https://{f5_host}/mgmt/shared/authn/login"
    headers = {"Content-Type": "application/json"}
    payload = {
        "username": username,
        "password": password,
        "loginProviderName": "tmos"
    }

    response = requests.post(url, headers=headers, json=payload, verify=False)
    if response.status_code == 200:
        token = response.json().get("token", {}).get("token")
        GLOBAL_TOKEN = token
        GLOBAL_TOKEN_TIME = time.time()  # Record when the token was obtained.
        print("✅ Successfully logged in!")
        return token, f5_host
    else:
        print(f"❌ Login failed: {response.status_code} - {response.text}")
        return None, None

# Function to check if the token is near expiry.
# If the token is older than (15 minutes - 3 minutes), then refresh it.
def check_token():
    global GLOBAL_TOKEN, GLOBAL_TOKEN_TIME
    if GLOBAL_TOKEN is None or GLOBAL_TOKEN_TIME is None:
        return False
    elapsed = time.time() - GLOBAL_TOKEN_TIME
    if elapsed >= (TOKEN_VALIDITY_SECONDS - REFRESH_BEFORE_EXPIRY):
        print("Token is nearing expiry; refreshing token now...")
        # Re-login using stored credentials
        login_to_f5(GLOBAL_F5_HOST, GLOBAL_USERNAME, GLOBAL_PASSWORD)
        return True
    return True

# Function to fetch all Wide IPs using curl via subprocess.
def get_wide_ips(f5_host, token):
    # Ensure the token is fresh before calling the API.
    check_token()
    token = GLOBAL_TOKEN  # Use the (possibly refreshed) global token.
    url = f"https://{f5_host}/mgmt/tm/gtm/wideip/a?$expand=all-properties"
    header = f"X-F5-Auth-Token: {token}"
    cmd = ["curl", "-k", "-H", header, url]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        data = json.loads(result.stdout)
        return data.get("items", [])
    except subprocess.CalledProcessError as e:
        print("Curl command failed:", e.stderr)
    except Exception as e:
        print("Error processing JSON response:", e)
    
    return []

# Function to fetch pool details for a given pool name using curl via subprocess.
def get_pool_details(f5_host, token, pool_name):
    check_token()
    token = GLOBAL_TOKEN  # Use the refreshed token.
    url = f"https://{f5_host}/mgmt/tm/gtm/pool/a/{pool_name}?$expand=all-properties"
    header = f"X-F5-Auth-Token: {token}"
    cmd = ["curl", "-k", "-H", header, url]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        data = json.loads(result.stdout)
        return data
    except subprocess.CalledProcessError as e:
        print(f"Curl command failed for pool '{pool_name}':", e.stderr)
    except Exception as e:
        print("Error processing JSON response:", e)
    
    return None

# Function to extract pool members (extracting the IP before the colon)
def extract_pool_members(pool_details):
    members = []
    for member in pool_details.get("members", []):
        raw_address = member["name"]  # Example: "10.160.224.64:10_160_224_64_445"
        ip_address = raw_address.split(":")[0]  # Extract only the IP part
        member_order = member.get("member-order", "Unknown")
        members.append({
            "raw": raw_address,
            "ip": ip_address,
            "order": member_order
        })
    return members

# Main function to gather Wide IP and Pool data.
def collect_wide_ip_data():
    token, f5_host = login_to_f5()
    if not token:
        return

    wide_ips = get_wide_ips(f5_host, token)
    wide_ip_data = []

    for wide_ip in wide_ips:
        wide_ip_entry = {
            "name": wide_ip["name"],
            "pool_lb_mode": wide_ip.get("pool-lb-mode", "Unknown"),
            "pools": []
        }

        for pool in wide_ip.get("pools", []):
            pool_name = pool["name"]
            pool_order = pool.get("order", "Unknown")
            pool_details = get_pool_details(f5_host, token, pool_name)

            if pool_details:
                pool_entry = {
                    "name": pool_name,
                    "order": pool_order,
                    "fallback_method": pool_details.get("fallback", "Unknown"),
                    "load_balancing_mode": pool_details.get("load-balancing-mode", "Unknown"),
                    "members": extract_pool_members(pool_details)
                }
                wide_ip_entry["pools"].append(pool_entry)

        wide_ip_data.append(wide_ip_entry)

    # Save the gathered data to a JSON file in the same directory.
    with open("f5_wide_ip_data.json", "w") as f:
        json.dump(wide_ip_data, f, indent=4)

    print("✅ Data successfully saved in f5_wide_ip_data.json")

# Run the script
if __name__ == "__main__":
    collect_wide_ip_data()

============================
import requests
import json
import subprocess
import time

# Global variables for token management
GLOBAL_F5_HOST = None
GLOBAL_USERNAME = None
GLOBAL_PASSWORD = None
GLOBAL_TOKEN = None
GLOBAL_TOKEN_TIME = None

# Define the refresh threshold in seconds (14 minutes)
REFRESH_THRESHOLD = 14 * 60  # 14 minutes

# Disable SSL warnings (only for testing, not recommended in production)
requests.packages.urllib3.disable_warnings()

def login_to_f5(f5_host=None, username=None, password=None):
    """
    Logs in to the F5 device and returns a token.
    If credentials are not provided, they are prompted from the user.
    Stores the credentials and token acquisition time in global variables.
    """
    global GLOBAL_F5_HOST, GLOBAL_USERNAME, GLOBAL_PASSWORD, GLOBAL_TOKEN, GLOBAL_TOKEN_TIME

    if not f5_host:
        f5_host = input("Enter F5 management IP/hostname: ")
    if not username:
        username = input("Enter your username: ")
    if not password:
        password = input("Enter your password: ")

    # Save credentials globally
    GLOBAL_F5_HOST = f5_host
    GLOBAL_USERNAME = username
    GLOBAL_PASSWORD = password

    url = f"https://{f5_host}/mgmt/shared/authn/login"
    headers = {"Content-Type": "application/json"}
    payload = {
        "username": username,
        "password": password,
        "loginProviderName": "tmos"
    }

    response = requests.post(url, headers=headers, json=payload, verify=False)
    if response.status_code == 200:
        print("✅ Successfully logged in!")
        token = response.json().get("token", {}).get("token")
        GLOBAL_TOKEN = token
        GLOBAL_TOKEN_TIME = time.time()
        return token
    else:
        print(f"❌ Login failed: {response.status_code} - {response.text}")
        return None

def check_token():
    """
    Checks if the token has expired (or is near expiration).
    If the token is older than the defined threshold, it re-authenticates.
    """
    global GLOBAL_TOKEN, GLOBAL_TOKEN_TIME, GLOBAL_F5_HOST, GLOBAL_USERNAME, GLOBAL_PASSWORD
    if GLOBAL_TOKEN is None or GLOBAL_TOKEN_TIME is None:
        # No token available, perform login.
        login_to_f5()
    elif time.time() - GLOBAL_TOKEN_TIME >= REFRESH_THRESHOLD:
        print("Refreshing token...")
        new_token = login_to_f5(GLOBAL_F5_HOST, GLOBAL_USERNAME, GLOBAL_PASSWORD)
        if new_token:
            print("Token refreshed.")
        else:
            print("Failed to refresh token.")

def get_wide_ips():
    """
    Uses curl (via a subprocess) to fetch all Wide IPs with expanded properties.
    Ensures the token is refreshed if necessary before making the call.
    """
    check_token()
    f5_host = GLOBAL_F5_HOST
    token = GLOBAL_TOKEN
    url = f"https://{f5_host}/mgmt/tm/gtm/wideip/a?$expand=all-properties"
    header = f"X-F5-Auth-Token: {token}"
    cmd = ["curl", "-k", "-H", header, url]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        data = json.loads(result.stdout)
        return data.get("items", [])
    except subprocess.CalledProcessError as e:
        print("Curl command failed:", e.stderr)
    except Exception as e:
        print("Error processing JSON response:", e)
    return []

def get_pool_details(pool_name):
    """
    Uses curl (via a subprocess) to fetch details for a given pool (with expanded properties).
    Checks for token freshness before making the call.
    """
    check_token()
    f5_host = GLOBAL_F5_HOST
    token = GLOBAL_TOKEN
    url = f"https://{f5_host}/mgmt/tm/gtm/pool/a/{pool_name}?$expand=all-properties"
    header = f"X-F5-Auth-Token: {token}"
    cmd = ["curl", "-k", "-H", header, url]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        data = json.loads(result.stdout)
        return data
    except subprocess.CalledProcessError as e:
        print(f"Curl command failed for pool '{pool_name}':", e.stderr)
    except Exception as e:
        print("Error processing JSON response:", e)
    return None

def extract_pool_members(pool_details):
    """
    Extracts and returns a list of pool members with their raw addresses, IP addresses,
    and member order from the pool details.
    """
    members = []
    for member in pool_details.get("members", []):
        raw_address = member["name"]  # e.g., "10.160.224.64:10_160_224_64_445"
        ip_address = raw_address.split(":")[0]  # Extract the IP part
        member_order = member.get("member-order", "Unknown")
        members.append({
            "raw": raw_address,
            "ip": ip_address,
            "order": member_order
        })
    return members

def collect_wide_ip_data():
    """
    Main function to gather Wide IP data and corresponding pool details.
    The collected data is saved to a JSON file.
    """
    token = login_to_f5()
    if not token:
        return

    wide_ips = get_wide_ips()
    wide_ip_data = []

    for wide_ip in wide_ips:
        wide_ip_entry = {
            "name": wide_ip["name"],
            "pool_lb_mode": wide_ip.get("pool-lb-mode", "Unknown"),
            "pools": []
        }

        for pool in wide_ip.get("pools", []):
            pool_name = pool["name"]
            pool_order = pool.get("order", "Unknown")
            pool_details = get_pool_details(pool_name)

            if pool_details:
                pool_entry = {
                    "name": pool_name,
                    "order": pool_order,
                    "fallback_method": pool_details.get("fallback", "Unknown"),
                    "load_balancing_mode": pool_details.get("load-balancing-mode", "Unknown"),
                    "members": extract_pool_members(pool_details)
                }
                wide_ip_entry["pools"].append(pool_entry)

        wide_ip_data.append(wide_ip_entry)

    # Save the collected data to a JSON file in the current directory.
    with open("f5_wide_ip_data.json", "w") as f:
        json.dump(wide_ip_data, f, indent=4)

    print("✅ Data successfully saved in f5_wide_ip_data.json")

if __name__ == "__main__":
    collect_wide_ip_data()


==========================
import requests
import json
import subprocess

# Disable SSL warnings (only for testing, not recommended in production)
requests.packages.urllib3.disable_warnings()

def login_to_f5():
    f5_host = input("Enter F5 management IP/hostname: ")
    username = input("Enter your username: ")
    password = input("Enter your password: ")

    url = f"https://{f5_host}/mgmt/shared/authn/login"
    headers = {"Content-Type": "application/json"}
    payload = {
        "username": username,
        "password": password,
        "loginProviderName": "tmos"
    }

    response = requests.post(url, headers=headers, json=payload, verify=False)
    if response.status_code == 200:
        print("✅ Successfully logged in!")
        token = response.json().get("token", {}).get("token")
        return token, f5_host
    else:
        print(f"❌ Login failed: {response.status_code} - {response.text}")
        return None, None

def run_curl_command(command):
    """
    Run a command via an interactive login shell.
    This ensures that the environment on your jump server (with its default
    headers, proxy settings, etc.) is loaded.
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

def get_wide_ips(f5_host, token):
    url = f"https://{f5_host}/mgmt/tm/gtm/wideip/a?$expand=all-properties"
    # Replicate your working curl command exactly:
    command = f'curl -vk -H "X-F5-Auth-Token: {token}" "{url}"'
    output = run_curl_command(command)
    if not output:
        print("No output received for wide IPs.")
        return []
    try:
        data = json.loads(output)
        items = data.get("items", [])
        if not items:
            print("No items returned in the wide IPs response.")
        else:
            print(f"Fetched {len(items)} wide IP items.")
        return items
    except json.JSONDecodeError as e:
        print("Error decoding JSON for wide IPs:", e)
        print("Output was:", output)
        return []

def get_pool_details(f5_host, token, pool_name):
    url = f"https://{f5_host}/mgmt/tm/gtm/pool/a/{pool_name}?$expand=all-properties"
    command = f'curl -vk -H "X-F5-Auth-Token: {token}" "{url}"'
    output = run_curl_command(command)
    if not output:
        print(f"No output received for pool '{pool_name}'.")
        return None
    try:
        data = json.loads(output)
        return data
    except json.JSONDecodeError as e:
        print(f"Error decoding JSON for pool '{pool_name}':", e)
        print("Output was:", output)
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
    token, f5_host = login_to_f5()
    if not token:
        return

    wide_ips = get_wide_ips(f5_host, token)
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
            pool_order = pool.get("order", "Unknown")
            print(f"Fetching details for pool: {pool_name}")
            pool_details = get_pool_details(f5_host, token, pool_name)
            if pool_details:
                pool_entry = {
                    "name": pool_name,
                    "order": pool_order,
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

# Disable SSL warnings (only for testing, not recommended in production)
requests.packages.urllib3.disable_warnings()

def login_to_f5():
    f5_host = input("Enter F5 management IP/hostname: ")
    username = input("Enter your username: ")
    password = input("Enter your password: ")

    url = f"https://{f5_host}/mgmt/shared/authn/login"
    headers = {"Content-Type": "application/json"}
    payload = {
        "username": username,
        "password": password,
        "loginProviderName": "tmos"
    }

    response = requests.post(url, headers=headers, json=payload, verify=False)
    if response.status_code == 200:
        print("✅ Successfully logged in!")
        token = response.json().get("token", {}).get("token")
        return token, f5_host
    else:
        print(f"❌ Login failed: {response.status_code} - {response.text}")
        return None, None

def run_curl_command(cmd):
    try:
        print("Running command:", " ".join(cmd))
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        if result.stderr:
            print("Curl stderr:", result.stderr)
        if not result.stdout:
            print("Empty stdout received")
        else:
            print("Curl stdout (first 200 chars):", result.stdout[:200])
        return result.stdout
    except subprocess.CalledProcessError as e:
        print("Curl command failed:", e.stderr)
        return None
    except Exception as e:
        print("Error executing curl command:", e)
        return None

def get_wide_ips(f5_host, token):
    base_url = f"https://{f5_host}/mgmt/tm/gtm/wideip/a"
    query = "?$expand=all-properties"
    url = base_url + query

    headers = [
        f"X-F5-Auth-Token: {token}",
        "Accept: application/json",
        "User-Agent: curl/7.68.0"
    ]

    all_items = []
    page = 1
    while url:
        print(f"\nFetching page {page} of Wide IPs from URL: {url}")
        # Use --fail to cause curl to error on HTTP errors
        cmd = ["curl", "-k", "--fail"]
        for h in headers:
            cmd.extend(["-H", h])
        cmd.append(url)
        output = run_curl_command(cmd)
        if not output:
            print("No output received from curl, stopping pagination.")
            break
        try:
            data = json.loads(output)
        except json.JSONDecodeError as e:
            print("JSON decode error:", e)
            print("Output was:", output)
            break

        items = data.get("items", [])
        if not items:
            print("No items returned on this page.")
        else:
            print(f"Fetched {len(items)} items on page {page}.")
        all_items.extend(items)

        # Check for a paging object with a next link
        paging = data.get("paging", {})
        next_link = paging.get("next")
        if next_link:
            url = next_link  # Should be a full URL
            page += 1
        else:
            url = None
    return all_items

def get_pool_details(f5_host, token, pool_name):
    url = f"https://{f5_host}/mgmt/tm/gtm/pool/a/{pool_name}?$expand=all-properties"
    headers = [
        f"X-F5-Auth-Token: {token}",
        "Accept: application/json",
        "User-Agent: curl/7.68.0"
    ]
    cmd = ["curl", "-k", "--fail"]
    for h in headers:
        cmd.extend(["-H", h])
    cmd.append(url)
    output = run_curl_command(cmd)
    if not output:
        print(f"No output received for pool '{pool_name}'.")
        return None
    try:
        data = json.loads(output)
        return data
    except json.JSONDecodeError as e:
        print(f"JSON decode error for pool '{pool_name}':", e)
        print("Output was:", output)
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
    token, f5_host = login_to_f5()
    if not token:
        return

    wide_ips = get_wide_ips(f5_host, token)
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
            pool_order = pool.get("order", "Unknown")
            print(f"\nFetching details for pool: {pool_name}")
            pool_details = get_pool_details(f5_host, token, pool_name)
            if pool_details:
                pool_entry = {
                    "name": pool_name,
                    "order": pool_order,
                    "fallback_method": pool_details.get("fallback", "Unknown"),
                    "load_balancing_mode": pool_details.get("load-balancing-mode", "Unknown"),
                    "members": extract_pool_members(pool_details)
                }
                wide_ip_entry["pools"].append(pool_entry)
        wide_ip_data.append(wide_ip_entry)

    with open("f5_wide_ip_data.json", "w") as f:
        json.dump(wide_ip_data, f, indent=4)

    print("\n✅ Data successfully saved in f5_wide_ip_data.json")

if __name__ == "__main__":
    collect_wide_ip_data()
    
    
    
    
    
    
    
    
    import requests
import json
import subprocess

# Disable SSL warnings (only for testing, not recommended in production)
requests.packages.urllib3.disable_warnings()

# Function to log in and get an authentication token
def login_to_f5():
    f5_host = input("Enter F5 management IP/hostname: ")
    username = input("Enter your username: ")
    password = input("Enter your password: ")

    url = f"https://{f5_host}/mgmt/shared/authn/login"
    headers = {"Content-Type": "application/json"}
    payload = {
        "username": username,
        "password": password,
        "loginProviderName": "tmos"
    }

    response = requests.post(url, headers=headers, json=payload, verify=False)
    if response.status_code == 200:
        print("✅ Successfully logged in!")
        return response.json().get("token", {}).get("token"), f5_host
    else:
        print(f"❌ Login failed: {response.status_code} - {response.text}")
        return None, None

# Function to fetch all Wide IPs using curl via subprocess with pagination support
def get_wide_ips(f5_host, token):
    base_url = f"https://{f5_host}/mgmt/tm/gtm/wideip/a"
    # Append query parameters to expand all properties
    query = "?$expand=all-properties"
    url = base_url + query
    header = f"X-F5-Auth-Token: {token}"
    
    all_items = []
    page = 1
    while url:
        print(f"Fetching page {page} of Wide IPs...")
        cmd = ["curl", "-k", "-H", header, url]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            data = json.loads(result.stdout)
            items = data.get("items", [])
            if not items:
                print("No items returned on this page.")
            else:
                print(f"Fetched {len(items)} items on page {page}.")
            all_items.extend(items)
            # Check if there is a 'paging' object with a 'next' link in the response.
            # This is typical behaviour for large datasets.
            paging = data.get("paging", {})
            next_link = paging.get("next")
            if next_link:
                url = next_link  # The next link should be a full URL.
                page += 1
            else:
                url = None
        except subprocess.CalledProcessError as e:
            print("Curl command failed:", e.stderr)
            break
        except Exception as e:
            print("Error processing JSON response:", e)
            break
    return all_items

# Function to fetch pool details for a given pool name using curl via subprocess
def get_pool_details(f5_host, token, pool_name):
    url = f"https://{f5_host}/mgmt/tm/gtm/pool/a/{pool_name}?$expand=all-properties"
    header = f"X-F5-Auth-Token: {token}"
    cmd = ["curl", "-k", "-H", header, url]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        data = json.loads(result.stdout)
        return data
    except subprocess.CalledProcessError as e:
        print(f"Curl command failed for pool '{pool_name}':", e.stderr)
    except Exception as e:
        print("Error processing JSON response:", e)
    return None

# Function to extract pool members (extracting the IP address before the colon)
def extract_pool_members(pool_details):
    members = []
    for member in pool_details.get("members", []):
        raw_address = member["name"]  # e.g. "10.160.224.64:10_160_224_64_445"
        ip_address = raw_address.split(":")[0]
        member_order = member.get("member-order", "Unknown")
        members.append({
            "raw": raw_address,
            "ip": ip_address,
            "order": member_order
        })
    return members

# Main function to gather Wide IP and Pool data
def collect_wide_ip_data():
    token, f5_host = login_to_f5()
    if not token:
        return

    wide_ips = get_wide_ips(f5_host, token)
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
            pool_order = pool.get("order", "Unknown")
            print(f"Fetching details for pool: {pool_name}")
            pool_details = get_pool_details(f5_host, token, pool_name)
            if pool_details:
                pool_entry = {
                    "name": pool_name,
                    "order": pool_order,
                    "fallback_method": pool_details.get("fallback", "Unknown"),
                    "load_balancing_mode": pool_details.get("load-balancing-mode", "Unknown"),
                    "members": extract_pool_members(pool_details)
                }
                wide_ip_entry["pools"].append(pool_entry)

        wide_ip_data.append(wide_ip_entry)

    # Save the gathered data to a JSON file
    with open("f5_wide_ip_data.json", "w") as f:
        json.dump(wide_ip_data, f, indent=4)

    print("✅ Data successfully saved in f5_wide_ip_data.json")

if __name__ == "__main__":
    collect_wide_ip_data()





import requests
import json
import subprocess

# Disable SSL warnings (only for testing, not recommended in production)
requests.packages.urllib3.disable_warnings()

# Function to log in and get an authentication token
def login_to_f5():
    f5_host = input("Enter F5 management IP/hostname: ")
    username = input("Enter your username: ")
    password = input("Enter your password: ")

    url = f"https://{f5_host}/mgmt/shared/authn/login"
    headers = {"Content-Type": "application/json"}
    payload = {
        "username": username,
        "password": password,
        "loginProviderName": "tmos"
    }

    response = requests.post(url, headers=headers, json=payload, verify=False)
    if response.status_code == 200:
        print("✅ Successfully logged in!")
        return response.json().get("token", {}).get("token"), f5_host
    else:
        print(f"❌ Login failed: {response.status_code} - {response.text}")
        return None, None

# Function to fetch all Wide IPs using curl directly via a subprocess
def get_wide_ips(f5_host, token):
    url = f"https://{f5_host}/mgmt/tm/gtm/wideip/a?$expand=all-properties"
    header = f"X-F5-Auth-Token: {token}"
    # Build the curl command as used on your jump server
    cmd = ["curl", "-k", "-H", header, url]
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        data = json.loads(result.stdout)
        return data.get("items", [])
    except subprocess.CalledProcessError as e:
        print("Curl command failed:", e.stderr)
    except Exception as e:
        print("Error processing JSON response:", e)
    
    return []

# Function to fetch pool details for a given pool name using curl directly via a subprocess
def get_pool_details(f5_host, token, pool_name):
    url = f"https://{f5_host}/mgmt/tm/gtm/pool/a/{pool_name}?$expand=all-properties"
    header = f"X-F5-Auth-Token: {token}"
    cmd = ["curl", "-k", "-H", header, url]
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        data = json.loads(result.stdout)
        return data
    except subprocess.CalledProcessError as e:
        print(f"Curl command failed for pool '{pool_name}':", e.stderr)
    except Exception as e:
        print("Error processing JSON response:", e)
    
    return None

# Function to extract pool members (extracting the IP before the colon)
def extract_pool_members(pool_details):
    members = []
    for member in pool_details.get("members", []):
        raw_address = member["name"]  # Example: "10.160.224.64:10_160_224_64_445"
        ip_address = raw_address.split(":")[0]  # Extract only the IP part
        member_order = member.get("member-order", "Unknown")
        members.append({
            "raw": raw_address,
            "ip": ip_address,
            "order": member_order
        })
    return members

# Main function to gather Wide IP and Pool data
def collect_wide_ip_data():
    token, f5_host = login_to_f5()
    if not token:
        return

    wide_ips = get_wide_ips(f5_host, token)
    wide_ip_data = []

    for wide_ip in wide_ips:
        wide_ip_entry = {
            "name": wide_ip["name"],
            "pool_lb_mode": wide_ip.get("pool-lb-mode", "Unknown"),
            "pools": []
        }

        for pool in wide_ip.get("pools", []):
            pool_name = pool["name"]
            pool_order = pool.get("order", "Unknown")
            pool_details = get_pool_details(f5_host, token, pool_name)

            if pool_details:
                pool_entry = {
                    "name": pool_name,
                    "order": pool_order,
                    "fallback_method": pool_details.get("fallback", "Unknown"),
                    "load_balancing_mode": pool_details.get("load-balancing-mode", "Unknown"),
                    "members": extract_pool_members(pool_details)
                }
                wide_ip_entry["pools"].append(pool_entry)

        wide_ip_data.append(wide_ip_entry)

    # Save the gathered data to a JSON file
    with open("f5_wide_ip_data.json", "w") as f:
        json.dump(wide_ip_data, f, indent=4)

    print("✅ Data successfully saved in f5_wide_ip_data.json")

# Run the script
if __name__ == "__main__":
    collect_wide_ip_data()




import requests
import json
import subprocess  # <-- Needed to run cURL commands

# Disable SSL warnings (only for testing, not recommended in production)
requests.packages.urllib3.disable_warnings()

# -------------------------
# 1) LOGIN TO F5
# -------------------------
def login_to_f5():
    f5_host = input("Enter F5 management IP/hostname: ")
    username = input("Enter your username: ")
    password = input("Enter your password: ")

    url = f"https://{f5_host}/mgmt/shared/authn/login"
    headers = {"Content-Type": "application/json"}
    payload = {
        "username": username,
        "password": password,
        "loginProviderName": "tmos"
    }

    response = requests.post(url, headers=headers, json=payload, verify=False)
    if response.status_code == 200:
        print("✅ Successfully logged in!")
        token = response.json().get("token", {}).get("token")
        return token, f5_host
    else:
        print(f"❌ Login failed: {response.status_code} - {response.text}")
        return None, None

# -------------------------
# 2) GET WIDE IPS via cURL
# -------------------------
def get_wide_ips_via_curl(f5_host, token):
    """
    Runs a cURL command in a subprocess to fetch GTM Wide IPs, then returns
    the parsed JSON 'items' array. This bypasses python-requests completely.
    """
    # Construct the cURL command exactly as you tested it on the CLI
    # Note: -s = silent, -k = skip SSL certificate verification
    curl_cmd = [
        "curl",
        "-sk",  # silent + insecure SSL
        "-H", f"X-F5-Auth-Token: {token}",
        f"https://{f5_host}/mgmt/tm/gtm/wideip/a?$expand=all-properties"
    ]

    try:
        # Run the command; capture the output (stdout)
        output = subprocess.check_output(curl_cmd)
        # Decode from bytes to string
        output_str = output.decode("utf-8", errors="replace")

        # Attempt to parse JSON
        data = json.loads(output_str)
        # Return 'items' if it exists
        return data.get("items", [])
    except subprocess.CalledProcessError as cpe:
        print("❌ Error calling cURL:", cpe)
        return []
    except json.JSONDecodeError as je:
        print("❌ Error parsing JSON:", je)
        return []

# -------------------------
# 3) GET POOL DETAILS (via Requests)
# -------------------------
def get_pool_details(f5_host, token, pool_name):
    """
    Fetches pool details for a given pool name using python-requests.
    This uses ?$expand=all-properties. If that fails with 400,
    try '?expandSubcollections=true' or '?$expand=full' or replicate cURL here too.
    """
    url = f"https://{f5_host}/mgmt/tm/gtm/pool/a/{pool_name}?$expand=all-properties"
    headers = {
        "X-F5-Auth-Token": token,
        "Accept": "*/*",
        "Accept-Encoding": "identity"  # optional to disable compression
    }

    response = requests.get(url, headers=headers, verify=False)
    if response.status_code == 200:
        return response.json()
    else:
        print(f"⚠️ Failed to fetch details for pool '{pool_name}' - HTTP {response.status_code}")
        return None

# -------------------------
# 4) EXTRACT POOL MEMBERS
# -------------------------
def extract_pool_members(pool_details):
    """
    Example: a pool member might be named: "10.160.224.64:10_160_224_64_445"
    We'll split on ':' to isolate the IP portion from the port-like suffix.
    """
    members = []
    for member in pool_details.get("members", []):
        raw_address = member["name"]  # e.g. "10.160.224.64:10_160_224_64_445"
        ip_address = raw_address.split(":")[0]
        member_order = member.get("member-order", "Unknown")

        members.append({
            "raw": raw_address,
            "ip": ip_address,
            "order": member_order
        })
    return members

# -------------------------
# 5) MAIN: COLLECT WIDE IP + POOL DATA
# -------------------------
def collect_wide_ip_data():
    token, f5_host = login_to_f5()
    if not token:
        return  # Stop if login failed

    # Get wide IPs via cURL approach
    wide_ips = get_wide_ips_via_curl(f5_host, token)

    wide_ip_data = []
    for wide_ip in wide_ips:
        wide_ip_entry = {
            "name": wide_ip["name"],
            "pool_lb_mode": wide_ip.get("pool-lb-mode", "Unknown"),  # Load balancing method
            "pools": []
        }

        # Each wide_ip can list multiple "pools"
        for pool in wide_ip.get("pools", []):
            pool_name = pool["name"]
            pool_order = pool.get("order", "Unknown")

            # Fetch details for this pool
            pool_details = get_pool_details(f5_host, token, pool_name)
            if pool_details:
                pool_entry = {
                    "name": pool_name,
                    "order": pool_order,
                    "fallback_method": pool_details.get("fallback", "Unknown"),
                    "load_balancing_mode": pool_details.get("load-balancing-mode", "Unknown"),
                    "members": extract_pool_members(pool_details)
                }
                wide_ip_entry["pools"].append(pool_entry)

        wide_ip_data.append(wide_ip_entry)

    # Save data to JSON file
    with open("f5_wide_ip_data.json", "w") as f:
        json.dump(wide_ip_data, f, indent=4)

    print("✅ Data successfully saved in f5_wide_ip_data.json")

# -------------------------
# 6) RUN THE SCRIPT
# -------------------------
if __name__ == "__main__":
    collect_wide_ip_data()












import requests

def get_wide_ips(f5_host, token):
    """
    Fetches Wide IPs from F5 GTM using the iControl REST API.
    Includes adjustments to avoid issues with URL encoding and compression.
    """
    # 1. Construct the URL with the literal $expand
    url = f"https://{f5_host}/mgmt/tm/gtm/wideip/a?$expand=all-properties"

    # 2. Create a requests Session to manage headers and connection pooling
    with requests.Session() as session:
        # 3a. Disable compression (in case F5 does not handle it well)
        session.headers["Accept-Encoding"] = "identity"
        
        # 3b. Set other headers needed
        session.headers.update({
            "X-F5-Auth-Token": token,
            "User-Agent": "curl/7.29.0",  # Mimic curl's UA (optional)
            "Accept": "*/*"
            # NOTE: Do not override 'Host' unless absolutely necessary
        })

        # Debugging prints
        print(f"🔍 Requesting URL: {url}")
        print(f"🔍 Headers: {session.headers}")

        # Disable SSL verification warnings for demonstration (you may want to handle certs properly)
        requests.packages.urllib3.disable_warnings()

        # 4. Send the GET request
        response = session.get(url, verify=False)

        # Debugging prints
        print(f"📡 Response Status Code: {response.status_code}")
        print(f"📡 Response Text: {response.text}")

        # 5. Return items (Wide IPs) or empty list on failure
        if response.status_code == 200:
            return response.json().get("items", [])
        else:
            print(f"❌ Failed to fetch Wide IPs: HTTP {response.status_code}")
            return []



import requests
from urllib.parse import quote

def get_wide_ips(f5_host, token):
    # Encode the $expand query parameter
    encoded_expand = quote("$expand=all-properties")

    # Construct the URL
    url = f"https://{f5_host}/mgmt/tm/gtm/wideip/a?{encoded_expand}"

    # Headers to mimic curl
    headers = {
        "X-F5-Auth-Token": token,
        "User-Agent": "curl/7.29.0",
        "Accept": "*/*",
        "Host": f5_host  # Ensure the correct Host header
    }

    # Print request details for debugging
    print(f"Requesting URL: {url}")
    print(f"Headers: {headers}")

    # Make the GET request with SSL verification disabled
    response = requests.get(url, headers=headers, verify=False)

    # Print response details for debugging
    print(f"Response Status Code: {response.status_code}")
    print(f"Response Text: {response.text}")

    # Return data if successful
    if response.status_code == 200:
        return response.json().get("items", [])
    else:
        print(f"❌ Failed to fetch Wide IPs: {response.status_code}")
        return []





import requests
import json

# Disable SSL warnings (only for testing, not recommended in production)
requests.packages.urllib3.disable_warnings()

# Function to log in and get an authentication token
def login_to_f5():
    f5_host = input("Enter F5 management IP/hostname: ")
    username = input("Enter your username: ")
    password = input("Enter your password: ")

    url = f"https://{f5_host}/mgmt/shared/authn/login"
    headers = {"Content-Type": "application/json"}
    payload = {
        "username": username,
        "password": password,
        "loginProviderName": "tmos"
    }

    response = requests.post(url, headers=headers, json=payload, verify=False)
    if response.status_code == 200:
        print("✅ Successfully logged in!")
        return response.json().get("token", {}).get("token"), f5_host
    else:
        print(f"❌ Login failed: {response.status_code} - {response.text}")
        return None, None

# Function to fetch all Wide IPs
def get_wide_ips_via_curl(f5_host, token):
    """
    Runs a cURL command in a subprocess to fetch GTM Wide IPs, then returns
    the parsed JSON 'items' array. This bypasses python-requests completely.
    """
    # Construct the cURL command exactly as you tested it on the CLI
    # Note: -s = silent, -k = skip SSL certificate verification
    curl_cmd = [
        "curl",
        "-sk",  # silent + insecure SSL
        "-H", f"X-F5-Auth-Token: {token}",
        f"https://{f5_host}/mgmt/tm/gtm/wideip/a?$expand=all-properties"
    ]

    try:
        # Run the command; capture the output (stdout)
        output = subprocess.check_output(curl_cmd)
        # Decode from bytes to string
        output_str = output.decode("utf-8", errors="replace")

        # Attempt to parse JSON
        data = json.loads(output_str)
        # Return 'items' if it exists
        return data.get("items", [])
    except subprocess.CalledProcessError as cpe:
        print("❌ Error calling cURL:", cpe)
        return []
    except json.JSONDecodeError as je:
        print("❌ Error parsing JSON:", je)
        return []

# Function to fetch pool details for a given pool name
def get_pool_details(f5_host, token, pool_name):
    url = f"https://{f5_host}/mgmt/tm/gtm/pool/a/{pool_name}?$expand=all-properties"
    headers = {"X-F5-Auth-Token": token}

    response = requests.get(url, headers=headers, verify=False)
    if response.status_code == 200:
        return response.json()
    else:
        print(f"⚠️ Failed to fetch details for pool: {pool_name}")
        return None

# Function to extract pool members (getting the IP before ":")
def extract_pool_members(pool_details):
    members = []
    for member in pool_details.get("members", []):
        raw_address = member["name"]  # Example: "10.160.224.64:10_160_224_64_445"
        ip_address = raw_address.split(":")[0]  # Extracting only the IP part
        member_order = member.get("member-order", "Unknown")
        members.append({
            "raw": raw_address,
            "ip": ip_address,
            "order": member_order
        })
    return members

# Main function to gather Wide IP and Pool data
def collect_wide_ip_data():
    token, f5_host = login_to_f5()
    if not token:
        return

    wide_ips = get_wide_ips(f5_host, token)
    wide_ip_data = []

    for wide_ip in wide_ips:
        wide_ip_entry = {
            "name": wide_ip["name"],
            "pool_lb_mode": wide_ip.get("pool-lb-mode", "Unknown"),  # Load balancing method for selecting pools
            "pools": []
        }

        for pool in wide_ip.get("pools", []):
            pool_name = pool["name"]
            pool_order = pool.get("order", "Unknown")
            pool_details = get_pool_details(f5_host, token, pool_name)

            if pool_details:
                pool_entry = {
                    "name": pool_name,
                    "order": pool_order,
                    "fallback_method": pool_details.get("fallback", "Unknown"),
                    "load_balancing_mode": pool_details.get("load-balancing-mode", "Unknown"),
                    "members": extract_pool_members(pool_details)
                }
                wide_ip_entry["pools"].append(pool_entry)

        wide_ip_data.append(wide_ip_entry)

    # Save data to JSON
    with open("f5_wide_ip_data.json", "w") as f:
        json.dump(wide_ip_data, f, indent=4)

    print("✅ Data successfully saved in f5_wide_ip_data.json")

# Run the script
if __name__ == "__main__":
    collect_wide_ip_data()








#!/bin/bash

# Set output file
OUTPUT_FILE="f5_wide_ip_data.json"

# Disable SSL verification for self-signed certs (use with caution)
CURL_OPTS="-sk"

# Function to log in and get authentication token
function login_to_f5() {
    echo "Enter F5 management IP/hostname: "
    read -r F5_HOST
    echo "Enter your username: "
    read -r USERNAME
    echo "Enter your password: "
    read -rs PASSWORD
    echo ""

    LOGIN_RESPONSE=$(curl $CURL_OPTS -H "Content-Type: application/json" -X POST -d '{
        "username": "'"$USERNAME"'",
        "password": "'"$PASSWORD"'",
        "loginProviderName": "tmos"
    }' "https://$F5_HOST/mgmt/shared/authn/login")

    TOKEN=$(echo "$LOGIN_RESPONSE" | jq -r '.token.token')

    if [[ "$TOKEN" == "null" || -z "$TOKEN" ]]; then
        echo "❌ Authentication failed!"
        exit 1
    fi

    echo "✅ Successfully logged in!"
}

# Function to fetch Wide IPs
function get_wide_ips() {
    echo "🔍 Fetching Wide IPs..."
    WIDE_IPS_RESPONSE=$(curl $CURL_OPTS -H "X-F5-Auth-Token: $TOKEN" "https://$F5_HOST/mgmt/tm/gtm/wideip/a?\$expand=all-properties")
    echo "$WIDE_IPS_RESPONSE" > wide_ips.json
}

# Function to fetch pool details for a given pool name
function get_pool_details() {
    POOL_NAME="$1"
    echo "🔍 Fetching Pool Details for: $POOL_NAME..."
    POOL_DETAILS_RESPONSE=$(curl $CURL_OPTS -H "X-F5-Auth-Token: $TOKEN" "https://$F5_HOST/mgmt/tm/gtm/pool/a/$POOL_NAME?\$expand=all-properties")
    echo "$POOL_DETAILS_RESPONSE"
}

# Main function
function collect_f5_data() {
    login_to_f5
    get_wide_ips

    echo "[" > "$OUTPUT_FILE"

    # Loop through each Wide IP and get details
    WIDE_IPS=$(jq -c '.items[]' wide_ips.json)

    FIRST_ITEM=true
    echo "$WIDE_IPS" | while IFS= read -r WIP; do
        WIP_NAME=$(echo "$WIP" | jq -r '.name')
        POOL_LB_MODE=$(echo "$WIP" | jq -r '.pool-lb-mode')

        echo "📌 Processing Wide IP: $WIP_NAME"

        # Start JSON entry
        if [ "$FIRST_ITEM" = true ]; then
            FIRST_ITEM=false
        else
            echo "," >> "$OUTPUT_FILE"
        fi
        echo "{ \"name\": \"$WIP_NAME\", \"pool_lb_mode\": \"$POOL_LB_MODE\", \"pools\": [" >> "$OUTPUT_FILE"

        # Loop through pools
        POOL_ENTRIES=$(echo "$WIP" | jq -c '.pools[]')
        FIRST_POOL=true

        echo "$POOL_ENTRIES" | while IFS= read -r POOL; do
            POOL_NAME=$(echo "$POOL" | jq -r '.name')
            POOL_ORDER=$(echo "$POOL" | jq -r '.order')

            POOL_DETAILS=$(get_pool_details "$POOL_NAME")

            FALLBACK_METHOD=$(echo "$POOL_DETAILS" | jq -r '.fallback')
            LB_MODE=$(echo "$POOL_DETAILS" | jq -r '.load-balancing-mode')

            # Start Pool JSON entry
            if [ "$FIRST_POOL" = true ]; then
                FIRST_POOL=false
            else
                echo "," >> "$OUTPUT_FILE"
            fi
            echo "{ \"name\": \"$POOL_NAME\", \"order\": \"$POOL_ORDER\", \"fallback_method\": \"$FALLBACK_METHOD\", \"load_balancing_mode\": \"$LB_MODE\", \"members\": [" >> "$OUTPUT_FILE"

            # Extract Pool Members
            MEMBERS=$(echo "$POOL_DETAILS" | jq -c '.members[]')
            FIRST_MEMBER=true
            echo "$MEMBERS" | while IFS= read -r MEMBER; do
                RAW_MEMBER=$(echo "$MEMBER" | jq -r '.name')
                MEMBER_IP=$(echo "$RAW_MEMBER" | cut -d':' -f1)
                MEMBER_ORDER=$(echo "$MEMBER" | jq -r '.member-order')

                # Start Member JSON entry
                if [ "$FIRST_MEMBER" = true ]; then
                    FIRST_MEMBER=false
                else
                    echo "," >> "$OUTPUT_FILE"
                fi
                echo "{ \"raw\": \"$RAW_MEMBER\", \"ip\": \"$MEMBER_IP\", \"order\": \"$MEMBER_ORDER\" }" >> "$OUTPUT_FILE"
            done

            # Close members array
            echo "] }" >> "$OUTPUT_FILE"
        done

        # Close pools array
        echo "] }" >> "$OUTPUT_FILE"
    done

    # Close JSON file
    echo "]" >> "$OUTPUT_FILE"
    echo "✅ Data successfully saved in $OUTPUT_FILE"
}

# Run the script
collect_f5_data








import requests
import json
import subprocess

# Disable SSL warnings (only for testing, not recommended in production)
requests.packages.urllib3.disable_warnings()

# Function to log in and get an authentication token
def login_to_f5():
    f5_host = input("Enter F5 management IP/hostname: ")
    username = input("Enter your username: ")
    password = input("Enter your password: ")

    url = f"https://{f5_host}/mgmt/shared/authn/login"
    headers = {"Content-Type": "application/json"}
    payload = {
        "username": username,
        "password": password,
        "loginProviderName": "tmos"
    }

    response = requests.post(url, headers=headers, json=payload, verify=False)
    if response.status_code == 200:
        print("✅ Successfully logged in!")
        return response.json().get("token", {}).get("token"), f5_host
    else:
        print(f"❌ Login failed: {response.status_code} - {response.text}")
        return None, None

# Function to fetch Wide IPs using Bash (`curl`)
def get_wide_ips(f5_host, token):
    try:
        url = f"https://{f5_host}/mgmt/tm/gtm/wideip/a?$expand=all-properties"
        print(f"🔍 Fetching Wide IPs: {url}")

        result = subprocess.run(
            ["curl", "-sk", "-H", f"X-F5-Auth-Token: {token}", url],
            capture_output=True, text=True
        )
        
        wide_ip_data = json.loads(result.stdout)
        return wide_ip_data.get("items", [])
    except Exception as e:
        print(f"⚠️ Failed to fetch Wide IPs: {e}")
        return []

# Function to fetch Pool details using Bash (`curl`)
def get_pool_details(f5_host, token, pool_name):
    try:
        url = f"https://{f5_host}/mgmt/tm/gtm/pool/a/{pool_name}?$expand=all-properties"
        print(f"🔍 Fetching Pool Details: {url}")

        result = subprocess.run(
            ["curl", "-sk", "-H", f"X-F5-Auth-Token: {token}", url],
            capture_output=True, text=True
        )
        
        pool_data = json.loads(result.stdout)
        return pool_data
    except Exception as e:
        print(f"⚠️ Failed to fetch details for pool {pool_name}: {e}")
        return None

# Function to extract pool members (getting the IP before ":")
def extract_pool_members(pool_details):
    members = []
    for member in pool_details.get("members", []):
        raw_address = member["name"]  # Example: "10.160.224.64:10_160_224_64_445"
        ip_address = raw_address.split(":")[0]  # Extracting only the IP part
        member_order = member.get("member-order", "Unknown")
        members.append({
            "raw": raw_address,
            "ip": ip_address,
            "order": member_order
        })
    return members

# Main function to gather Wide IP and Pool data
def collect_wide_ip_data():
    token, f5_host = login_to_f5()
    if not token:
        return

    wide_ips = get_wide_ips(f5_host, token)
    wide_ip_data = []

    for wide_ip in wide_ips:
        wide_ip_entry = {
            "name": wide_ip["name"],
            "pool_lb_mode": wide_ip.get("pool-lb-mode", "Unknown"),  # Load balancing method for selecting pools
            "pools": []
        }

        for pool in wide_ip.get("pools", []):
            pool_name = pool["name"]
            pool_order = pool.get("order", "Unknown")
            pool_details = get_pool_details(f5_host, token, pool_name)

            if pool_details:
                pool_entry = {
                    "name": pool_name,
                    "order": pool_order,
                    "fallback_method": pool_details.get("fallback", "Unknown"),
                    "load_balancing_mode": pool_details.get("load-balancing-mode", "Unknown"),
                    "members": extract_pool_members(pool_details)
                }
                wide_ip_entry["pools"].append(pool_entry)

        wide_ip_data.append(wide_ip_entry)

    # Save data to JSON
    with open("f5_wide_ip_data.json", "w") as f:
        json.dump(wide_ip_data, f, indent=4)

    print("✅ Data successfully saved in f5_wide_ip_data.json")

# Run the script
if __name__ == "__main__":
    collect_wide_ip_data()
















import requests

def get_wide_ips(f5_host, token):
    url = f"https://{f5_host}/mgmt/tm/gtm/wideip/a"

    # Headers that match your working curl request
    headers = {
        "X-F5-Auth-Token": token,
        "User-Agent": "curl/7.29.0",  # Mimic curl exactly
        "Accept": "*/*",  # Curl sends this, so Python should too
        "Content-Type": "application/json",
        "Cache-Control": "no-cache",
        "Connection": "keep-alive"
    }

    # Equivalent to `-k` in curl (disable SSL verification)
    response = requests.get(url, headers=headers, verify=False)

    # Debugging output
    print("Python Sending URL:", url)
    print("Python Sending Headers:", headers)
    print("Response Status Code:", response.status_code)
    print("Response Text:", response.text)

    if response.status_code == 200:
        return response.json().get("items", [])
    else:
        return []




import requests

def get_wide_ips(f5_host, token):
    url = f"https://{f5_host}/mgmt/tm/gtm/wideip/a?%24expand=all-properties"
    headers = {
        "X-F5-Auth-Token": token,
        "Accept": "application/json",
        "Content-Type": "application/json"
    }

    # Debug: Print the exact URL and headers Python is sending
    print("🚀 Python is sending this request:")
    print("🔗 URL:", url)
    print("📌 Headers:", headers)

    # Create a prepared request to inspect the exact request format
    session = requests.Session()
    req = requests.Request("GET", url, headers=headers)
    prepared = session.prepare_request(req)

    print("\n📢 FINAL SENT REQUEST URL:", prepared.url)

    # Send the request
    response = session.send(prepared, verify=False)

    if response.status_code == 200:
        return response.json().get("items", [])
    else:
        print(f"❌ Failed to fetch Wide IPs: {response.status_code}")
        print("🛑 Response Text:", response.text)
        return []



































import requests
import json

# Disable SSL warnings (only for testing, not recommended in production)
requests.packages.urllib3.disable_warnings()

# Function to log in and get an authentication token
def login_to_f5():
    f5_host = input("Enter F5 management IP/hostname: ")
    username = input("Enter your username: ")
    password = input("Enter your password: ")

    url = f"https://{f5_host}/mgmt/shared/authn/login"
    headers = {"Content-Type": "application/json"}
    payload = {
        "username": username,
        "password": password,
        "loginProviderName": "tmos"
    }

    response = requests.post(url, headers=headers, json=payload, verify=False)
    if response.status_code == 200:
        print("✅ Successfully logged in!")
        return response.json().get("token", {}).get("token"), f5_host
    else:
        print(f"❌ Login failed: {response.status_code} - {response.text}")
        return None, None

# Function to fetch all Wide IPs
def get_wide_ips(f5_host, token):
    url = f"https://{f5_host}/mgmt/tm/gtm/wideip/a?$expand=all-properties"
    headers = {"X-F5-Auth-Token": token}

    response = requests.get(url, headers=headers, verify=False)
    if response.status_code == 200:
        return response.json().get("items", [])
    else:
        print(f"❌ Failed to fetch Wide IPs: {response.status_code}")
        return []

# Function to fetch pool details for a given pool name
def get_pool_details(f5_host, token, pool_name):
    url = f"https://{f5_host}/mgmt/tm/gtm/pool/a/{pool_name}?$expand=all-properties"
    headers = {"X-F5-Auth-Token": token}

    response = requests.get(url, headers=headers, verify=False)
    if response.status_code == 200:
        return response.json()
    else:
        print(f"⚠️ Failed to fetch details for pool: {pool_name}")
        return None

# Function to extract pool members (getting the IP before ":")
def extract_pool_members(pool_details):
    members = []
    for member in pool_details.get("members", []):
        raw_address = member["name"]  # Example: "10.160.224.64:10_160_224_64_445"
        ip_address = raw_address.split(":")[0]  # Extracting only the IP part
        member_order = member.get("member-order", "Unknown")
        members.append({
            "raw": raw_address,
            "ip": ip_address,
            "order": member_order
        })
    return members

# Main function to gather Wide IP and Pool data
def collect_wide_ip_data():
    token, f5_host = login_to_f5()
    if not token:
        return

    wide_ips = get_wide_ips(f5_host, token)
    wide_ip_data = []

    for wide_ip in wide_ips:
        wide_ip_entry = {
            "name": wide_ip["name"],
            "pool_lb_mode": wide_ip.get("pool-lb-mode", "Unknown"),  # Load balancing method for selecting pools
            "pools": []
        }

        for pool in wide_ip.get("pools", []):
            pool_name = pool["name"]
            pool_order = pool.get("order", "Unknown")
            pool_details = get_pool_details(f5_host, token, pool_name)

            if pool_details:
                pool_entry = {
                    "name": pool_name,
                    "order": pool_order,
                    "fallback_method": pool_details.get("fallback", "Unknown"),
                    "load_balancing_mode": pool_details.get("load-balancing-mode", "Unknown"),
                    "members": extract_pool_members(pool_details)
                }
                wide_ip_entry["pools"].append(pool_entry)

        wide_ip_data.append(wide_ip_entry)

    # Save data to JSON
    with open("f5_wide_ip_data.json", "w") as f:
        json.dump(wide_ip_data, f, indent=4)

    print("✅ Data successfully saved in f5_wide_ip_data.json")

# Run the script
if __name__ == "__main__":
    collect_wide_ip_data()























import requests
import json

# Disable SSL warnings (only recommended in test environments)
requests.packages.urllib3.disable_warnings()

def login_to_f5():
    f5_host = input("Enter F5 management IP/hostname: ")
    username = input("Enter your username: ")
    password = input("Enter your password: ")

    url = f"https://{f5_host}/mgmt/shared/authn/login"
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json"
    }
    payload = {
        "username": username,
        "password": password,
        "loginProviderName": "tmos"
    }

    response = requests.post(url, headers=headers, json=payload, verify=False)
    if response.status_code == 200:
        # Debug: Print the entire response JSON to confirm we have a token
        print("Login response JSON:", response.json())

        token = response.json().get("token", {}).get("token")
        if token:
            print("✅ Successfully logged in!")
            return token, f5_host, username, password
        else:
            print("❌ Could not extract token from login response.")
            return None, None, None, None
    else:
        print(f"❌ Login failed: {response.status_code} - {response.text}")
        return None, None, None, None

def get_all_wide_ips(f5_host, token):
    """
    Fetches the basic list of Wide IPs without using ?$expand.
    This should return at least the Wide IP names and references to their pools.
    """
    url = f"https://{f5_host}/mgmt/tm/gtm/wideip/a"
    headers = {
        "X-F5-Auth-Token": token,
        "Content-Type": "application/json",
        "Accept": "application/json"
    }

    print(f"GET: {url}")
    response = requests.get(url, headers=headers, verify=False)
    if response.status_code == 200:
        data = response.json()
        return data.get("items", [])
    else:
        print(f"❌ Failed to fetch Wide IPs: {response.status_code}")
        print("Response text:", response.text)
        return []

def get_wideip_pools(pools_link, headers):
    """
    Given the wide IP's 'poolsReference.link', fetch the actual pool info (basic).
    """
    print(f"GET pools for wide IP: {pools_link}")
    response = requests.get(pools_link, headers=headers, verify=False)
    if response.status_code == 200:
        data = response.json()
        return data.get("items", [])
    else:
        print("⚠️ Failed to fetch pools from:", pools_link)
        print("Status code:", response.status_code, "Response text:", response.text)
        return []

def get_pool_details(pool_selfLink, headers):
    """
    pool_selfLink is typically from pool["selfLink"], e.g.:
      "https://<host>/mgmt/tm/gtm/pool/a/~Common~mypool?ver=..."
    """
    print(f"GET pool details: {pool_selfLink}")
    response = requests.get(pool_selfLink, headers=headers, verify=False)
    if response.status_code == 200:
        return response.json()
    else:
        print(f"⚠️ Failed to fetch details for pool at link: {pool_selfLink}")
        print(f"Status code: {response.status_code}, Response text: {response.text}")
        return None

def extract_pool_members(pool_details):
    members = []
    for member in pool_details.get("members", []):
        # e.g. "10.160.224.64:10_160_224_64_445"
        raw_address = member["name"]
        ip_address = raw_address.split(":")[0]
        member_order = member.get("member-order", "Unknown")
        members.append({
            "raw": raw_address,
            "ip": ip_address,
            "order": member_order
        })
    return members

def collect_wide_ip_data():
    # 1) Log in and get token
    token, f5_host, username, password = login_to_f5()
    if not token:
        return

    # 2) Fetch the list of Wide IPs
    wide_ips = get_all_wide_ips(f5_host, token)

    # Prepare common headers for subsequent requests
    headers = {
        "X-F5-Auth-Token": token,
        "Content-Type": "application/json",
        "Accept": "application/json"
    }

    wide_ip_data = []

    # 3) For each Wide IP, get pool references, then pool details
    for wip in wide_ips:
        wip_name = wip.get("name", "Unknown")
        wip_entry = {
            "name": wip_name,
            "pools": []
        }
        # Some basic info about the WIP that might exist
        # (Check keys in your environment; "pool-lb-mode" might or might not appear)
        if "pool-lb-mode" in wip:
            wip_entry["pool_lb_mode"] = wip["pool-lb-mode"]

        # The 'poolsReference' key should point to a subcollection link
        pools_ref = wip.get("poolsReference", {})
        pools_link = pools_ref.get("link")

        if pools_link:
            # 4) Fetch the wide IP's pools
            pools = get_wideip_pools(pools_link, headers)
            for p in pools:
                pool_selfLink = p.get("selfLink", "")
                pool_name = p.get("name", "Unknown")

                # 5) Fetch the pool's *full* details, including members
                pool_details = get_pool_details(pool_selfLink, headers)
                if pool_details:
                    pool_entry = {
                        "name": pool_details.get("name", pool_name),
                        "fallback_method": pool_details.get("fallback", "Unknown"),
                        "load_balancing_mode": pool_details.get("load-balancing-mode", "Unknown"),
                        "members": extract_pool_members(pool_details)
                    }
                    wip_entry["pools"].append(pool_entry)
        else:
            print(f"⚠️ Wide IP {wip_name} has no 'poolsReference' link. Possibly no pools?")

        wide_ip_data.append(wip_entry)

    # 6) Save final data to JSON
    with open("f5_wide_ip_data.json", "w") as f:
        json.dump(wide_ip_data, f, indent=4)

    print("✅ Data successfully saved in f5_wide_ip_data.json")

if __name__ == "__main__":
    collect_wide_ip_data()


def get_wide_ips(f5_host, token):
    # Base URL without query
    url = f"https://{f5_host}/mgmt/tm/gtm/wideip/a"
    
    # Headers
    headers = {
        "X-F5-Auth-Token": token,
        "Content-Type": "application/json",
        "Accept": "application/json"
    }

    # Manually append the query parameter, but use '%24expand' (URL-encoded '$')
    # instead of '$expand' to avoid issues.
    url_with_expand = f"{url}?%24expand=all-properties"
    
    # Debug print, so you can confirm final URL
    print("Requesting Wide IPs from:", url_with_expand)

    # Perform GET
    response = requests.get(url_with_expand, headers=headers, verify=False)
    if response.status_code == 200:
        return response.json().get("items", [])
    else:
        print(f"❌ Failed to fetch Wide IPs: {response.status_code}")
        print("Response text:", response.text)  # Print the full error message
        return []



import requests
import json

# Disable SSL warnings (only for testing, not recommended in production)
requests.packages.urllib3.disable_warnings()

def login_to_f5():
    f5_host = input("Enter F5 management IP/hostname: ")
    username = input("Enter your username: ")
    password = input("Enter your password: ")

    url = f"https://{f5_host}/mgmt/shared/authn/login"
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json"
    }
    payload = {
        "username": username,
        "password": password,
        "loginProviderName": "tmos"
    }

    response = requests.post(url, headers=headers, json=payload, verify=False)
    if response.status_code == 200:
        # Debug: Print the entire response JSON to see if token is returned as expected
        print("Login response JSON:", response.json())

        token = response.json().get("token", {}).get("token")
        if token:
            print("✅ Successfully logged in!")
            return token, f5_host, username, password
        else:
            print("❌ Could not extract token from login response.")
            return None, None, None, None
    else:
        print(f"❌ Login failed: {response.status_code} - {response.text}")
        return None, None, None, None

def get_wide_ips(f5_host, token):
    url = f"https://{f5_host}/mgmt/tm/gtm/wideip/a"
    headers = {
        "X-F5-Auth-Token": token,
        "Content-Type": "application/json",
        "Accept": "application/json"
    }
    # Use the 'params' argument to safely add the query parameter
    params = {
        '$expand': 'all-properties'
    }

    print(f"Requesting Wide IPs from: {url} with params: {params}")  # Debug line

    response = requests.get(url, headers=headers, params=params, verify=False)
    if response.status_code == 200:
        return response.json().get("items", [])
    else:
        print(f"❌ Failed to fetch Wide IPs: {response.status_code}")
        print("Response text:", response.text)  # Print the full error for debugging
        return []

def get_pool_details(f5_host, token, pool_name):
    url = f"https://{f5_host}/mgmt/tm/gtm/pool/a/{pool_name}"
    headers = {
        "X-F5-Auth-Token": token,
        "Content-Type": "application/json",
        "Accept": "application/json"
    }
    # If needed, also expand pool properties
    params = {
        '$expand': 'all-properties'
    }

    response = requests.get(url, headers=headers, params=params, verify=False)
    if response.status_code == 200:
        return response.json()
    else:
        print(f"⚠️ Failed to fetch details for pool: {pool_name}")
        print(f"Status code: {response.status_code}, Response text: {response.text}")
        return None

def extract_pool_members(pool_details):
    members = []
    for member in pool_details.get("members", []):
        raw_address = member["name"]  # e.g., "10.160.224.64:10_160_224_64_445"
        ip_address = raw_address.split(":")[0]
        member_order = member.get("member-order", "Unknown")
        members.append({
            "raw": raw_address,
            "ip": ip_address,
            "order": member_order
        })
    return members

def collect_wide_ip_data():
    token, f5_host, username, password = login_to_f5()
    if not token:
        return

    wide_ips = get_wide_ips(f5_host, token)
    wide_ip_data = []

    for wide_ip in wide_ips:
        wide_ip_entry = {
            "name": wide_ip["name"],
            "pool_lb_mode": wide_ip.get("pool-lb-mode", "Unknown"),
            "pools": []
        }

        for pool in wide_ip.get("pools", []):
            pool_name = pool["name"]
            pool_order = pool.get("order", "Unknown")
            pool_details = get_pool_details(f5_host, token, pool_name)

            if pool_details:
                pool_entry = {
                    "name": pool_name,
                    "order": pool_order,
                    "fallback_method": pool_details.get("fallback", "Unknown"),
                    "load_balancing_mode": pool_details.get("load-balancing-mode", "Unknown"),
                    "members": extract_pool_members(pool_details)
                }
                wide_ip_entry["pools"].append(pool_entry)

        wide_ip_data.append(wide_ip_entry)

    # Save to JSON
    with open("f5_wide_ip_data.json", "w") as f:
        json.dump(wide_ip_data, f, indent=4)

    print("✅ Data successfully saved in f5_wide_ip_data.json")

if __name__ == "__main__":
    collect_wide_ip_data()



import requests
import json

# Disable SSL warnings (only for testing, not recommended in production)
requests.packages.urllib3.disable_warnings()

def login_to_f5():
    f5_host = input("Enter F5 management IP/hostname: ")
    username = input("Enter your username: ")
    password = input("Enter your password: ")

    url = f"https://{f5_host}/mgmt/shared/authn/login"
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json"
    }
    payload = {
        "username": username,
        "password": password,
        "loginProviderName": "tmos"
    }

    response = requests.post(url, headers=headers, json=payload, verify=False)
    if response.status_code == 200:
        # Print the entire response JSON to debug token extraction
        print("Login response JSON:", response.json())

        # Extract token
        token = response.json().get("token", {}).get("token")
        if token:
            print("✅ Successfully logged in!")
            return token, f5_host, username, password
        else:
            print("❌ Could not extract token from login response.")
            return None, None, None, None
    else:
        print(f"❌ Login failed: {response.status_code} - {response.text}")
        return None, None, None, None

def get_wide_ips(f5_host, token):
    # Defaulting to A-type Wide IPs; change if you need AAAA or CNAME type
    url = f"https://{f5_host}/mgmt/tm/gtm/wideip/a?$expand=all-properties"
    headers = {
        "X-F5-Auth-Token": token,
        "Content-Type": "application/json",
        "Accept": "application/json"
    }

    response = requests.get(url, headers=headers, verify=False)
    if response.status_code == 200:
        return response.json().get("items", [])
    else:
        print(f"❌ Failed to fetch Wide IPs: {response.status_code}")
        print("Response text:", response.text)  # Print full error
        return []

def get_pool_details(f5_host, token, pool_name):
    url = f"https://{f5_host}/mgmt/tm/gtm/pool/a/{pool_name}?$expand=all-properties"
    headers = {
        "X-F5-Auth-Token": token,
        "Content-Type": "application/json",
        "Accept": "application/json"
    }

    response = requests.get(url, headers=headers, verify=False)
    if response.status_code == 200:
        return response.json()
    else:
        print(f"⚠️ Failed to fetch details for pool: {pool_name}")
        print(f"Status code: {response.status_code}, Response text: {response.text}")
        return None

def extract_pool_members(pool_details):
    members = []
    for member in pool_details.get("members", []):
        raw_address = member["name"]  # e.g., "10.160.224.64:10_160_224_64_445"
        ip_address = raw_address.split(":")[0]  # Extract IP before colon
        member_order = member.get("member-order", "Unknown")
        members.append({
            "raw": raw_address,
            "ip": ip_address,
            "order": member_order
        })
    return members

def collect_wide_ip_data():
    token, f5_host, username, password = login_to_f5()
    if not token:
        return

    wide_ips = get_wide_ips(f5_host, token)
    wide_ip_data = []

    for wide_ip in wide_ips:
        wide_ip_entry = {
            "name": wide_ip["name"],
            "pool_lb_mode": wide_ip.get("pool-lb-mode", "Unknown"),  # LB method for selecting pools
            "pools": []
        }

        for pool in wide_ip.get("pools", []):
            pool_name = pool["name"]
            pool_order = pool.get("order", "Unknown")
            pool_details = get_pool_details(f5_host, token, pool_name)

            if pool_details:
                pool_entry = {
                    "name": pool_name,
                    "order": pool_order,
                    "fallback_method": pool_details.get("fallback", "Unknown"),
                    "load_balancing_mode": pool_details.get("load-balancing-mode", "Unknown"),
                    "members": extract_pool_members(pool_details)
                }
                wide_ip_entry["pools"].append(pool_entry)

        wide_ip_data.append(wide_ip_entry)

    # Save data to JSON
    with open("f5_wide_ip_data.json", "w") as f:
        json.dump(wide_ip_data, f, indent=4)

    print("✅ Data successfully saved in f5_wide_ip_data.json")

# Run the script
if __name__ == "__main__":
    collect_wide_ip_data()



curl -sk -X POST https://192.168.1.1/mgmt/shared/authn/login \
     -H "Content-Type: application/json" \
     -d '{"username":"admin","password":"mypassword","loginProviderName":"tmos"}'



import requests

# Disable SSL warnings (use only for testing, not recommended for production)
requests.packages.urllib3.disable_warnings()

def login_to_f5():
    # Get user input for credentials and F5 host
    f5_host = input("Enter F5 management IP/hostname (e.g., https://<BIG-IP-IP>): ").strip()
    username = input("Enter your username: ").strip()
    password = input("Enter your password: ").strip()

    # Login URL
    url = f"{f5_host}/mgmt/shared/authn/login"
    headers = {"Content-Type": "application/json"}
    payload = {
        "username": username,
        "password": password,
        "loginProviderName": "tmos"
    }

    try:
        # Send POST request to authenticate
        response = requests.post(url, headers=headers, json=payload, verify=False)

        # Check for success or failure
        if response.status_code == 200:
            print("✅ Successfully logged in!")
            token = response.json().get("token", {}).get("token")
            if token:
                print(f"🔑 Authentication Token: {token}")
            return token
        elif response.status_code == 401:
            print("❌ Unauthorized: Invalid credentials.")
        else:
            print(f"❌ Error: {response.status_code} - {response.text}")
    except requests.exceptions.RequestException as e:
        print(f"❌ Connection error: {e}")

if __name__ == "__main__":
    login_to_f5()




from netmiko import ConnectHandler
from getpass import getpass
import os

# List of device hostnames
devices = [
    "device1",
    "gbgb",  # Example device that will fail to connect
    "device3",
    # Add more devices as needed
]

# Commands to execute on devices
commands = [
    "show license usage",
    "show version",
    # Add more commands as needed
]

def connect_to_device(hostname, username, password, commands, output_file):
    """Connects to a device using Netmiko and runs multiple commands."""
    try:
        # Define device parameters
        device = {
            "device_type": "cisco_ios",  # Change this to match your device type
            "host": hostname,
            "username": username,
            "password": password,
        }

        # Connect to the device
        connection = ConnectHandler(**device)

        # Append the output for each command
        with open(output_file, "a") as file:
            file.write(f"--- Output for {hostname} ---\n")
            for command in commands:
                file.write(f"\n>>> Command: {command}\n")
                output = connection.send_command(command)
                file.write(output + "\n")
            file.write("\n" + "=" * 50 + "\n\n")

        print(f"Output for {hostname} saved in {output_file}")
        connection.disconnect()

    except Exception as e:
        # Log the error for the device
        error_file = "error_log.txt"
        with open(error_file, "a") as log:
            log.write(f"Failed to connect to {hostname}: {e}\n")
        print(f"Failed to connect to {hostname}: {e}")
        # Skip the current device and continue with others

def main():
    # Ask for username and password once
    username = input("Enter your username: ")
    password = getpass("Enter your password: ")  # Secure password input

    # Define the single output file name
    output_file = "all_device_outputs.txt"

    # Clear the file at the start (if it already exists)
    with open(output_file, "w") as file:
        file.write("Device Command Outputs\n")
        file.write("=" * 50 + "\n\n")

    # Iterate over devices and run the commands
    for device in devices:
        print(f"Connecting to {device}...")
        connect_to_device(device, username, password, commands, output_file)

    print("All tasks completed. Check all_device_outputs.txt for results.")
    print("Check error_log.txt for failures, if any.")

if __name__ == "__main__":
    main()







Dim managerRaw As String
Dim managerClean As String

managerRaw = .manager ' Get the raw manager DN
If managerRaw <> "" Then
    ' Remove "CN=" and anything after a comma
    managerClean = Replace(managerRaw, "CN=", "")
    managerClean = Replace(managerClean, "\", "") ' Remove the slash
    managerClean = Left(managerClean, InStr(managerClean, ",") - 1) ' Extract until first comma
Else
    managerClean = "N/A" ' Handle cases where manager is not set
End If

' Write the cleaned name to the Manager column
shtADQuery.[ra_Results_Manager].Offset(IngRowOffset, 0).Value = managerClean


import subprocess

# Define the subnet details
subnets = ["10.244.230", "10.244.231"]  # Covers the full /23 range
start_ip = 0
end_ip = 255

# Output file to save results
output_file = "nslookup_results_10.244.230.0_23.txt"

print(f"Starting nslookup scan for /23 subnet: {subnets[0]}.0 to {subnets[1]}.255")
with open(output_file, "w") as file:
    for subnet in subnets:
        for i in range(start_ip, end_ip + 1):
            ip = f"{subnet}.{i}"
            try:
                # Run nslookup for the current IP
                result = subprocess.run(["nslookup", ip], capture_output=True, text=True, timeout=3)

                # Write the raw output to the file
                file.write(f"Results for {ip}:\n")
                file.write(result.stdout + "\n")
                file.write("-" * 50 + "\n")  # Separator for readability
                print(f"Checked {ip}, results saved.")
            except subprocess.TimeoutExpired:
                print(f"{ip} timed out.")
                file.write(f"Results for {ip}:\nTimeout\n")
                file.write("-" * 50 + "\n")
            except Exception as e:
                print(f"Error for {ip}: {e}")
                file.write(f"Results for {ip}:\nError: {e}\n")
                file.write("-" * 50 + "\n")

print(f"Scan completed. Results saved to {output_file}")



import subprocess

# Define your subnet range
subnet = "10.344.344"
start_ip = 1
end_ip = 254

# Open a file to save raw results
output_file = "nslookup_raw_results.txt"

print(f"Starting nslookup scan for {subnet}.{start_ip}-{end_ip}")
with open(output_file, "w") as file:
    for i in range(start_ip, end_ip + 1):
        ip = f"{subnet}.{i}"
        try:
            # Run nslookup for the current IP
            result = subprocess.run(["nslookup", ip], capture_output=True, text=True, timeout=3)

            # Write the raw output to the file
            file.write(f"Results for {ip}:\n")
            file.write(result.stdout + "\n")
            file.write("-" * 50 + "\n")  # Separator for readability
            print(f"Checked {ip}, results saved.")
        except subprocess.TimeoutExpired:
            print(f"{ip} timed out.")
            file.write(f"Results for {ip}:\nTimeout\n")
            file.write("-" * 50 + "\n")
        except Exception as e:
            print(f"Error for {ip}: {e}")
            file.write(f"Results for {ip}:\nError: {e}\n")
            file.write("-" * 50 + "\n")

print(f"Scan completed. Raw results saved to {output_file}")



import sys
import os
import shutil
from PyQt5.QtWidgets import QApplication, QWidget, QVBoxLayout, QPushButton, QLabel, QTextEdit, QFileDialog
from PyQt5.QtGui import QDesktopServices
from PyQt5.QtCore import pyqtSlot, QUrl
from datetime import datetime, timedelta
from PyQt5.QtWidgets import QLabel
from PyQt5.QtCore import pyqtSignal


import numpy as np
from tensorflow import keras
from keras.preprocessing import image
from keras.applications.mobilenet_v2 import MobileNetV2, preprocess_input, decode_predictions







class ClickableLabel(QLabel):
    clicked = pyqtSignal()  # Define the signal

    def mousePressEvent(self, event):
        self.clicked.emit()  # Emit the signal


class FileOrganizerApp(QWidget):
    def __init__(self, auto_run=False):
        super().__init__()
        self.image_model = MobileNetV2(weights='imagenet')
        self.initUI()
        
        if auto_run:
            self.organize_files()
        
    def initUI(self):
        layout = QVBoxLayout()

        self.srcDirLabel = QLabel("Source Directory:")
        self.srcDirPathLabel = ClickableLabel("C:/Users/dania/Desktop")  # Default directory
        self.chooseDirButton = QPushButton("Choose Directory", self)
        self.organizeButton = QPushButton("Organize Files", self)
        self.viewHistoryButton = QPushButton("View History", self)
        self.logDisplay = QTextEdit(self)
        self.logDisplay.setReadOnly(True)

        layout.addWidget(self.srcDirLabel)
        layout.addWidget(self.srcDirPathLabel)
        layout.addWidget(self.chooseDirButton)
        layout.addWidget(self.organizeButton)
        layout.addWidget(self.viewHistoryButton)
        layout.addWidget(self.logDisplay)

        self.chooseDirButton.clicked.connect(self.choose_directory)
        self.organizeButton.clicked.connect(self.organize_files)
        self.viewHistoryButton.clicked.connect(self.show_history)
        self.srcDirPathLabel.clicked.connect(self.open_folder_in_explorer)

        self.setLayout(layout)
        self.setWindowTitle('Desktop File Organizer')
        self.show()

    @pyqtSlot()
    def choose_directory(self):
        dir_path = QFileDialog.getExistingDirectory(self, "Select Directory")
        if dir_path:
            self.srcDirPathLabel.setText(dir_path)

    @pyqtSlot()
    def organize_files(self):
        src_dir = self.srcDirPathLabel.text()
        self.logDisplay.append(f"Organizing files from {src_dir}")
        self.organize_desktop(src_dir)
        self.logDisplay.append("Organization completed.")

    @pyqtSlot()
    def open_folder_in_explorer(self):
        folder_path = self.srcDirPathLabel.text()
        QDesktopServices.openUrl(QUrl.fromLocalFile(folder_path))

    def log_move(self, src, dst):
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        message = f"[{timestamp}] Moved '{src}' to '{dst}'\n"
        self.logDisplay.append(message)

        with open('file_move_history.log', 'a') as log_file:
            log_file.write(message)

    def move_with_rename(self, src, dst):
        if not os.path.exists(dst):
            shutil.move(src, dst)
            self.log_move(src, dst)
        else:
            base, extension = os.path.splitext(dst)
            counter = 1
            new_dst = f"{base} ({counter}){extension}"
            while os.path.exists(new_dst):
                counter += 1
                new_dst = f"{base} ({counter}){extension}"
            shutil.move(src, new_dst)
            self.log_move(src, new_dst)

    def classify_image(self, img_path):
        img = image.load_img(img_path, target_size=(224, 224))
        img_array = image.img_to_array(img)
        img_array = np.expand_dims(img_array, axis=0)
        img_array = preprocess_input(img_array)

        predictions = self.image_model.predict(img_array)
        decoded_predictions = decode_predictions(predictions, top=1)[0][0]
        return decoded_predictions[1]  # Return the most likely category label

    def organize_desktop(self, desktop_path):
        # Define paths...
        documents_path = r"C:\Users\dania\OneDrive\Documenti\PDF"
        python_projects_path = r"C:\Users\dania\OneDrive\Documenti\Projects"
        downloads_path = r"C:\Users\dania\Downloads"
        screenshots_path = r"C:\Users\dania\OneDrive\Immagini\Screenshots"
        other_images_path = r"C:\Users\dania\OneDrive\Immagini\Other"
        word_documents_path = r"C:\Users\dania\OneDrive\Documenti\World Documents"


        files_on_desktop = [os.path.join(desktop_path, f) for f in os.listdir(desktop_path) if os.path.isfile(os.path.join(desktop_path, f))]

        for img_file in [f for f in files_on_desktop if f.endswith(('.jpg', '.png', '.gif', '.jpeg', '.avif'))]:
            full_img_path = os.path.join(desktop_path, img_file)
            category = self.classify_image(full_img_path)

            if "screenshot" in category.lower():
                destination = os.path.join(screenshots_path, os.path.basename(img_file))
            else:
                new_name = f"{category}_{os.path.basename(img_file)}"
                destination = os.path.join(other_images_path, new_name)

            self.move_with_rename(full_img_path, destination)

        # Continue organizing other file types as before
        # ...
        # Organize PDFs
        for pdf in [f for f in files_on_desktop if f.endswith('.pdf')]:
            self.move_with_rename(pdf, os.path.join(documents_path, os.path.basename(pdf)))

        # Organize .py files
        for py_file in [f for f in files_on_desktop if f.endswith('.py')]:
            self.move_with_rename(py_file, os.path.join(python_projects_path, os.path.basename(py_file)))

        # Organize .zip files
        for zip_file in [f for f in files_on_desktop if f.endswith('.zip')]:
            self.move_with_rename(zip_file, os.path.join( downloads_path, os.path.basename(zip_file)))

        for doc_file in [f for f in files_on_desktop if f.endswith('.docx')]:
            self.move_with_rename(doc_file, os.path.join(word_documents_path, os.path.basename(doc_file)))

    def read_log_history(self):
        two_weeks_ago = datetime.now() - timedelta(days=14)
        history = ""

        with open('file_move_history.log', 'r') as log_file:
            for line in log_file:
                if line.strip():
                    timestamp_str = line.split(']')[0].strip('[')
                    timestamp = datetime.strptime(timestamp_str, '%Y-%m-%d %H:%M:%S')
                    if timestamp > two_weeks_ago:
                        history += line

        return history

    def show_history(self):
        history = self.read_log_history()
        self.logDisplay.clear()
        self.logDisplay.append(history)

if __name__ == '__main__':
    app = QApplication(sys.argv)
    auto_run_flag = '--auto-run' in sys.argv
    ex = FileOrganizerApp(auto_run=auto_run_flag)
    if not auto_run_flag:
        sys.exit(app.exec_())  # Only start the event loop if not auto-running
import subprocess

# Define your subnet range
subnet = "10.344.344"
start_ip = 1
end_ip = 254

# Open a file to save results
output_file = "nslookup_results.txt"

print(f"Starting nslookup scan for {subnet}.{start_ip}-{end_ip}")
with open(output_file, "w") as file:
    for i in range(start_ip, end_ip + 1):
        ip = f"{subnet}.{i}"
        try:
            # Run nslookup for the current IP
            result = subprocess.run(["nslookup", ip], capture_output=True, text=True, timeout=3)
            
            # Process the result
            if "name =" in result.stdout.lower():
                hostname = result.stdout.split("name =")[1].strip().split("\n")[0]
                print(f"{ip} resolves to {hostname}")
                file.write(f"{ip} resolves to {hostname}\n")
            else:
                print(f"{ip} does not resolve to a hostname")
                file.write(f"{ip} does not resolve to a hostname\n")
        except subprocess.TimeoutExpired:
            print(f"{ip} timed out")
            file.write(f"{ip}: Timeout\n")
        except Exception as e:
            print(f"Error for {ip}: {e}")
            file.write(f"{ip}: Error: {e}\n")

print(f"Scan completed. Results saved to {output_file}")
