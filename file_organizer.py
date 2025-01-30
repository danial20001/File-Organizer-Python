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
