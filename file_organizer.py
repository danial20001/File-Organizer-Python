import json
import subprocess
import requests
import time

# Disable SSL warnings (only for testing, not recommended in production)
requests.packages.urllib3.disable_warnings()

class F5TokenManager:
    def __init__(self, f5_host, username, password):
        self.f5_host = f5_host
        self.username = username
        self.password = password
        self.token = None
        self.refresh_token = None
        self.login()

    def login(self):
        url = f"https://{self.f5_host}/mgmt/shared/authn/login"
        headers = {"Content-Type": "application/json"}
        payload = {
            "username": self.username,
            "password": self.password,
            "loginProviderName": "tmos"
        }

        response = requests.post(url, headers=headers, json=payload, verify=False)
        if response.status_code == 200:
            data = response.json()
            self.token = data["token"]["token"]
            # Store the refresh token if available
            self.refresh_token = data["token"].get("refreshToken")
            print("✅ Successfully logged in!")
        else:
            print(f"❌ Login failed: {response.status_code} - {response.text}")
            raise Exception("Login failed")

    def refresh(self):
        """Refresh the access token"""
        url = f"https://{self.f5_host}/mgmt/shared/authn/exchange"
        headers = {
            "Content-Type": "application/json",
            "X-F5-Auth-Token": self.token
        }
        
        try:
            response = requests.post(url, headers=headers, verify=False)
            if response.status_code == 200:
                data = response.json()
                self.token = data["token"]["token"]
                print("✅ Token refreshed successfully")
            else:
                print("❌ Token refresh failed, performing new login")
                self.login()
        except Exception as e:
            print(f"Error during token refresh: {e}")
            self.login()

    def get_token(self):
        """Get the current token, refreshing if necessary"""
        return self.token

def get_wide_ips(token_manager):
    url = f"https://{token_manager.f5_host}/mgmt/tm/gtm/wideip/a?$expand=all-properties"
    header = f"X-F5-Auth-Token: {token_manager.get_token()}"
    cmd = ["curl", "-k", "-H", header, url]
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        data = json.loads(result.stdout)
        return data.get("items", [])
    except subprocess.CalledProcessError as e:
        if "401" in str(e.stderr):
            token_manager.refresh()
            # Retry once with new token
            header = f"X-F5-Auth-Token: {token_manager.get_token()}"
            cmd = ["curl", "-k", "-H", header, url]
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            data = json.loads(result.stdout)
            return data.get("items", [])
        print("Curl command failed:", e.stderr)
    except Exception as e:
        print("Error processing JSON response:", e)
    
    return []

def get_pool_details(token_manager, pool_name):
    url = f"https://{token_manager.f5_host}/mgmt/tm/gtm/pool/a/{pool_name}?$expand=all-properties"
    header = f"X-F5-Auth-Token: {token_manager.get_token()}"
    cmd = ["curl", "-k", "-H", header, url]
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        data = json.loads(result.stdout)
        return data
    except subprocess.CalledProcessError as e:
        if "401" in str(e.stderr):
            token_manager.refresh()
            # Retry once with new token
            header = f"X-F5-Auth-Token: {token_manager.get_token()}"
            cmd = ["curl", "-k", "-H", header, url]
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            data = json.loads(result.stdout)
            return data
        print(f"Curl command failed for pool '{pool_name}':", e.stderr)
    except Exception as e:
        print("Error processing JSON response:", e)
    
    return None

def extract_pool_members(pool_details):
    members = []
    for member in pool_details.get("members", []):
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
    f5_host = input("Enter F5 management IP/hostname: ")
    username = input("Enter your username: ")
    password = input("Enter your password: ")

    token_manager = F5TokenManager(f5_host, username, password)
    wide_ips = get_wide_ips(token_manager)
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
            pool_details = get_pool_details(token_manager, pool_name)

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
