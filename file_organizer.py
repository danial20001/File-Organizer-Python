from datetime import datetime
import requests

def convert_epoch_to_date(epoch_time):
    """Convert Unix timestamp to a human-readable date format"""
    try:
        return datetime.utcfromtimestamp(int(epoch_time)).strftime('%Y-%m-%d %H:%M:%S UTC')
    except (ValueError, TypeError):
        return "Unknown"

def get_f5_certificates(credentials: dict, device_list: list) -> None:
    for f5_device in device_list:
        device = f5_device['device']
        device_ip = f5_device['ip']

        # Fetch all SSL certificates
        cert_response = requests.get(
            f"https://{device_ip}/mgmt/tm/sys/file/ssl-cert",
            verify=False,
            headers={"Content-Type": "application/json"},
            auth=(credentials['username'], credentials['password'])
        )
        cert_json_response = cert_response.json().get('items', [])

        # Fetch all SSL profiles
        ssl_response = requests.get(
            f"https://{device_ip}/mgmt/tm/ltm/profile/client-ssl",
            verify=False,
            headers={"Content-Type": "application/json"},
            auth=(credentials['username'], credentials['password'])
        )
        ssl_json_response = ssl_response.json().get('items', [])

        # Fetch all Virtual Servers (VIPs)
        vip_response = requests.get(
            f"https://{device_ip}/mgmt/tm/ltm/virtual?expandSubcollections=true",
            verify=False,
            headers={"Content-Type": "application/json"},
            auth=(credentials['username'], credentials['password'])
        )
        vip_json_response = vip_response.json().get('items', [])

        # Map SSL Profiles to the VIPs using them
        ssl_profile_to_vip_map = {}
        for vip in vip_json_response:
            try:
                vip_name = vip['name']
                vs_profiles = vip['profilesReference']['items']
                for profile in vs_profiles:
                    ssl_profile_name = profile['name']
                    if ssl_profile_name not in ssl_profile_to_vip_map:
                        ssl_profile_to_vip_map[ssl_profile_name] = []
                    ssl_profile_to_vip_map[ssl_profile_name].append(vip_name)
            except KeyError:
                continue  # Skip if no profiles are found

        # Extract all certificate names used in SSL profiles
        ssl_profile_certs = {}
        for ssl_profile in ssl_json_response:
            cert_name = ssl_profile.get('cert', '').split("/")[-1]  # Extract clean cert name
            ssl_profile_name = ssl_profile['name']
            if cert_name:
                ssl_profile_certs[cert_name] = ssl_profile_name  # Map Cert → SSL Profile

        # Insert certificate details into the database
        for cert in cert_json_response:
            cert_name = cert['name']
            cert_expiry_epoch = cert.get('expirationDate', None)
            cert_expiry_human = convert_epoch_to_date(cert_expiry_epoch)

            # Check if this cert is used in any SSL profile
            ssl_profile_name = ssl_profile_certs.get(cert_name, None)
            in_ssl_profile = "Yes" if ssl_profile_name else "No"

            # Find which VIPs are using this SSL profile
            associated_vips = ssl_profile_to_vip_map.get(ssl_profile_name, [])

            # Print the VIPs using this SSL profile
            if in_ssl_profile == "Yes":
                print(f"Certificate {cert_name} (Exp: {cert_expiry_human}) is used in SSL Profile '{ssl_profile_name}' and is associated with VIP(s): {', '.join(associated_vips)}")
            else:
                print(f"Certificate {cert_name} (Exp: {cert_expiry_human}) is NOT used in any SSL profile.")

            lock.acquire()
            db.insert({
                "Device Type": "F5",
                "Device": device.upper(),
                "Cert": cert_name,
                "Expiry_Date": cert_expiry_human,
                "In_SSL_Profile": in_ssl_profile,  # Yes or No
                "Associated_VIPs": associated_vips  # List of VIPs
            })
            lock.release()

        lock.acquire()
        print(f"{device.upper()} - Certificate Scanning Completed!")
        lock.release()




def convert_epoch_to_date(epoch_time):
    """Convert Unix timestamp to a human-readable date format"""
    try:
        return datetime.utcfromtimestamp(int(epoch_time)).strftime('%Y-%m-%d %H:%M:%S UTC')
    except (ValueError, TypeError):
        return "Unknown"

def get_f5_certificates(credentials: dict, device_list: list) -> None:
    for f5_device in device_list:
        device = f5_device['device']
        device_ip = f5_device['ip']

        # Fetch all SSL certificates
        cert_response = requests.get(
            f"https://{device_ip}/mgmt/tm/sys/file/ssl-cert",
            verify=False,
            headers={"Content-Type": "application/json"},
            auth=(credentials['username'], credentials['password'])
        )
        cert_json_response = cert_response.json().get('items', [])

        # Fetch all SSL profiles
        ssl_response = requests.get(
            f"https://{device_ip}/mgmt/tm/ltm/profile/client-ssl",
            verify=False,
            headers={"Content-Type": "application/json"},
            auth=(credentials['username'], credentials['password'])
        )
        ssl_json_response = ssl_response.json().get('items', [])

        # Fetch all Virtual Servers (VIPs)
        vip_response = requests.get(
            f"https://{device_ip}/mgmt/tm/ltm/virtual?expandSubcollections=true",
            verify=False,
            headers={"Content-Type": "application/json"},
            auth=(credentials['username'], credentials['password'])
        )
        vip_json_response = vip_response.json().get('items', [])

        # Map SSL Profiles to the VIPs using them
        ssl_profile_to_vip_map = {}
        for vip in vip_json_response:
            try:
                vip_name = vip['name']
                vs_profiles = vip['profilesReference']['items']
                for profile in vs_profiles:
                    ssl_profile_name = profile['name']
                    if ssl_profile_name not in ssl_profile_to_vip_map:
                        ssl_profile_to_vip_map[ssl_profile_name] = []
                    ssl_profile_to_vip_map[ssl_profile_name].append(vip_name)
            except KeyError:
                continue  # Skip if no profiles are found

        # Extract all certificate names used in SSL profiles
        ssl_profile_certs = {}
        for ssl_profile in ssl_json_response:
            cert_name = ssl_profile.get('cert', '').split("/")[-1]  # Extract clean cert name
            ssl_profile_name = ssl_profile['name']
            if cert_name:
                ssl_profile_certs[cert_name] = ssl_profile_name  # Map Cert → SSL Profile

        # Insert certificate details into the database
        for cert in cert_json_response:
            cert_name = cert['name']
            cert_expiry_epoch = cert.get('expirationDate', None)
            cert_expiry_human = convert_epoch_to_date(cert_expiry_epoch)

            # Check if this cert is used in any SSL profile
            ssl_profile_name = ssl_profile_certs.get(cert_name, None)
            in_ssl_profile = "Yes" if ssl_profile_name else "No"

            # Find which VIPs are using this SSL profile
            associated_vips = ssl_profile_to_vip_map.get(ssl_profile_name, [])

            # Print the VIPs using this SSL profile
            if in_ssl_profile == "Yes":
                print(f"Certificate {cert_name} (Exp: {cert_expiry_human}) is used in SSL Profile '{ssl_profile_name}' and is associated with VIP(s): {', '.join(associated_vips)}")
            else:
                print(f"Certificate {cert_name} (Exp: {cert_expiry_human}) is NOT used in any SSL profile.")

            lock.acquire()
            db.insert({
                "Device Type": "F5",
                "Device": device.upper(),
                "Cert": cert_name,
                "Expiry_Date": cert_expiry_human,
                "In_SSL_Profile": in_ssl_profile,  # Yes or No
                "Associated_VIPs": associated_vips  # List of VIPs
            })
            lock.release()

        lock.acquire()
        print(f"{device.upper()} - Certificate Scanning Completed!")
        lock.release()
====================
from datetime import datetime

def convert_epoch_to_date(epoch_time):
    """Convert Unix timestamp to a human-readable date format"""
    try:
        return datetime.utcfromtimestamp(int(epoch_time)).strftime('%Y-%m-%d %H:%M:%S UTC')
    except (ValueError, TypeError):
        return "Unknown"

# Fetch all SSL certificate files (same API request)
cert_response = requests.get(
    f"https://{device_ip}/mgmt/tm/sys/file/ssl-cert",
    verify=False,
    headers={"Content-Type": "application/json"},
    auth=(credentials['username'], credentials['password'])
)
cert_json_response = cert_response.json()
cert_json_response = cert_json_response.get('items', [])

# Store certificate details in a dictionary for easy lookup
cert_dict = {}
for cert in cert_json_response:
    cert_name = cert['name']
    cert_expiry_epoch = cert.get('expirationDate', None)  # Extract expiration date as epoch
    cert_expiry_human = convert_epoch_to_date(cert_expiry_epoch)  # Convert to readable format
    cert_dict[cert_name] = cert_expiry_human  # Store converted date







//----------------------------------------------------------------
// 1) For each device, filter to F5 + name ^P2 or ^S2
//----------------------------------------------------------------
foreach device in network.devices
where device.platform.vendor == "Vendor.F5"
where matches(toupperCase(device.name), "^P2")
   or matches(toupperCase(device.name), "^S2")

//----------------------------------------------------------------
// 2) Get the 'configuration' text
//----------------------------------------------------------------
let config_text = max(
    foreach p in device.outputs.commands
    where p.commandType == CommandType.F5_CONFIGURATION
    select p.response
)

//----------------------------------------------------------------
// 3) Parse out client-ssl profiles
//    Regex: ltm profile client-ssl <profileName>
//----------------------------------------------------------------
let ssl_profiles =
    foreach match in blockMatches(config_text, "ltm profile client-ssl\\s+(\\S+)")
    select match.captures[0]

//----------------------------------------------------------------
// 4) Return final row with device name & the array of ssl_profiles
//----------------------------------------------------------------
select device.name, ssl_profiles



//----------------------------------------------------------------
// 1) For each F5 device matching name ^P2 or ^S2, grab the config
//----------------------------------------------------------------
foreach device in network.devices
where device.platform.vendor == "Vendor.F5"
where matches(toupperCase(device.name), "^P2") 
   or matches(toupperCase(device.name), "^S2")

//----------------------------------------------------------------
// 2) Extract the "configuration" text (where we define client-ssl profiles)
//----------------------------------------------------------------
let config_text = max(
    foreach cmd in device.outputs.commands
    where cmd.commandType == CommandType.F5_CONFIGURATION
    // You can do any cleanup (e.g. remove brackets) here
    let cleaned_config = replace(cmd.response, "[", "")
    select cleaned_config
);

//----------------------------------------------------------------
// 3) Extract the "ltm_config" text (where we define VIPs + attached profiles)
//----------------------------------------------------------------
let ltm_text = max(
    foreach cmd in device.outputs.commands
    where cmd.commandType == CommandType.F5_LTM_CONFIG
    let cleaned_ltm = replace(cmd.response, "[", "")
    select cleaned_ltm
);

//----------------------------------------------------------------
// 4) Parse out client-ssl profiles from config_text
//    Looking for lines like:
//      ltm profile client-ssl <profileName>
//----------------------------------------------------------------
let ssl_profiles = foreach match in blockMatches(config_text, @"ltm profile client-ssl\s+(\S+)")
select {
    // Usually captures[0] is the entire match, captures[1] is the group
    profileName: match.captures[0]
};

//----------------------------------------------------------------
// 5) Parse out VIP definitions from ltm_text
//    For lines like:
//       ltm virtual <vipName> {
//         ...
//         profiles {
//           myClientSSLProfile { ... }
//         }
//       }
//    We'll do it in two steps:
//    (A) Extract each VIP block (VIP name + entire curly block).
//    (B) From that block, extract all client-ssl references.
//----------------------------------------------------------------

// (A) Extract each VIP block, capturing the VIP name and the block contents
let vipBlocks = foreach vipBlock in blockMatches(ltm_text, @"ltm virtual\s+(\S+)\s*\{(.*?)\}")
select {
    vipName: vipBlock.captures[0],    // The 1st capture group is the name
    vipBody: vipBlock.captures[1]     // The 2nd capture group is everything inside {...}
};

// (B) For each VIP block, extract any client-ssl lines inside
let vipSslProfiles =
    foreach vb in vipBlocks
    foreach ssl in blockMatches(vb.vipBody, @"client-ssl\s+(\S+)")
    select {
        vipName: vb.vipName,
        sslProfile: ssl.captures[0]
    };

//----------------------------------------------------------------
// 6) Final "select": Show the device name plus the arrays we found.
//    This will produce one row per device, with arrays for ssl_profiles
//    and vipSslProfiles. You can export or expand them further if needed.
//----------------------------------------------------------------
select {
    deviceName: device.name,
    ssl_profiles: ssl_profiles,        // All client-ssl profiles found in config
    vipSslProfiles: vipSslProfiles     // VIP name + each client-ssl reference
}


=======
// 1) Extract client-ssl profiles from the "configuration" file.
//    Looks for lines like: "ltm profile client-ssl <profileName>"
let client_ssl_profiles =
    network.devices
    | where platform.vendor == "Vendor F5"
    | where matches(toupper(name), "^P2") or matches(toupper(name), "^S2")
    // Regex: capture the text after "ltm profile client-ssl"
    | extend client_ssl_profile_name = extract(@"ltm profile client-ssl\s+(\S+)", 1, configuration)
    // Only keep rows where we found a profile name
    | where isnotempty(client_ssl_profile_name)
    | project 
        device_name = name,
        client_ssl_profile_name;


// 2) Extract VIP info (and the client-ssl profile references) from the "ltm_config" file.
//    Assumes something like:
//       ltm virtual myVIP {
//         ...
//         profiles {
//           mySSLprofile {
//             ...
//           }
//         }
//       }
let vip_data =
    network.devices
    | where platform.vendor == "Vendor F5"
    | where matches(toupper(name), "^P2") or matches(toupper(name), "^S2")
    // Extract the VIP name from a line like "ltm virtual <vipName>"
    | extend vip_name = extract(@"ltm virtual\s+(\S+)", 1, ltm_config)

    // Next, capture the entire 'profiles { ... }' block if it's multiline
    | extend raw_profiles_block = extract(@"profiles\s*\{(.*?)\}", 1, ltm_config)

    // Flatten newlines so it's easier to parse
    | extend raw_profiles_block = replace(@"\r?\n", " ", raw_profiles_block)

    // Split on '}' so each profile definition becomes a separate string
    | mv-expand raw_profile_line = split(raw_profiles_block, "}")

    // Inside each chunk, look for "client-ssl <profileName>"
    | extend client_ssl_profile = extract(@"client-ssl\s+(\S+)", 1, raw_profile_line)

    // Only keep rows where we actually found a client-ssl profile reference
    | where isnotempty(client_ssl_profile)
    | project 
        device_name = name,
        vip_name,
        client_ssl_profile;


// 3) Join the two sets to show only VIPs that reference a client-ssl profile
//    which is actually defined in the configuration.
client_ssl_profiles
| join kind=inner vip_data on device_name, $left.client_ssl_profile_name == $right.client_ssl_profile
| project 
    device_name,
    vip_name,
    client_ssl_profile

==============
// First, extract the VIP information from the ltm config
let vip_info = 
    network.devices
    | where platform.vendor == "Vendor F5"
    | where matches(toupper(name), "^P2") or matches(toupper(name), "^S2")
    // Extract the client-ssl certificate from the VIP (ltm config)
    | extend vip_cert = extract(@"client-ssl\s+(\S+)", 1, ltm_config)
    // And extract the VIP name (assumes a line like "ltm virtual <vip_name>")
    | extend vip_name = extract(@"ltm virtual\s+(\S+)", 1, ltm_config)
    | project device_name = name, vip_name, vip_cert;
    
// Next, extract the certificate info from the configuration file
let cert_info =
    network.devices
    | where platform.vendor == "Vendor F5"
    | where matches(toupper(name), "^P2") or matches(toupper(name), "^S2")
    // Extract the certificate name from a line like "ltm profile client-ssl <cert_name>"
    | extend config_cert = extract(@"ltm profile client-ssl\s+(\S+)", 1, configuration)
    | project device_name = name, config_cert;
    
// Now, join the two so that we only display VIPs where the client-ssl profile (cert) is defined in configuration.
vip_info
| join kind=inner cert_info on device_name, $left.vip_cert == $right.config_cert
| project device_name, vip_name, client_ssl_cert = config_cert

=========
import ipaddress
import socket
import pandas as pd
import concurrent.futures

def lookup_ip(ip_str, skipped_ips):
    """
    Performs a reverse DNS lookup for the given IP address.
    Returns a tuple (ip_str, dns_result, domain_extracted) if successful,
    or None if no DNS record is found.
    """
    try:
        dns_result = socket.gethostbyaddr(ip_str)[0]
    except socket.herror as e:
        error_msg = f"DNS lookup failed for IP {ip_str}: {e}"
        print(error_msg)
        skipped_ips.append(error_msg)
        return None  # Skip IPs with no DNS entry

    # Check if the DNS name contains "bankofamerica.com"
    if "bankofamerica.com" in dns_result.lower():
        domain_extracted = "bankofamerica.com"
    else:
        domain_extracted = "old domain detected"

    return (ip_str, dns_result, domain_extracted)

def process_subnet(subnet_str, invalid_subnets):
    """
    Given a subnet string (CIDR), returns a list of host IP addresses as strings.
    If the subnet is invalid, records the error message.
    """
    results = []
    try:
        # Using strict=True to enforce valid CIDR format
        network = ipaddress.ip_network(subnet_str.strip(), strict=True)
    except ValueError as e:
        error_msg = f"Invalid subnet: {subnet_str.strip()} - Error: {e}"
        print(error_msg)
        invalid_subnets.append(error_msg)
        return results
    # Enumerate all usable host addresses
    for ip in network.hosts():
        results.append(str(ip))
    print(f"Processed subnet: {subnet_str.strip()} -> {len(results)} IPs")
    return results

def main():
    all_ips = []
    invalid_subnets = []  # To record any invalid subnets
    skipped_ips = []      # To record IPs that fail DNS lookup
    
    # Read subnets from subnet.txt (one per line)
    with open("subnet.txt", "r") as f:
        subnets = f.readlines()
    
    # Process each subnet to get all IP addresses
    for subnet in subnets:
        ips = process_subnet(subnet, invalid_subnets)
        all_ips.extend(ips)
    
    total_ips = len(all_ips)
    print(f"Total IP addresses to process: {total_ips}")
    
    results = []
    processed_count = 0
    
    # Use a thread pool to perform DNS lookups concurrently
    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
        future_to_ip = {executor.submit(lookup_ip, ip, skipped_ips): ip for ip in all_ips}
        for future in concurrent.futures.as_completed(future_to_ip):
            processed_count += 1
            result = future.result()
            if result is not None:
                results.append(result)
            # Print progress every 100 processed IPs (adjust as needed)
            if processed_count % 100 == 0 or processed_count == total_ips:
                print(f"Processed {processed_count} / {total_ips} IPs")
    
    # Create a pandas DataFrame with the results
    df = pd.DataFrame(results, columns=["IP Address", "DNS Name", "Domain Extracted"])
    
    # Save the DataFrame to an Excel file
    excel_file = "dns_lookup_results.xlsx"
    df.to_excel(excel_file, index=False)
    
    print(f"Excel file '{excel_file}' has been created with the DNS lookup results.")
    
    # After all processing, print out the skipped subnets and DNS lookup failures
    if invalid_subnets:
        print("\nThe following subnets were skipped due to errors:")
        for error in invalid_subnets:
            print(error)
    if skipped_ips:
        print("\nThe following IP addresses failed DNS lookup:")
        for error in skipped_ips:
            print(error)

if __name__ == "__main__":
    main()




def format_a_record_comments(wideip_entry: dict) -> str:
    """
    Formats the comment field of a wideip_entry into a neat, multi-line, numbered string.
    
    Assumes that wideip_entry["comment"] is a string where individual comments are
    separated by " | ". If the comment field is empty or missing, returns an empty string.
    """
    comment_text = wideip_entry.get("comment", "")
    if not comment_text:
        return ""
    # Split the comment string into individual lines using " | " as the delimiter.
    comment_list = [c.strip() for c in comment_text.split("|") if c.strip()]
    # Create a numbered list of comments.
    formatted_comments = "\n".join([f"{i+1}) {comment}" for i, comment in enumerate(comment_list)])
    return formatted_comments

# Example usage:
# Assume wideip_entry["comment"] is "Please add the following IPs in a record: 10.0.0.1,10.0.0.2 | Please delete the following from a record list: 192.168.1.5 | Please set fallback method"
# Calling the function would yield:
# 1) Please add the following IPs in a record: 10.0.0.1,10.0.0.2
# 2) Please delete the following from a record list: 192.168.1.5
# 3) Please set fallback method





======

# Now, build the comment string based on missing and extra IPs.
missing_ips = expected_set - actual_set
extra_ips = actual_set - expected_set
comments = []

if missing_ips:
    comments.append("Please add the following IPs in a record: " + ", ".join(sorted(missing_ips)))
if extra_ips:
    comments.append("Please delete the following from a record list: " + ", ".join(sorted(extra_ips)))

# Check if all pools have fallbackMode set as "none".
if wideip_entry['pools']:
    all_fallback_none = all(pool.get("fallbackMode", "").lower() == "none" for pool in wideip_entry['pools'])
    if all_fallback_none:
        comments.append("Please set fallback method")
        # Force the severity to critical if not already critical.
        if wideip_entry.get("aRecordCheck") not in ["Critical", "Non-Prod Critical"]:
            if env in ["Production", "Missing"]:
                wideip_entry["aRecordCheck"] = "Critical"
            else:
                wideip_entry["aRecordCheck"] = "Non-Prod Critical"

# Save the concatenated comment in the entry.
wideip_entry["comment"] = " | ".join(comments)




env = wideip_entry.get("environment", "Missing")
# If no expected A-records are defined, consider it OK.
if not expected_set:
    wideip_entry["aRecordCheck"] = "OK"
else:
    # Check for missing actual A-records or no intersection
    if not actual_set or not expected_set.intersection(actual_set):
        if env in ["Production", "Missing"]:
            wideip_entry["aRecordCheck"] = "Critical"
        else:
            wideip_entry["aRecordCheck"] = "Non-Prod Critical"
    # If all expected records match exactly
    elif expected_set == actual_set:
        wideip_entry["aRecordCheck"] = "OK"
    # Partial match: some but not all expected records are found
    else:
        if env in ["Production", "Missing"]:
            wideip_entry["aRecordCheck"] = "Medium-Impact"
        else:
            wideip_entry["aRecordCheck"] = "Non-Prod Medium"


========
import ipaddress
import socket
import pandas as pd
import concurrent.futures

def lookup_ip(ip_str):
    """
    Performs a reverse DNS lookup for the given IP address.
    Returns a tuple (ip_str, dns_result, domain_extracted) if successful,
    or None if no DNS record is found.
    """
    try:
        dns_result = socket.gethostbyaddr(ip_str)[0]
    except socket.herror:
        return None  # Skip IPs with no DNS entry

    # Check if the DNS name contains "bankofamerica.com"
    if "bankofamerica.com" in dns_result.lower():
        domain_extracted = "bankofamerica.com"
    else:
        domain_extracted = "old domain detected"

    return (ip_str, dns_result, domain_extracted)

def process_subnet(subnet_str):
    """
    Given a subnet string (CIDR), returns a list of host IP addresses as strings.
    """
    results = []
    try:
        network = ipaddress.ip_network(subnet_str.strip())
    except ValueError:
        print(f"Invalid subnet: {subnet_str}")
        return results
    # Enumerate all usable host addresses
    for ip in network.hosts():
        results.append(str(ip))
    print(f"Processed subnet: {subnet_str.strip()} -> {len(results)} IPs")
    return results

def main():
    all_ips = []
    
    # Read subnets from subnet.txt (one per line)
    with open("subnet.txt", "r") as f:
        subnets = f.readlines()
    
    # Process each subnet to get all IP addresses
    for subnet in subnets:
        ips = process_subnet(subnet)
        all_ips.extend(ips)
    
    total_ips = len(all_ips)
    print(f"Total IP addresses to process: {total_ips}")
    
    results = []
    processed_count = 0
    
    # Use a thread pool to perform DNS lookups concurrently
    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
        future_to_ip = {executor.submit(lookup_ip, ip): ip for ip in all_ips}
        for future in concurrent.futures.as_completed(future_to_ip):
            processed_count += 1
            result = future.result()
            if result is not None:
                results.append(result)
            # Print progress every 100 processed IPs (adjust as needed)
            if processed_count % 100 == 0 or processed_count == total_ips:
                print(f"Processed {processed_count} / {total_ips} IPs")
    
    # Create a pandas DataFrame with the results
    df = pd.DataFrame(results, columns=["IP Address", "DNS Name", "Domain Extracted"])
    
    # Save the DataFrame to an Excel file
    excel_file = "dns_lookup_results.xlsx"
    df.to_excel(excel_file, index=False)
    
    print(f"Excel file '{excel_file}' has been created with the DNS lookup results.")

if __name__ == "__main__":
    main()
    
    
    



import ipaddress
import socket
import pandas as pd

# Specify your CIDR subnet here (e.g., "10.161.200.0/22")
subnet = ipaddress.ip_network("10.161.200.0/22")

# List to hold tuples of (IP, DNS result)
results = []

# Iterate through all host addresses in the subnet.
# This automatically skips the network and broadcast addresses.
for ip in subnet.hosts():
    ip_str = str(ip)
    try:
        # Perform a reverse DNS lookup for the current IP address.
        dns_result = socket.gethostbyaddr(ip_str)[0]
        # Optionally, you can check if the returned domain contains the expected string.
        # For instance, to only capture entries that include "bankofamerica.com", you could:
        # if "bankofamerica.com" in dns_result.lower():
        results.append((ip_str, dns_result))
    except socket.herror:
        # No reverse DNS entry found for this IP.
        # You can choose to ignore or log this case.
        continue

# Create a pandas DataFrame with the results.
df = pd.DataFrame(results, columns=["IP Address", "DNS Name"])

# Save the results to an Excel file.
excel_file = "dns_lookup_results.xlsx"
df.to_excel(excel_file, index=False)

print(f"Excel file '{excel_file}' has been created with the DNS lookup results.")






def calculate_expected_a_records(wideip_entry: dict) -> list:
    """
    Calculate expected A‑records for a WideIP entry following these revised rules:

    - If at least one pool in the WideIP has fallbackMode "return-to-dns",
      then consider ALL pools for calculating expected A‑records.
    - Otherwise, return an empty list.

    For poolLbMode:
      * If "global-availability" (using the key "poollbMode" as in your master code):
          - Sort all pools by order and use the lowest pool.
          - If its loadBalancingMode is "round robin":
                expected A‑records = all members from that lowest pool.
          - If its loadBalancingMode is "global availability":
                expected A‑record = the member with the lowest memberOrder from that pool.
      * If "round-robin":
          - For each pool:
                - If loadBalancingMode is "round robin": include all members.
                - If loadBalancingMode is "global availability": include only the member with the lowest memberOrder.
    """
    all_pools = wideip_entry.get("pools", [])
    
    # If no pool has fallbackMode "return-to-dns", return empty list.
    if not any(p.get("fallbackMode", "").lower() == "return-to-dns" for p in all_pools):
         return []
    
    # Consider ALL pools if at least one qualifies.
    valid_pools = all_pools
    expected = set()
    
    # Use the key "poollbMode" as per your master code.
    pool_lb_mode = wideip_entry.get("poollbMode", "").lower()

    if pool_lb_mode == "global-availability" or pool_lb_mode == "global availability":
        # Sort all pools by their order (assuming order is numeric)
        valid_pools_sorted = sorted(valid_pools, key=lambda p: int(p.get("order", 0)))
        lowest_pool = valid_pools_sorted[0]
        lowest_pool_lb_mode = lowest_pool.get("loadBalancingMode", "").lower()
        if lowest_pool_lb_mode == "round robin":
            # All members from the lowest pool
            for member in lowest_pool.get("members", []):
                expected.add(member.get("member", ""))
        elif lowest_pool_lb_mode == "global availability":
            members = lowest_pool.get("members", [])
            try:
                sorted_members = sorted(members, key=lambda m: int(m.get("order", 9999)))
                if sorted_members:
                    expected.add(sorted_members[0].get("member", ""))
            except Exception:
                if members:
                    expected.add(members[0].get("member", ""))
    elif pool_lb_mode == "round-robin":
        # For each pool, apply the rule based on its loadBalancingMode.
        for pool in valid_pools:
            lb_mode = pool.get("loadBalancingMode", "").lower()
            if lb_mode == "round robin":
                # Include all members
                for member in pool.get("members", []):
                    expected.add(member.get("member", ""))
            elif lb_mode == "global availability":
                members = pool.get("members", [])
                try:
                    sorted_members = sorted(members, key=lambda m: int(m.get("order", 9999)))
                    if sorted_members:
                        expected.add(sorted_members[0].get("member", ""))
                except Exception:
                    if members:
                        expected.add(members[0].get("member", ""))
    return list(expected)



# Calculate and attach expected A‑records.
wideip_entry["expectedARecords"] = calculate_expected_a_records(wideip_entry)

expected_set = set(wideip_entry.get("expectedARecords", []))
actual_set = set(wideip_entry.get("A-Record", []))

if not expected_set:
    # If no expected A-records are defined, consider it OK.
    wideip_entry["aRecordCheck"] = "OK"
else:
    if not actual_set:
        # Expected records exist but actual A-record list is empty.
        wideip_entry["aRecordCheck"] = "Critical"
    elif not expected_set.intersection(actual_set):
        # None of the expected records are found.
        wideip_entry["aRecordCheck"] = "Critical"
    elif expected_set == actual_set:
        # All expected records match.
        wideip_entry["aRecordCheck"] = "OK"
    else:
        # Some but not all expected records are found.
        wideip_entry["aRecordCheck"] = "Medium-Impact"


# Calculate and attach expected A‑records.
wideip_entry["expectedARecords"] = calculate_expected_a_records(wideip_entry)

# Perform A-record check
expected_set = set(wideip_entry.get("expectedARecords", []))
actual_set = set(wideip_entry.get("A-Record", []))

if not expected_set.intersection(actual_set):
    # No expected A-record is found in the actual list.
    wideip_entry["aRecordCheck"] = "Critical"
elif expected_set != actual_set:
    # Some (but not all) expected A-records are missing.
    wideip_entry["aRecordCheck"] = "Medium-Impact"
else:
    # All expected A-records are present.
    wideip_entry["aRecordCheck"] = "OK"



expected_a_records_str = "\r\n".join(wideip_entry.get("expectedARecords", []))




def calculate_expected_a_records(wideip_entry: dict) -> list:
    """
    Calculate expected A‑records for a WideIP entry following these revised rules:
    
    - If at least one pool in the WideIP has fallbackMode "return-to-dns",
      then consider ALL pools for calculating expected A‑records.
    - Otherwise, return an empty list.
    
    For poolLbMode:
      * If "global availability":
          - Sort all pools by order and use the lowest pool.
          - If its loadBalancingMode is "round robin":
                expected A‑records = all members from that lowest pool.
          - If its loadBalancingMode is "global availability":
                expected A‑record = the member with the lowest memberOrder from that pool.
      * If "round-robin":
          - For each pool:
                - If loadBalancingMode is "round robin": include all members.
                - If loadBalancingMode is "global availability": include only the member with the lowest memberOrder.
    """
    all_pools = wideip_entry.get("pools", [])
    
    # If no pool in this WideIP has fallbackMode "return-to-dns", return empty list.
    if not any(p.get("fallbackMode", "").lower() == "return-to-dns" for p in all_pools):
         return []
    
    # Otherwise, consider ALL pools
    valid_pools = all_pools
    expected = set()
    pool_lb_mode = wideip_entry.get("poollbMode", "").lower()

    if pool_lb_mode == "global availability":
        # Sort all pools by their order (assuming order is numeric)
        valid_pools_sorted = sorted(valid_pools, key=lambda p: int(p.get("order", 0)))
        lowest_pool = valid_pools_sorted[0]
        lowest_pool_lb_mode = lowest_pool.get("loadBalancingMode", "").lower()
        if lowest_pool_lb_mode == "round robin":
            # All members from the lowest pool
            for member in lowest_pool.get("members", []):
                expected.add(member.get("member", ""))
        elif lowest_pool_lb_mode == "global availability":
            members = lowest_pool.get("members", [])
            try:
                sorted_members = sorted(members, key=lambda m: int(m.get("order", 9999)))
                if sorted_members:
                    expected.add(sorted_members[0].get("member", ""))
            except Exception:
                if members:
                    expected.add(members[0].get("member", ""))
    elif pool_lb_mode == "round-robin":
        # For each pool, apply the rule based on its loadBalancingMode.
        for pool in valid_pools:
            lb_mode = pool.get("loadBalancingMode", "").lower()
            if lb_mode == "round robin":
                # Include all members
                for member in pool.get("members", []):
                    expected.add(member.get("member", ""))
            elif lb_mode == "global availability":
                members = pool.get("members", [])
                try:
                    sorted_members = sorted(members, key=lambda m: int(m.get("order", 9999)))
                    if sorted_members:
                        expected.add(sorted_members[0].get("member", ""))
                except Exception:
                    if members:
                        expected.add(members[0].get("member", ""))
    return list(expected)

===============

wideip_entry["expectedARecords"] = calculate_expected_a_records(wideip_entry)

def calculate_expected_a_records(wideip_entry: dict) -> list:
    """
    Calculate expected A-records for a WideIP entry, following these rules:
    
    1. Consider only pools with fallbackMode equal to "return-to-dns" (ignore others).
    
    2. If poolLbMode is "global availability":
         - And if the lowest pool's loadBalancingMode is "round robin":
              expected A-record = all pool members (their "member" value) from the lowest pool.
         - And if the lowest pool's loadBalancingMode is "global availability":
              expected A-record = the pool member with the lowest memberOrder from the lowest pool.
              
    3. If poolLbMode is "round-robin":
         - And if a pool’s loadBalancingMode is "round robin":
              expected A-record = include all pool members from that pool.
         - And if a pool’s loadBalancingMode is "global availability":
              expected A-record = the pool member with the lowest memberOrder from that pool.
              
    Returns a list of expected A-record IP addresses.
    """
    expected = set()
    
    # Filter pools: only consider those with fallbackMode "return-to-dns"
    valid_pools = [p for p in wideip_entry.get("pools", []) if p.get("fallbackMode", "").lower() == "return-to-dns"]
    if not valid_pools:
        return []
    
    pool_lb_mode = wideip_entry.get("poollbMode", "").lower()
    
    if pool_lb_mode == "global availability":
        # Sort valid pools by pool order (assumed numeric)
        valid_pools_sorted = sorted(valid_pools, key=lambda p: int(p.get("order", 0)))
        lowest_pool = valid_pools_sorted[0]
        lowest_pool_lb_mode = lowest_pool.get("loadBalancingMode", "").lower()
        if lowest_pool_lb_mode == "round robin":
            # Expected A-record: all members from the lowest pool.
            for member in lowest_pool.get("members", []):
                expected.add(member.get("member", ""))
        elif lowest_pool_lb_mode == "global availability":
            # Expected A-record: the member with the lowest memberOrder in the lowest pool.
            members = lowest_pool.get("members", [])
            try:
                sorted_members = sorted(members, key=lambda m: int(m.get("order", 9999)))
                if sorted_members:
                    expected.add(sorted_members[0].get("member", ""))
            except Exception as e:
                if members:
                    expected.add(members[0].get("member", ""))
    elif pool_lb_mode == "round-robin":
        # For each valid pool, check its loadBalancingMode.
        for pool in valid_pools:
            lb_mode = pool.get("loadBalancingMode", "").lower()
            if lb_mode == "round robin":
                # Include all members from that pool.
                for member in pool.get("members", []):
                    expected.add(member.get("member", ""))
            elif lb_mode == "global availability":
                # Include the member with the lowest memberOrder from that pool.
                members = pool.get("members", [])
                try:
                    sorted_members = sorted(members, key=lambda m: int(m.get("order", 9999)))
                    if sorted_members:
                        expected.add(sorted_members[0].get("member", ""))
                except Exception as e:
                    if members:
                        expected.add(members[0].get("member", ""))
    # Return as a list
    return list(expected)



========
elif user_choice == "2":
    import xlsxwriter

    print("Writing DB to Excel file...\n")
    # Set file path for XLSX file
    filename = f"/storage/PUT_STUFF_IN_HERE/{getpass.getuser()}/data_base.xlsx"
    workbook = xlsxwriter.Workbook(filename)
    worksheet = workbook.add_worksheet()

    # Define header format (dark navy background, white bold text, centered)
    header_format = workbook.add_format({
        'bold': True,
        'font_color': 'white',
        'bg_color': '#000080',  # dark navy
        'align': 'center',
        'valign': 'vcenter'
    })

    # Define cell format (wrap text and top align)
    cell_format = workbook.add_format({
        'text_wrap': True,
        'valign': 'top'
    })

    # Define headers
    headers = ['Vendor', 'VIP Name', 'Environment', 'Description', 'PoolLbMode', 'Pool Details']

    # Write header row manually (row 0)
    for col, header in enumerate(headers):
        worksheet.write(0, col, header, header_format)

    # Collect and write data rows from DB
    data = []
    for entry in db.all():
        pool_details = build_pool_details(entry.get("pools", []))
        row_data = [
            entry.get('device', ''),
            entry.get('wideip_name', ''),
            entry.get('environment', 'Missing'),
            entry.get('description', ''),
            entry.get('poollbMode', ''),
            pool_details
        ]
        data.append(row_data)

    row_index = 1  # Data rows start at row 1
    for row in data:
        for col, value in enumerate(row):
            worksheet.write(row_index, col, value, cell_format)
        # Dynamically set row height based on the number of lines in Pool Details
        num_lines = row[5].count('\r\n') + 1  # using Windows line breaks
        worksheet.set_row(row_index, num_lines * 15)  # Adjust multiplier as needed
        row_index += 1

    # Optionally, set column widths (adjust values as needed)
    worksheet.set_column(0, 0, 15)  # Vendor
    worksheet.set_column(1, 1, 25)  # VIP Name
    worksheet.set_column(2, 2, 15)  # Environment
    worksheet.set_column(3, 3, 40)  # Description
    worksheet.set_column(4, 4, 20)  # PoolLbMode
    worksheet.set_column(5, 5, 50)  # Pool Details

    # Add a table effect to the entire range to get alternating row colors, etc.
    num_rows = row_index  # total rows (including header)
    num_cols = len(headers)
    worksheet.add_table(0, 0, num_rows - 1, num_cols - 1, {
        'columns': [{'header': h} for h in headers],
        'style': 'Table Style Medium 2'  # Choose a table style that gives you a blue-light/white alternating effect
    })

    workbook.close()

    print(f"Data base written to {filename}\n"
          "Please either use WinSCP or run the following scp command from a Windows command prompt: ")
    print(f"scp {getpass.getuser()}@171.206.203.213:{filename} C:\\Users\\{getpass.getuser().upper()}\\Desktop")






def build_pool_details(pools: list) -> str:
    lines = []
    for pool in pools:
        lines.append(f"Pool Name: {pool.get('pool_name', '')}")
        lines.append(f"Order: {pool.get('order', '')} | FallbackMode: {pool.get('fallbackMode', '')}")
        lines.append("Members:")
        for member in pool.get("members", []):
            lines.append(f"  - {member.get('order', '-')}) {member.get('member', '')}")
        lines.append("")  # Blank line between pools
    return "\r\n".join(lines)


def build_pool_details(pools: list) -> str:
    """
    Build a multi-line string for Excel export for the given pools.
    Each pool is formatted as:
    
      Pool Name: <pool_name>
      Order: <order> | FallbackMode: <fallbackMode>
      Members:
        - <order>) <member>
        - <order>) <member>
    
    Pools are separated by a blank line.
    """
    lines = []
    for pool in pools:
        lines.append(f"Pool Name: {pool.get('pool_name', '')}")
        lines.append(f"Order: {pool.get('order', '')} | FallbackMode: {pool.get('fallbackMode', '')}")
        lines.append("Members:")
        for member in pool.get("members", []):
            # Here member is a dict like {"member": "1.1.1.1", "order": 0}
            lines.append(f"  - {member.get('order', '-')}) {member.get('member', '')}")
        lines.append("")  # Blank line between pools
    return "\n".join(lines)



# Extract Pool Members as a list of dictionaries containing both member and memberOrder
members_list = []
members_ref = pool_obj.get('membersReference', {}).get('items', [])
for member in members_ref:
    member_name = member.get('name', '')
    # Extract IP from the member_name (if needed) using your extract_ip() function,
    # or simply use the member name as is.
    ip = extract_ip(member_name)
    m_order = member.get('memberOrder', '-')  # Use '-' if memberOrder is missing
    members_list.append({
        "member": ip,
        "order": m_order
    })






# Extract Pool Members along with their memberOrder
pool_members = []       # raw member names
member_orders = []      # parallel list for memberOrder values
members_ref = pool_obj.get('membersReference', {}).get('items', [])
for member in members_ref:
    member_name = member.get('name', '')
    # Use the API-provided memberOrder, or '-' if it's missing
    m_order = member.get('memberOrder', '-')
    pool_members.append(member_name)
    member_orders.append(m_order)






health_response = requests.get(
                f"https://{device_ip}/mgmt/tm/gtm/wideip/a/stats",
                verify=False,
                headers={'Content-Type': 'application/json'},
                auth=(credentials['username'], credentials['password'])
            )
            health_json = health_response.json() or {}
            health_entries = health_json.get('entries', {})




# 1) Retrieve availabilityState/enabledState from the map
                if wideip_name in health_map:
                    wideip_entry['availabilityState'] = health_map[wideip_name]['availabilityState']
                    wideip_entry['enabledState'] = health_map[wideip_name]['enabledState']
                else:
                    wideip_entry['availabilityState'] = 'Unknown'
                    wideip_entry['enabledState'] = 'Unknown'



# ---------------------------------------------------------
        # Build a map from wideipName --> (availability, enabled)
        # ---------------------------------------------------------
        health_map = {}
        for full_url, val in health_entries.items():
            # full_url looks like:
            #   "https://localhost/mgmt/tm/gtm/wideip/a/~Common~mywideip.com/stats?ver=15.1.6.1"
            #
            # We'll extract "mywideip.com" from that.
            match = re.search(r'/~Common~([^/]+)/stats', full_url)
            if match:
                found_name = match.group(1)  # e.g. "mywideip.com"
                nested_stats = val.get('nestedStats', {}).get('entries', {})
                availability = nested_stats.get('status.availabilityState', {}).get('description', 'Unknown')
                enabled = nested_stats.get('status.enabledState', {}).get('description', 'Unknown')

                health_map[found_name] = {
                    'availabilityState': availability,
                    'enabledState': enabled
                }
            # else: ignore keys that don't match the pattern










wideip_key = f"Common~{wideip_name}"
                if wideip_key in health_entries:
                    nested_stats = health_entries[wideip_key].get('nestedStats', {}).get('entries', {})
                    availability = nested_stats.get('status.availabilityState', {}).get('description', '')
                    enabled = nested_stats.get('status.enabledState', {}).get('description', '')
                    # Store in wideip_entry
                    wideip_entry['availabilityState'] = availability
                    wideip_entry['enabledState'] = enabled
                else:
                    # If not found, set some default or “Unknown”
                    wideip_entry['availabilityState'] = 'Unknown'
                    wideip_entry['enabledState'] = 'Unknown'



#!/usr/bin/expect -f

# Enable internal debugging for detailed output (remove or comment out after debugging)
exp_internal 1

# Set a timeout (in seconds)
set timeout 10

# Set credentials and file names
set user "yourusername"
set password "YourPasswordHere"   ;# WARNING: Storing passwords in plain text is insecure.
set input_file "ips.txt"
set output_file "hostnames.csv"

# Initialize the CSV file with headers
set out [open $output_file "w"]
puts $out "Hostname,IP Address"
close $out

# Open the input file for reading
set in [open $input_file "r"]

while {[gets $in ip] != -1} {
    if {$ip ne ""} {
        puts "Connecting to $ip..."

        # Spawn the SSH process to run 'hostname' on the remote device
        spawn ssh -o StrictHostKeyChecking=accept-new -o ConnectTimeout=10 "$user@$ip" hostname

        expect {
            -re "yes/no" {
                send "yes\r"
                exp_continue
            }
            -re "(?i)password:" {
                send "$password\r"
            }
            timeout {
                puts "Timeout connecting to $ip"
                set hostname "Unknown"
                # Append the result as unknown for this IP
                set out [open $output_file "a"]
                puts $out "$hostname,$ip"
                close $out
                continue
            }
        }

        # Expect the hostname output
        expect {
            -re "(.*)\r\n" {
                set hostname $expect_out(1,string)
            }
            timeout {
                set hostname "Unknown"
            }
        }

        # Append the result to the CSV file
        set out [open $output_file "a"]
        puts $out "$hostname,$ip"
        close $out

        puts "Retrieved hostname: $hostname"
    }
}

close $in

puts "Process completed. Results saved in $output_file."




#!/bin/bash

# Input and output files
input_file="ips.txt"
output_file="hostnames.csv"
password="YourPasswordHere"  # Replace with your actual password

# Initialize the output CSV file with headers
echo "Hostname,IP Address" > "$output_file"

# Loop through each IP address in the input file
while IFS= read -r ip; do
    # Check if the IP address is not empty
    if [[ -n "$ip" ]]; then
        echo "Connecting to $ip..."

        # SSH into the server, retrieve the hostname, and append to the output file
        hostname=$(sshpass -p "$password" ssh -o StrictHostKeyChecking=accept-new -o ConnectTimeout=5 "user@$ip" 'hostname' 2>/dev/null)

        # Check if SSH was successful
        if [[ $? -eq 0 ]]; then
            echo "Retrieved hostname: $hostname"
            echo "$hostname,$ip" >> "$output_file"
        else
            echo "Failed to connect to $ip"
            echo "Unknown,$ip" >> "$output_file"
        fi
    fi
done < "$input_file"

echo "Process completed. Results saved in $output_file."


#!/bin/bash

# Input file containing IPs
input_file="ips.txt"

# Output file for storing results
output_file="hostnames.csv"

# Initialize the output CSV file with headers
echo "Hostname,IP Address" > "$output_file"

# Loop through each IP in the input file
while IFS= read -r ip; do
    # Trim whitespace from the IP address
    clean_ip=$(echo "$ip" | xargs)

    # Check if IP is not empty
    if [[ -n "$clean_ip" ]]; then
        echo "Connecting to $clean_ip..."

        # SSH command to retrieve hostname (Safe key handling)
        hostname=$(ssh -o StrictHostKeyChecking=accept-new -o ConnectTimeout=5 "user@$clean_ip" 'hostname' 2>/dev/null)

        # Check if SSH connection was successful
        if [[ $? -eq 0 ]]; then
            echo "Retrieved hostname: $hostname"
            echo "$hostname,$clean_ip" >> "$output_file"
        else
            echo "Failed to connect to $clean_ip"
            echo "Unknown,$clean_ip" >> "$output_file"
        fi
    fi
done < "$input_file"

echo "✅ Process completed. Results saved in $output_file."



#!/bin/bash

input_file="ips.txt"
output_file="ping_results.txt"

> "$output_file"

while IFS= read -r ip; do
    if [[ -n "$ip" ]]; then
        echo "Processing IP: '$ip'"
        ping -c 4 "$ip" >> "$output_file" 2>&1
        if [[ $? -ne 0 ]]; then
            echo "Failed to ping $ip" >> "$output_file"
        fi
        echo -e "\n-------------------------\n" >> "$output_file"
    else
        echo "Empty or invalid line detected."
    fi
done < "$input_file"

echo "Done! Results saved in $output_file"



#!/bin/bash

# Input file containing IPs
input_file="ips.txt"

# Output file for results
output_file="ping_results.txt"

# Clear previous results file
> "$output_file"

# Loop through each IP in ips.txt
while IFS= read -r ip; do
    if [[ -n "$ip" ]]; then
        echo "Pinging $ip..."
        
        # Run ping (adjust count based on your need)
        ping -c 4 "$ip" >> "$output_file"
        
        # Separate results with a line
        echo -e "\n-------------------------\n" >> "$output_file"
    fi
done < "$input_file"

echo "Done! Results saved in ping_results.txt"





import subprocess

# Read IPs from a text file
input_file = "ips.txt"
output_file = "results.txt"

with open(input_file, "r") as file, open(output_file, "w") as output:
    for ip in file:
        ip = ip.strip()
        if ip:
            # Run nslookup using the native shell of your jump box
            result = subprocess.run(f"nslookup {ip}", shell=True, capture_output=True, text=True, executable="/bin/bash")

            # Write the raw output directly to file
            output.write(f"NSLOOKUP for {ip}:\n{result.stdout}\n\n")

            # Print to screen for live feedback
            print(f"NSLOOKUP for {ip}:\n{result.stdout}\n")

print("Done! Results saved in results.txt")




import subprocess

def get_hostname(ip):
    try:
        result = subprocess.run(["nslookup", ip], capture_output=True, text=True)
        for line in result.stdout.splitlines():
            if "Name:" in line:
                return line.split(":")[1].strip().split('.')[0]  # Get hostname before first dot
        return "No PTR record found"
    except Exception as e:
        return f"Error: {e}"

# Read IPs from a text file
input_file = "ips.txt"
output_file = "results.txt"

with open(input_file, "r") as file, open(output_file, "w") as output:
    for ip in file:
        ip = ip.strip()
        if ip:  # Skip empty lines
            hostname = get_hostname(ip)
            output.write(f"{ip} -> {hostname}\n")
            print(f"{ip} -> {hostname}")  # Print progress

print("Done! Results saved in results.txt")





import subprocess

def get_hostname(ip):
    try:
        result = subprocess.run(["nslookup", ip], capture_output=True, text=True)
        for line in result.stdout.splitlines():
            if "Name:" in line:
                return line.split(":")[1].strip().split('.')[0]  # Get hostname before first dot
        return "No PTR record found"
    except Exception as e:
        return f"Error: {e}"

ip = "your-ip-here"
print(get_hostname(ip))






import socket

with open("ips.txt") as file:
    ips = file.read().splitlines()

with open("results.txt", "w") as output:
    for ip in ips:
        try:
            hostname = socket.gethostbyaddr(ip)[0].split('.')[0]
            output.write(f"{ip} -> {hostname}\n")
        except socket.herror:
            output.write(f"{ip} -> No PTR Record Found\n")

print("Done! Check results.txt")




import os
import csv
import time

# Determine the script directory and build the CSV file path.
script_dir = os.path.dirname(crt.ScriptFullName)
csv_path = os.path.join(script_dir, "Book1.csv")

def ssh_to_device(device, expected_prompt, timeout=20):
    crt.Screen.Clear()
    crt.Screen.Send("ssh " + device + "\r")
    
    start_time = time.time()
    while (time.time() - start_time) < timeout:
        index = crt.Screen.WaitForStrings(
            ["yes/no", "assword:", expected_prompt, "Could not resolve hostname"],
            1
        )
        if index == 1:
            # Auto-accept the host key.
            crt.Screen.Send("yes\r")
            continue
        elif index == 2:
            # Password prompt: wait for you to type the password manually.
            if crt.Screen.WaitForString(expected_prompt, timeout - (time.time() - start_time)):
                return True
            else:
                return False
        elif index == 3:
            # Expected prompt found; login successful.
            return True
        elif index == 4:
            # Hostname resolution failed.
            return False
    return False

def main():
    crt.Screen.Synchronous = True

    try:
        csvfile = open(csv_path, "rb")
    except Exception:
        return

    reader = csv.reader(csvfile)
    for row in reader:
        if not row or row[0].strip() == "":
            continue

        device = row[0].strip()
        if ssh_to_device(device, device, 20):
            # Once logged in, send exit to close the session.
            crt.Screen.Send("exit\r")
            time.sleep(1)
        # Proceed to next device regardless of success/failure.
    csvfile.close()

main()








import os
import csv  # Make sure you import the csv module
import time

# Get the directory of the current script.
script_dir = os.path.dirname(crt.ScriptFullName)
csv_path = os.path.join(script_dir, "Book1.csv")

def parse_ips(ip_cell):
    """
    Given a cell containing multiple IP addresses (one per line),
    return a list of IP address strings.
    """
    lines = ip_cell.splitlines()
    ips = []
    for line in lines:
        line = line.strip()
        if line:
            ips.append(line)
    return ips

def ssh_in_same_session(target, expected_hostname, ssh_username, ssh_password, timeout=20):
    crt.Screen.Clear()
    crt.Screen.Send("ssh " + target + "\r")
    
    start_time = time.time()
    while (time.time() - start_time) < timeout:
        index = crt.Screen.WaitForStrings(["yes/no", "assword:", expected_hostname], 1)
        if index == 1:
            crt.Screen.Send("yes\r")
            continue
        elif index == 2:
            crt.Screen.Send(ssh_password + "\r")
            if crt.Screen.WaitForString(expected_hostname, timeout - (time.time() - start_time)):
                return True
            else:
                return False
        elif index == 3:
            return True
    return False

def main():
    crt.Screen.Synchronous = True

    # Update with your SSH login details
    ssh_username = "your_username"     # Replace with your actual username
    ssh_password = "your_password"     # Replace with your actual password

    try:
        # For Python 2, open in binary mode.
        csvfile = open(csv_path, "rb")
    except Exception as e:
        crt.Dialog.MessageBox("Error opening CSV file: " + str(e))
        return
    
    reader = csv.reader(csvfile)
    
    for row in reader:
        if len(row) < 2:
            continue
        
        hostname = row[0].strip()
        ip_cell = row[1]
        ip_list = parse_ips(ip_cell)
        
        crt.Dialog.MessageBox("Testing Host: " + hostname)
        
        if ssh_in_same_session(hostname, hostname, ssh_username, ssh_password, 20):
            crt.Dialog.MessageBox("SUCCESS: Connected to " + hostname + " via hostname")
            crt.Screen.Send("exit\r")
            time.sleep(1)
        else:
            crt.Dialog.MessageBox("FAILED: Unable to connect to " + hostname + " via hostname. Skipping IP tests.")
            continue
        
        successful_ips = []
        for ip in ip_list:
            crt.Dialog.MessageBox("Testing IP: " + ip)
            if ssh_in_same_session(ip, hostname, ssh_username, ssh_password, 20):
                successful_ips.append(ip)
                crt.Dialog.MessageBox("SUCCESS: " + hostname + " reachable at " + ip)
                crt.Screen.Send("exit\r")
                time.sleep(1)
            else:
                crt.Dialog.MessageBox("FAILED: " + hostname + " not confirmed at " + ip)
        
        if successful_ips:
            summary = "Host " + hostname + " - Successful IPs: " + ", ".join(successful_ips)
        else:
            summary = "Host " + hostname + " - No IP addresses succeeded."
        crt.Dialog.MessageBox(summary)
    
    csvfile.close()
    crt.Dialog.MessageBox("Script finished processing all devices.")

main()



# SecureCRT Python script with password handling and prompt verification
import csv
import time

def parse_ips(ip_cell):
    """
    Given a cell containing multiple IP addresses (one per line),
    return a list of IP address strings.
    """
    lines = ip_cell.splitlines()
    ips = []
    for line in lines:
        line = line.strip()
        if line:
            ips.append(line)
    return ips

def ssh_in_same_session(target, expected_hostname, ssh_username, ssh_password, timeout=20):
    """
    In the current SecureCRT session, sends:
       ssh <target>
    and then waits for one of these prompts:
       - "yes/no"    -> send "yes"
       - "assword:"  -> send the password (ssh_password)
       - expected_hostname -> success!
    
    Returns True if expected_hostname appears (meaning you reached the device),
    otherwise returns False.
    
    NOTE:
      - If a password prompt appears, this function sends the password.
      - Adjust 'timeout' if your network or device is slow.
    """
    crt.Screen.Clear()
    crt.Screen.Send("ssh " + target + "\r")
    
    start_time = time.time()
    # Loop until timeout expires
    while (time.time() - start_time) < timeout:
        # Wait for 1 second for one of these strings to appear
        index = crt.Screen.WaitForStrings(["yes/no", "assword:", expected_hostname], 1)
        if index == 1:
            # Host key confirmation prompt detected
            crt.Screen.Send("yes\r")
            continue
        elif index == 2:
            # Password prompt detected; send password.
            crt.Screen.Send(ssh_password + "\r")
            # Now wait for the expected hostname prompt.
            if crt.Screen.WaitForString(expected_hostname, timeout - (time.time() - start_time)):
                return True
            else:
                return False
        elif index == 3:
            # Expected hostname prompt found. Success!
            return True
    return False

def main():
    # Ensure the screen is synchronous so we capture all output reliably.
    crt.Screen.Synchronous = True

    # Use the CSV file "Book1.csv" in the same folder as this script.
    csv_path = "Book1.csv"
    
    # Update with your SSH login details
    ssh_username = "your_username"     # <<-- Replace with your actual username
    ssh_password = "your_password"     # <<-- Replace with your actual password

    try:
        csvfile = open(csv_path, "r", newline='')
    except Exception as e:
        crt.Dialog.MessageBox("Error opening CSV file: " + str(e))
        return
    
    reader = csv.reader(csvfile)
    
    # Process each row: Column A is the hostname; Column B has one or more IP addresses (each on a new line)
    for row in reader:
        if len(row) < 2:
            continue
        
        hostname = row[0].strip()
        ip_cell = row[1]
        ip_list = parse_ips(ip_cell)
        
        crt.Dialog.MessageBox("Testing Host: " + hostname)
        
        # 1) Test SSH using the hostname
        if ssh_in_same_session(hostname, hostname, ssh_username, ssh_password, 20):
            crt.Dialog.MessageBox("SUCCESS: Connected to " + hostname + " via hostname")
            # Exit the remote session to return to your jumpbox shell.
            crt.Screen.Send("exit\r")
            time.sleep(1)
        else:
            crt.Dialog.MessageBox("FAILED: Unable to connect to " + hostname + " via hostname. Skipping IP tests.")
            continue
        
        # 2) Test each IP address from the IP cell.
        successful_ips = []
        for ip in ip_list:
            crt.Dialog.MessageBox("Testing IP: " + ip)
            if ssh_in_same_session(ip, hostname, ssh_username, ssh_password, 20):
                successful_ips.append(ip)
                crt.Dialog.MessageBox("SUCCESS: " + hostname + " reachable at " + ip)
                crt.Screen.Send("exit\r")
                time.sleep(1)
            else:
                crt.Dialog.MessageBox("FAILED: " + hostname + " not confirmed at " + ip)
        
        # Display summary for this host.
        if successful_ips:
            summary = "Host " + hostname + " - Successful IPs: " + ", ".join(successful_ips)
        else:
            summary = "Host " + hostname + " - No IP addresses succeeded."
        crt.Dialog.MessageBox(summary)
    
    csvfile.close()
    crt.Dialog.MessageBox("Script finished processing all devices.")

main()








# SecureCRT Python script
import csv
import time

def parse_ips(ip_cell):
    """
    Split the cell containing multiple IP addresses on separate lines,
    returning a list of IP strings.
    """
    # Split on newline
    ips = ip_cell.splitlines()
    # Clean up whitespace
    return [ip.strip() for ip in ips if ip.strip()]

def test_connection(target, ssh_username, expected_hostname, timeout=10):
    """
    Attempts an SSH connection to 'target' (hostname or IP) using SecureCRT.
    Checks if 'expected_hostname' appears in the prompt to confirm it's the same device.
    Returns True if we see the hostname in the prompt, else False.
    """
    ssh_command = f"/SSH2 /L {ssh_username} {target}"
    crt.Dialog.MessageBox(f"Attempting SSH to: {target}")
    
    # Initiate SSH connection via SecureCRT
    crt.Session.Connect(ssh_command)
    
    # Small delay to allow session to establish
    time.sleep(2)
    
    # We'll check if the screen eventually shows the expected hostname
    try:
        # Wait up to 'timeout' seconds for the hostname to appear in the prompt
        if crt.Screen.WaitForString(expected_hostname, timeout):
            return True
        else:
            return False
    except Exception as e:
        crt.Dialog.MessageBox(f"Error while checking prompt for {target}: {str(e)}")
        return False

def main():
    # Path to your CSV file. Adjust as needed.
    csv_path = r"C:\path\to\your\devices.csv"
    
    # Set your SSH username.
    ssh_username = "your_username"
    
    # Open the CSV file
    try:
        csvfile = open(csv_path, "r", newline='')
    except Exception as e:
        crt.Dialog.MessageBox(f"Error opening CSV file: {str(e)}")
        return
    
    reader = csv.reader(csvfile)
    
    for row in reader:
        # Each row should have at least two columns: hostname and IP-cell
        if len(row) < 2:
            continue
        
        hostname = row[0].strip()
        ip_cell = row[1]
        
        # Parse out all IP addresses from the second column
        ip_list = parse_ips(ip_cell)
        
        crt.Dialog.MessageBox(f"--- Testing Host: {hostname} ---")
        
        # 1) Test the device by hostname
        hostname_success = test_connection(hostname, ssh_username, hostname)
        
        # Disconnect after the attempt
        crt.Session.Disconnect()
        
        if not hostname_success:
            # If we can't connect by hostname, skip IP checks
            crt.Dialog.MessageBox(f"FAILED: Unable to SSH to {hostname} by hostname. Skipping IP tests.")
            continue
        else:
            crt.Dialog.MessageBox(f"SUCCESS: Able to SSH to {hostname} by hostname.")
        
        # 2) Now test each IP address
        successful_ips = []
        for ip in ip_list:
            ip_success = test_connection(ip, ssh_username, hostname)
            crt.Session.Disconnect()
            
            if ip_success:
                successful_ips.append(ip)
                crt.Dialog.MessageBox(f"SUCCESS: {hostname} reachable at IP {ip}")
            else:
                crt.Dialog.MessageBox(f"FAILED: {hostname} not confirmed at IP {ip}")
        
        # Summary for this row
        if successful_ips:
            summary = (f"Host {hostname} - IPs that worked: " +
                       ", ".join(successful_ips))
        else:
            summary = f"Host {hostname} - No IPs succeeded."
        
        crt.Dialog.MessageBox(summary)
    
    csvfile.close()
    crt.Dialog.MessageBox("Script finished processing all devices.")

# Run main
main()






import pandas as pd
import paramiko
import socket

# Load the CSV file and extract device names/IPs from Column A
file_path = 'devices.csv'  # Make sure your CSV file is named correctly
df = pd.read_csv(file_path, usecols=[0], header=None)  # Read only Column A

# Convert Column A to a list of device IPs
device_names = df[0].dropna().tolist()  # Drop empty rows and convert to list

# SSH credentials
username = 'your_username'
password = 'your_password'

# Function to check SSH connectivity
def check_ssh(device_ip):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(
            hostname=device_ip,
            username=username,
            password=password,
            timeout=5  # Timeout in seconds
        )
        print(f"{device_ip}: GOOD (SSH connection successful)")
    except (paramiko.ssh_exception.NoValidConnectionsError, socket.timeout, paramiko.AuthenticationException):
        print(f"{device_ip}: BAD (SSH failed)")
    finally:
        client.close()

# Iterate over device IPs and check SSH connectivity
for device_ip in device_names:
    check_ssh(device_ip)


import pandas as pd
import paramiko
import socket

# Load the Excel file and extract device names/IPs from Column A
file_path = 'Book1.xlsx'
df = pd.read_excel(file_path, usecols='A', header=None)
device_names = df[0].dropna().tolist()  # Drop any empty cells and convert to list

# SSH credentials
username = 'your_username'
password = 'your_password'

# Function to check SSH connectivity
def check_ssh(device_ip):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(
            hostname=device_ip,
            username=username,
            password=password,
            timeout=5  # seconds
        )
        print(f"{device_ip}: GOOD")
    except (paramiko.ssh_exception.NoValidConnectionsError, socket.timeout, paramiko.AuthenticationException):
        print(f"{device_ip}: BAD")
    finally:
        client.close()

# Iterate over device IPs and check SSH connectivity
for device_ip in device_names:
    check_ssh(device_ip)
    
    
    
    



def apply_rules(wideip_entry: dict):
    """
    Apply all rules, then:
      - Pick the worst severity (i.e. highest priority)
      - Concatenate all rule messages (numbered) into a single comment
      - Do not duplicate the flag; only the worst severity is kept.
    """
    rule_results = []
    for rule in RULES:
        result = rule(wideip_entry)
        if result:
            rule_results.append(result)  # Each result is a tuple (severity, comment)

    if not rule_results:
        wideip_entry["flag"] = "OK"
        wideip_entry["comment"] = ""
        return

    # Define severity rankings.
    # Adjust these values if you introduce new severity levels.
    severity_mapping = {
        "critical": 3,
        "medium": 2,
        "out of standards": 1
    }

    # Determine the highest severity (worst flag)
    worst_severity = None
    worst_severity_rank = -1
    for severity, comment in rule_results:
        rank = severity_mapping.get(severity.lower(), 0)
        if rank > worst_severity_rank:
            worst_severity_rank = rank
            worst_severity = severity

    # Build a combined comment, numbering each message
    comments = []
    for idx, (severity, comment) in enumerate(rule_results, 1):
        comments.append(f"{idx}) {comment}")

    wideip_entry["flag"] = worst_severity
    wideip_entry["comment"] = "; ".join(comments)


def rule_single_pool(wideip_entry: dict):
    """
    Applies when the WideIP has a single pool.
    
    For wideip poolLbMode (round robin or global availability):
      - If the pool’s loadBalancingMode is round robin:
            fallbackMode must be return-to-dns, and the A-Record should include all members.
      - If the pool’s loadBalancingMode is global availability:
            fallbackMode must be return-to-dns, and the A-Record should include only the primary member.
    """
    pools = wideip_entry.get("pools", [])
    if len(pools) != 1:
        return None  # Not applicable for multiple pools
    
    pool = pools[0]
    pool_lb = pool.get("loadBalancingMode", "").lower()
    fallback = pool.get("fallbackMode", "").lower()
    
    if fallback != "return-to-dns":
        return ("Critical", f"Single pool '{pool.get('pool_name', '')}' must have fallbackMode 'return-to-dns' (found '{fallback}')")
    
    a_record_ips = set(wideip_entry.get("A-Record", []))
    members = pool.get("members", [])
    
    if pool_lb == "round robin":
        # A‑Record should include all pool member IPs
        expected_ips = {extract_ip(m) for m in members}
        if expected_ips != a_record_ips:
            return ("Critical", "For a single pool with round robin load balancing, the A‑Record must include all pool members")
    
    elif pool_lb == "global availability":
        # A‑Record should include only the primary member (assumed to be the first)
        if members:
            primary_ip = extract_ip(members[0])
            if a_record_ips != {primary_ip}:
                return ("Critical", "For a single pool with global availability, the A‑Record must include only the primary pool member")
    
    return None


def rule_multiple_pools_global_availability(wideip_entry: dict):
    """
    Applies when the WideIP uses global availability and has multiple pools.
    
    Expected behavior:
      - For multiple pools:
          * All pools except the LAST must have fallbackMode 'none'
          * The LAST pool must have fallbackMode 'return-to-dns'
      - The A‑Record should be based on the primary pool:
          * If the primary pool uses round robin: include all its members
          * If it uses global availability: include only its primary member
    """
    pools = wideip_entry.get("pools", [])
    if len(pools) < 2:
        return None  # Not applicable for single-pool scenarios
    
    wideip_lb = wideip_entry.get("poollbMode", "").lower()
    if wideip_lb != "global availability":
        return None  # This rule applies only when wideip poolLbMode is global availability
    
    # Sort pools by their 'order' (assuming order can be converted to integer)
    try:
        pools_sorted = sorted(pools, key=lambda p: int(p.get("order", 0)))
    except Exception:
        pools_sorted = pools
    
    primary_pool = pools_sorted[0]
    last_pool = pools_sorted[-1]
    
    # Check fallback modes:
    for pool in pools_sorted[:-1]:
        if pool.get("fallbackMode", "").lower() != "none":
            return ("Critical", f"Pool '{pool.get('pool_name', '')}' should have fallbackMode 'none' when multiple pools are used")
    
    if last_pool.get("fallbackMode", "").lower() != "return-to-dns":
        return ("Critical", f"Last pool '{last_pool.get('pool_name', '')}' must have fallbackMode 'return-to-dns'")
    
    # Check A‑Record based on the primary pool's load balancing method:
    a_record_ips = set(wideip_entry.get("A-Record", []))
    primary_lb = primary_pool.get("loadBalancingMode", "").lower()
    members = primary_pool.get("members", [])
    
    if primary_lb == "round robin":
        expected_ips = {extract_ip(m) for m in members}
        if expected_ips != a_record_ips:
            return ("Critical", "For multiple pools with primary pool using round robin, A‑Record must include all primary pool members")
    elif primary_lb == "global availability":
        if members:
            primary_ip = extract_ip(members[0])
            if a_record_ips != {primary_ip}:
                return ("Critical", "For multiple pools with primary pool using global availability, A‑Record must include only the primary member")
    
    return None

======





FLAG_PRIORITY = {
    "Critical": 1,
    "Out of Standard": 2,
    "Low Impact": 3,
    # Add other flag types here as needed.
}

def apply_rules(wideip_entry: dict):
    """
    Runs all rule functions on the wideip_entry.
    If multiple rules trigger, choose the main flag based on priority
    (Critical is highest) and combine comments as a numbered list.
    """
    triggered_rules = []
    for rule in RULES:
        result = rule(wideip_entry)
        if result is not None:
            triggered_rules.append(result)  # result is a (flag, comment) tuple

    if triggered_rules:
        # Determine the main flag by selecting the one with the highest priority.
        main_flag = min(
            (flag for flag, _ in triggered_rules),
            key=lambda f: FLAG_PRIORITY.get(f, 99)
        )

        # Combine comments into a numbered list.
        comments = []
        for idx, (_, comment) in enumerate(triggered_rules, start=1):
            comments.append(f"{idx}) {comment}")
            
        wideip_entry["flag"] = main_flag
        wideip_entry["comment"] = "; ".join(comments)

def rule_missing_description(wideip_entry: dict):
    """
    Rule:
    If the WideIP description is missing or empty, flag this as Out of Standard.
    
    Returns:
        (flag, comment) tuple if the rule is triggered, otherwise None.
    """
    description = wideip_entry.get("description", "").strip()
    if not description:
        return ("Out of Standard", "Description is missing for the WideIP")
    return None
============



def rule_no_fallback_none(wideip_entry: dict):
    """
    Rule:
    If none of the pools in the WideIP has fallbackMode set to 'none',
    flag this as Critical.

    Returns:
        (flag, comment) tuple if the rule is triggered, otherwise None.
    """
    pools = wideip_entry.get("pools", [])
    
    # Check if at least one pool has fallbackMode equal to 'none'
    if not any(pool.get("fallbackMode", "").lower() == "none" for pool in pools):
        return ("Critical", "None of the pools has fallbackMode set to 'none'")
    
    return None







def rule_fallback_return_to_dns(wideip_entry: dict):
    """
    Rule:
    If at least one pool in the WideIP has fallbackMode 'return-to-dns',
    then check ALL pools. If none of the pool member IPs (from any pool)
    are found in the WideIP's A‑Record list, return a critical flag.
    
    Returns:
        (flag, comment) tuple if the rule is triggered, otherwise None.
    """
    a_record_ips = wideip_entry.get("A-Record", [])
    pools = wideip_entry.get("pools", [])
    
    # Check if any pool has fallbackMode "return-to-dns"
    if not any(pool.get("fallbackMode", "").lower() == "return-to-dns" for pool in pools):
        # No pool is using return-to-dns, so rule not applicable.
        return None

    # If at least one pool uses return-to-dns, check ALL pool members from every pool.
    all_members = []
    for pool in pools:
        all_members.extend(pool.get("members", []))
    
    # Compare the extracted IPs against the A‑Record list.
    if not any(extract_ip(member) in a_record_ips for member in all_members):
        return ("Critical", 
                "At least one pool has fallbackMode 'return-to-dns', but no pool member IP from any pool "
                "is found in the A‑Record")
    
    # Otherwise, the condition is satisfied.
    return None





def rule_fallback_return_to_dns(wideip_entry: dict):
    """
    Rule:
    If any pool in the WideIP has fallbackMode 'return-to-dns'
    but none of its pool member IPs are found in the WideIP's A-Record,
    flag this as Critical.
    
    Returns:
        (flag, comment) tuple if rule is triggered, else None.
    """
    a_record_ips = wideip_entry.get("A-Record", [])
    for pool in wideip_entry.get("pools", []):
        if pool.get("fallbackMode", "").lower() == "return-to-dns":
            pool_members = pool.get("members", [])
            # Ensure we compare using extracted IP addresses
            match_found = any(extract_ip(pm) in a_record_ips for pm in pool_members)
            if not match_found:
                return ("Critical", "Pool fallbackMode is 'return-to-dns' but no pool member IP is found in the A-Record")
    return None

# List of rules. In the future, add more functions to this list.
RULES = [
    rule_fallback_return_to_dns,
    # rule_another,  # Add more rules here.
]

def apply_rules(wideip_entry: dict):
    """
    Runs all the rule functions against the wideip_entry.
    Accumulates any flags and comments, and adds them to the entry.
    """
    flags = []
    comments = []
    for rule in RULES:
        result = rule(wideip_entry)
        if result:
            flags.append(result[0])
            comments.append(result[1])
    # Add new keys to the entry. You can change the key names as needed.
    wideip_entry["flag"] = flags
    wideip_entry["comment"] = "; ".join(comments)
    
############################
# END OF RULE SECTION      #
############################









def extract_ip(pool_member: str) -> str:
    """
    Extract the IP address from a pool member string.
    
    If the string contains a colon, try the following:
      - If the part before the colon is a valid dotted IP, return it.
      - Otherwise, assume the part after the colon is underscore separated,
        split it and join the first four segments with dots.
    
    If no colon is found and underscores are present, try to split by underscore.
    Otherwise, return the pool_member as-is.
    """
    # Case 1: Pool member contains a colon
    if ":" in pool_member:
        parts = pool_member.split(":", 1)
        candidate_ip = parts[0]
        # Check if candidate_ip is in dotted format (e.g., "171.132.23.23")
        if re.match(r'^\d{1,3}(?:\.\d{1,3}){3}$', candidate_ip):
            return candidate_ip
        else:
            # Assume the part after the colon is underscore separated like "171_132_23_23_443"
            underscore_parts = parts[1].split("_")
            if len(underscore_parts) >= 5:
                # Join the first four parts to form the IP
                return ".".join(underscore_parts[:4])
            else:
                # Fallback: return the part after colon (or candidate_ip)
                return parts[1]
    
    # Case 2: No colon but the string might be underscore separated
    if "_" in pool_member:
        underscore_parts = pool_member.split("_")
        if len(underscore_parts) >= 5:
            return ".".join(underscore_parts[:4])
        else:
            return ".".join(underscore_parts)
    
    # Case 3: Otherwise, return the pool_member as is
    return pool_member





def load_a_records(file_path: str) -> dict:
    a_records = defaultdict(list)
    # Adjust regex to allow for extra spaces and leading/trailing whitespace
    pattern = re.compile(r'^\s*(?P<wip>\S+)\s+\d+\s+IN\s+A\s+(?P<ip>\S+)', re.IGNORECASE)
    
    try:
        with open(file_path, 'r') as f:
            for line in f:
                match = pattern.search(line)
                if match:
                    # Remove any trailing dot, strip extra spaces, and normalize to lower case
                    wip = match.group('wip').strip().rstrip('.').lower()
                    ip = match.group('ip')
                    if ip not in a_records[wip]:
                        a_records[wip].append(ip)
                    # Optionally, print for debugging:
                    # print(f"Loaded A record: {wip} -> {ip}")
    except Exception as e:
        print(f"Error loading A records from {file_path}: {e}")
    return a_records


================
A_RECORDS_MAPPING = {}
def load_a_records(file_path: str) -> dict:
    """
    Loads the A records from the specified file.
    Expected line format (with extra spaces possible):
      <wipname>   45 IN A  <ip>
    This function returns a dictionary mapping wipname to a list of IP addresses.
    """
    a_records = defaultdict(list)
    # Regex breakdown:
    #   ^(?P<wip>\S+)\s+  : Start of line, capture the wip name (non-space) followed by one or more spaces.
    #   \d+\s+           : A number (could be 45 or something else) followed by spaces.
    #   IN\s+A\s+        : The literal string "IN A" with spaces around.
    #   (?P<ip>\S+)      : Capture the IP (non-space characters).
    pattern = re.compile(r'^(?P<wip>\S+)\s+\d+\s+IN\s+A\s+(?P<ip>\S+)', re.IGNORECASE)
    
    try:
        with open(file_path, 'r') as f:
            for line in f:
                match = pattern.search(line)
                if match:
                    wip = match.group('wip')
                    ip = match.group('ip')
                    # Avoid duplicates if necessary
                    if ip not in a_records[wip]:
                        a_records[wip].append(ip)
    except Exception as e:
        print(f"Error loading A records from {file_path}: {e}")
    return a_records

wideip_entry["A-Record"] = A_RECORDS_MAPPING.get(wideip_name, [])




import re  # Ensure re is imported (it is already at the top)
                    env_map = {'p': 'Production', 't': 'Test', 's': 'UAT'}
                    env_set = set()

                    # Check each pool's name for the environment letter
                    for pool in wideip_entry['pools']:
                        pool_name = pool.get("pool_name", "")
                        # Look for an underscore, a single letter (p, t, or s), then another underscore.
                        match = re.search(r'_(?P<env>[pts])_', pool_name, re.IGNORECASE)
                        if match:
                            env_set.add(match.group("env").lower())

                    if not env_set:
                        wideip_entry["environment"] = "Missing"
                    elif len(env_set) == 1:
                        # Only one unique environment letter found; map it accordingly.
                        env_letter = env_set.pop()
                        wideip_entry["environment"] = env_map.get(env_letter, "Unknown")
                    else:
                        # More than one unique environment letter found among the pools.
                        wideip_entry["environment"] = "Non Standard"
                    # --- End of new code ---
========
def get_f5_based_vips(credentials: dict, device_list: list) -> None:
    for f5_device in device_list:
        device = f5_device['device']
        device_ip = f5_device['ip']

        try:
            # Fetch WideIP Data
            vs_response = requests.get(
                f"https://{device_ip}/mgmt/tm/gtm/wideip/a?expandSubcollections=true", verify=False, headers={'Content-Type': 'application/json'},
                auth=(credentials['username'], credentials['password']))
            vs_json_response = vs_response.json().get('items', [])

            # Fetch Pool Data
            pool_response = requests.get(
                f"https://{device_ip}/mgmt/tm/gtm/pool/a?expandSubcollections=true", verify=False, headers={'Content-Type': 'application/json'},
                auth=(credentials['username'], credentials['password']))
            pool_json_response = pool_response.json().get('items', [])

            # Process each WideIP entry
            for vs in vs_json_response:
                try:
                    wideip_name = vs.get('name', '')
                    description = vs.get('description', '')
                    poollbMode = vs.get('poollbMode', '')
                    wip_pools = vs.get('pools', [])
                    
                    # Determine environment
                    environment_codes = set()
                    for wip_pool in wip_pools:
                        pool_name = wip_pool.get('name', '')
                        match = re.search(r'_([pts])_', pool_name)
                        if match:
                            environment_codes.add(match.group(1).upper())
                    
                    if not environment_codes:
                        environment = "Missing"
                    elif len(environment_codes) == 1:
                        environment = environment_codes.pop()
                    else:
                        environment = "Non Standard"
                    
                    # Store extracted data
                    wideip_entry = {
                        "device": device.upper(),
                        "wideip_name": wideip_name,
                        "description": description,
                        "poollbMode": poollbMode,
                        "environment": environment,
                        "pools": []
                    }

                    # Extract Pools
                    for wip_pool in wip_pools:
                        pool_name = wip_pool.get('name', '')
                        pool_order = wip_pool.get('order', '')

                        # Fetch Pool Details
                        pool_obj = next((p for p in pool_json_response if p.get('name', '') == pool_name), None)

                        if pool_obj:
                            fallbackMode = pool_obj.get('fallbackMode', '')
                            loadBalancingMode = pool_obj.get('loadBalancingMode', '')

                            # Extract Pool Members
                            pool_members = []
                            members_ref = pool_obj.get('membersReference', {}).get('items', [])

                            for member in members_ref:
                                member_name = member.get('name', '')
                                pool_members.append(member_name)

                            # Add to WideIP Pools
                            wideip_entry['pools'].append({
                                "pool_name": pool_name,
                                "order": pool_order,
                                "fallbackMode": fallbackMode,
                                "loadBalancingMode": loadBalancingMode,
                                "members": pool_members
                            })

                    print(f"Storing to DB - VIP: {vs['name']}, Pool Name: {pool_name}, Pool Members: {pool_members}")

                    # Insert into TinyDB
                    lock.acquire()
                    db.insert(wideip_entry)
                    lock.release()

                except Exception as e:
                    print(f"Error processing WideIP {wideip_name}: {e}")

        except Exception as e:
            lock.acquire()
            print(f"{device.upper()} not reachable! Error: {e}")
            lock.release()
            continue

    lock.acquire()
    print(f"{device.upper()} - Completed Scanning!")
    lock.release()
