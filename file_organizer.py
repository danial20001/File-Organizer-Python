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
