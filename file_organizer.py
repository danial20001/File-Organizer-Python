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
