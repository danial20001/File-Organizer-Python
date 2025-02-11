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
