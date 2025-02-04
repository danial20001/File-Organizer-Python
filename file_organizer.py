# Get your Pool Names (handle multiple pools if they exist)
pool_names = vs.get('pool', 'N/A')

# Ensure pool_names is always a list
if isinstance(pool_names, str): 
    pool_names = [pool_names]

for pool_path in pool_names:
    pool_name = pool_path.split('/')[-1]  # Extract the actual pool name
    pool_members = "N/A"

    if pool_name != "N/A":
        try:
            # Fetch members for each pool
            pool_response = requests.get(
                f"https://{device_ip}/mgmt/tm/ltm/pool/{pool_name}/members",
                verify=False,
                auth=(credentials['username'], credentials['password'])
            )
            pool_json_response = pool_response.json()

            # Extract all member addresses
            pool_members = ", ".join(
                [member['address'] for member in pool_json_response.get('items', [])]
            ) if pool_json_response.get('items') else "None"

        except Exception as e:
            pool_members = f"Error Fetching: {str(e)}"

    print(f"Storing to DB - VIP: {vs['name']}, Pool Name: {pool_name}, Pool Members: {pool_members}")





# UPDATED: Extract Pool Names
                            pool_names = vs.get('pool', 'N/A')
                            if isinstance(pool_names, str):
                                pool_names = [pool_names]
                            
                            for pool_name in pool_names:
                                pool_name = pool_name.split('/')[-1]
                                pool_members = "N/A"

# Extract Pool Name - Minimal Change
pools = vs.get('pool', 'N/A')
pool_members = "N/A"

if pools != "N/A":
    pool_names = [p.strip() for p in pools.split(",")]  # Strip spaces and ensure list format
    for pool_name in pool_names:
        pool_name = pool_name.split('/')[-1]  # Extract actual pool name

        try:
            # Fetch Pool Members - UPDATED
            pool_response = requests.get(f"https://{device_ip}/mgmt/tm/ltm/pool/{pool_name}/members",
                                         verify=False, headers={'Content-Type': 'application/json'},
                                         auth=(credentials['username'], credentials['password']))

            if pool_response.status_code == 200:  # Ensure the request was successful
                pool_json_response = pool_response.json()
                pool_members = ", ".join([member.get('address', 'N/A') for member in pool_json_response.get('items', [])])
            else:
                pool_members = "Error: Response Code " + str(pool_response.status_code)

        except Exception as e:
            pool_members = f"Error: {str(e)}"
            print(f"Error Fetching pool members for {pool_name}: {str(e)}")
            

