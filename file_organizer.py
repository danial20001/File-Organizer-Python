# Extract Pool Name - Minimal Change
pools = vs.get('pool', 'N/A')
pool_members = "N/A"

if pools != "N/A":
    pool_names = pools.split(",")  # Ensure multiple pools are handled
    for pool_name in pool_names:
        pool_name = pool_name.split('/')[-1]  # Extract actual pool name
