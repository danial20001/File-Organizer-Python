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
