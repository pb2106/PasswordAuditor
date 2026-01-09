"""
PASSWORD AUDITOR - Educational Credential & Wi-Fi Recovery Tool (Linux Edition)

Author(s): G Abhiram, Chirag Anil Ramamurthy
Contributor: Prabhav M Naik
Linux Port: Antigravity

DISCLAIMER:
This tool is strictly for educational purposes only. It is intended to demonstrate how
locally stored credentials and Wi-Fi passwords can be accessed on a Linux system
that the user owns and has permission to audit. The authors do not condone or support
any form of malicious activity using this code. We are not responsible for any misuse
or illegal use of this script.
"""
import os
import json
import sqlite3
import shutil
import base64
import subprocess
import secretstorage
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from browser_pass import extract_browser_passwords
from hashlib import pbkdf2_hmac
from Crypto.Cipher import AES
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
                                                                                  
            Version 1.0 (Linux Edition) - Educational Use Only
""")
print("Loading Password Auditor modules...\n")

# --------------------------------------
# Resolve current username and MAC address
# --------------------------------------
try:
    name = os.getlogin()
except:
    name = "UnknownUser"

mac = "UNKNOWN_MAC"
try:
    # Try to get the MAC address of the default interface
    ip_route = subprocess.check_output(["ip", "route", "show", "default"], text=True)
    default_dev = ip_route.split("dev")[1].split()[0]
    with open(f"/sys/class/net/{default_dev}/address", "r") as f:
        mac = f.read().strip()
except Exception:
    pass

name += f"_{mac.replace(':', '')}"



# -----------------------------
# Wi-Fi Password Extraction
# -----------------------------
# -----------------------------
# Wi-Fi Password Extraction (File-based)
# -----------------------------
def extract_wifi_passwords():
    wifi_details = []
    connections_dir = "/etc/NetworkManager/system-connections/"
    
    print("\n[*] Extracting Wi-Fi passwords (via system files)...")
    
    # 1. Get list of files (requires sudo)
    try:
        ls_cmd = ["sudo", "ls", connections_dir]
        result = subprocess.run(ls_cmd, capture_output=True, text=True)
        if result.returncode != 0:
            print(f"    [!] Failed to list {connections_dir}: {result.stderr.strip()}")
            return [f"Wi-Fi: Failed to list system connections: {result.stderr.strip()}\n"]
            
        filenames = result.stdout.splitlines()
    except Exception as e:
        print(f"    [!] Error listing files: {e}")
        return [f"Wi-Fi: Error listing files: {str(e)}\n"]

    for filename in filenames:
        if not filename: continue
        filepath = os.path.join(connections_dir, filename)
        
        try:
            # User requested: sudo cat ... | grep psk=
            # We will try to grep for psk= and wep-key0=
            
            # 1. Try getting PSK
            psk = None
            cmd = f"sudo cat '{filepath}' | grep psk="
            result = subprocess.run(cmd, capture_output=True, text=True, shell=True)
            
            if result.returncode == 0 and result.stdout.strip():
                # Output format: psk=PASSWORD
                line = result.stdout.strip()
                if "=" in line:
                    psk = line.split("=", 1)[1]

            # 2. If no PSK, try WEP key
            if not psk:
                cmd = f"sudo cat '{filepath}' | grep wep-key0="
                result = subprocess.run(cmd, capture_output=True, text=True, shell=True)
                if result.returncode == 0 and result.stdout.strip():
                    line = result.stdout.strip()
                    if "=" in line:
                        psk = line.split("=", 1)[1]

            # 3. Get SSID for display (we still need to read the file or grep it)
            ssid = filename # Default to filename
            cmd = f"sudo cat '{filepath}' | grep ssid="
            result = subprocess.run(cmd, capture_output=True, text=True, shell=True)
            if result.returncode == 0 and result.stdout.strip():
                 line = result.stdout.strip()
                 if "=" in line:
                     ssid = line.split("=", 1)[1]

            if psk:
                print(f"    [+] {ssid}: {psk}")
                wifi_details.append(f"{ssid} : {psk}")
            else:
                # Check for key-mgmt to see if it's Enterprise/Open
                cmd = f"sudo cat '{filepath}' | grep key-mgmt="
                result = subprocess.run(cmd, capture_output=True, text=True, shell=True)
                status = "OPEN/UNKNOWN"
                if result.returncode == 0 and result.stdout.strip():
                     status = result.stdout.strip().split("=", 1)[1]
                
                print(f"    [-] {ssid}: [{status}]")
                wifi_details.append(f"{ssid} : [{status}]")
                    
        except Exception as e:
            print(f"    [!] Error processing {filename}: {e}")
            wifi_details.append(f"{filename} : Error - {str(e)}")
                    
        except Exception as e:
            print(f"    [!] Error processing {filename}: {e}")
            wifi_details.append(f"{filename} : Error - {str(e)}")

    return wifi_details



# -----------------------------
# MAIN
# -----------------------------
if __name__ == "__main__":
    # We need to run as USER for Keyring access, but need SUDO for Wi-Fi.
    if os.geteuid() != 0:
        # Check if we already have sudo privileges
        if subprocess.call(["sudo", "-n", "true"], stderr=subprocess.DEVNULL) != 0:
            print("[*] Sudo privileges required for Wi-Fi extraction.")
            print("    Please enter your sudo password below:")
            try:
                subprocess.check_call(["sudo", "-v"])
            except subprocess.CalledProcessError:
                print("\n[!] Sudo authentication failed. Wi-Fi extraction will fail.\n")
    else:
        print("[!] WARNING: Running as root. Browser password extraction WILL FAIL (Keyring inaccessible).")
        print("    Please run as a normal user: ./venv/bin/python3 Password_Auditor.py")

    all_output = []

    all_output.append("Wi-Fi Profiles and Passwords ===\n")
    wifi_data = extract_wifi_passwords()
    all_output.extend([f + "\n" for f in wifi_data])

    # Browser Paths (Linux)
    # Chrome
    all_output.append("\n=== Chrome Saved Logins ===\n")
    all_output.extend(extract_browser_passwords('Chrome'))

    # Chromium
    all_output.append("\n=== Chromium Saved Logins ===\n")
    all_output.extend(extract_browser_passwords('Chromium'))

    # Edge (Linux)
    all_output.append("\n=== Edge Saved Logins ===\n")
    all_output.extend(extract_browser_passwords('Edge'))

    # Opera (Linux)
    all_output.append("\n=== Opera Saved Logins ===\n")
    all_output.extend(extract_browser_passwords('Opera'))
    
    # Brave (Linux)
    all_output.append("\n=== Brave Saved Logins ===\n")
    all_output.extend(extract_browser_passwords('Brave'))

    # Save Results Locally
    final_report = f"{name}_report.txt"
    with open(final_report, 'w', encoding='utf-8') as report_file:
        report_file.writelines(all_output)

    print(f"\n[✔] Report generated: {final_report}\n")
    print("NOTE: This report contains sensitive information. Handle it securely.\n")
