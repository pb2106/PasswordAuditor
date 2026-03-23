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
import subprocess
from browser_pass import extract_browser_passwords

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
                                                                                  
            Version 1.2 (Linux/KDE Edition) - Educational Use Only
""")
print("Loading Password Auditor modules...\n")


# --------------------------------------
# Resolve current username and MAC address
# --------------------------------------
try:
    name = os.getlogin()
except Exception:
    name = "UnknownUser"

mac = "UNKNOWN_MAC"
try:
    ip_route    = subprocess.check_output(["ip", "route", "show", "default"], text=True)
    default_dev = ip_route.split("dev")[1].split()[0]
    with open(f"/sys/class/net/{default_dev}/address", "r") as f:
        mac = f.read().strip()
except Exception:
    pass

name += f"_{mac.replace(':', '')}"


# -----------------------------
# Wi-Fi Password Extraction (File-based, requires sudo)
# -----------------------------
def extract_wifi_passwords():
    wifi_details    = []
    connections_dir = "/etc/NetworkManager/system-connections/"

    print("\n[*] Extracting Wi-Fi passwords (via system files)...")

    try:
        result = subprocess.run(
            ["sudo", "ls", connections_dir],
            capture_output=True, text=True
        )
        if result.returncode != 0:
            print(f"    [!] Failed to list {connections_dir}: {result.stderr.strip()}")
            return [f"Wi-Fi: Failed to list system connections: {result.stderr.strip()}\n"]
        filenames = result.stdout.splitlines()
    except Exception as e:
        print(f"    [!] Error listing files: {e}")
        return [f"Wi-Fi: Error listing files: {str(e)}\n"]

    for filename in filenames:
        if not filename:
            continue
        filepath = os.path.join(connections_dir, filename)

        try:
            psk = None

            # Try PSK
            cmd    = f"sudo cat '{filepath}' | grep psk="
            result = subprocess.run(cmd, capture_output=True, text=True, shell=True)
            if result.returncode == 0 and result.stdout.strip():
                line = result.stdout.strip()
                if "=" in line:
                    psk = line.split("=", 1)[1]

            # Try WEP key
            if not psk:
                cmd    = f"sudo cat '{filepath}' | grep wep-key0="
                result = subprocess.run(cmd, capture_output=True, text=True, shell=True)
                if result.returncode == 0 and result.stdout.strip():
                    line = result.stdout.strip()
                    if "=" in line:
                        psk = line.split("=", 1)[1]

            # Get SSID
            ssid   = filename
            cmd    = f"sudo cat '{filepath}' | grep ssid="
            result = subprocess.run(cmd, capture_output=True, text=True, shell=True)
            if result.returncode == 0 and result.stdout.strip():
                line = result.stdout.strip()
                if "=" in line:
                    ssid = line.split("=", 1)[1]

            if psk:
                print(f"    [+] {ssid}: {psk}")
                wifi_details.append(f"{ssid} : {psk}")
            else:
                cmd    = f"sudo cat '{filepath}' | grep key-mgmt="
                result = subprocess.run(cmd, capture_output=True, text=True, shell=True)
                status = "OPEN/UNKNOWN"
                if result.returncode == 0 and result.stdout.strip():
                    status = result.stdout.strip().split("=", 1)[1]
                print(f"    [-] {ssid}: [{status}]")
                wifi_details.append(f"{ssid} : [{status}]")

        except Exception as e:
            print(f"    [!] Error processing {filename}: {e}")
            wifi_details.append(f"{filename} : Error - {str(e)}")

    return wifi_details


# -----------------------------
# MAIN
# -----------------------------
if __name__ == "__main__":
    if os.geteuid() != 0:
        # Prompt for sudo upfront so Wi-Fi extraction doesn't fail mid-run
        if subprocess.call(["sudo", "-n", "true"], stderr=subprocess.DEVNULL) != 0:
            print("[*] Sudo privileges required for Wi-Fi extraction.")
            print("    Please enter your sudo password below:")
            try:
                subprocess.check_call(["sudo", "-v"])
            except subprocess.CalledProcessError:
                print("\n[!] Sudo authentication failed. Wi-Fi extraction will fail.\n")
    else:
        print("[!] WARNING: Running as root. Browser password extraction WILL FAIL.")
        print("    KWallet is inaccessible as root. Run as a normal user instead:")
        print("    python3 Password_Auditor.py\n")

    all_output = []

    # Wi-Fi
    all_output.append("=== Wi-Fi Profiles and Passwords ===\n")
    wifi_data = extract_wifi_passwords()
    all_output.extend([f + "\n" for f in wifi_data])

    # Browsers — add any new browser by extending this list
    # and adding its entry to BROWSER_CONFIG in browser_pass.py
    browsers = ["Chrome", "Chromium", "Edge", "Opera", "Brave"]

    for browser in browsers:
        print(f"\n[*] Extracting {browser} saved logins...")
        all_output.append(f"\n=== {browser} Saved Logins ===\n")
        results = extract_browser_passwords(browser)
        if results:
            for entry in results:
                print(f"    {entry}")
            all_output.extend([e + "\n" for e in results])
        else:
            print(f"    [-] No logins found or browser not installed.")
            all_output.append("No logins found or browser not installed.\n")

    # Save report
    final_report = f"{name}_report.txt"
    with open(final_report, "w", encoding="utf-8") as f:
        f.writelines(all_output)

    print(f"\n[✔] Report saved: {final_report}")
    print("NOTE: This report contains sensitive information. Handle it securely.\n")
