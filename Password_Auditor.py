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
import subprocess
from browser_pass import extract_browser_passwords

print("""
\n\n██████╗  █████╗ ███████╗███████╗ ██████╗ ██╗   ██╗██████╗ ████████╗ ██████╗ ██████╗ 
██╔══██╗██╔══██╗╚══███╔╝██╔════╝██╔═══██╗██║   ██║██╔══██╗╚══██╔══╝██╔═══██╗██╔══██╗
██████╔╝███████║  ███╔╝ █████╗  ██║   ██║██║   ██║██████╔╝   ██║   ██║   ██║██████╔╝
██╔═══╝ ██╔══██║ ███╔╝  ██╔══╝  ██║▄▄ ██║██║   ██║██╔═══╝    ██║   ██║   ██║██╔═══╝ 
██║     ██║  ██║███████╗███████╗╚██████╔╝╚██████╔╝██║        ██║   ╚██████╔╝██║     
╚═╝     ╚═╝  ╚═╝╚══════╝╚══════╝ ╚══▀▀═╝  ╚═════╝ ╚═╝        ╚═╝    ╚═════╝ ╚═╝     
                                                                                  
            Version 1.4 (Linux/KDE Edition) - Educational Use Only
""")
print("Loading Password Auditor modules...\n")

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


def _get_wallet_name():
    for qdbus in ["qdbus", "qdbus6"]:
        try:
            res = subprocess.run(
                [qdbus, "org.kde.kwalletd5", "/modules/kwalletd5",
                 "org.kde.KWallet.networkWallet"],
                capture_output=True, text=True, timeout=3
            )
            if res.returncode == 0 and res.stdout.strip():
                return res.stdout.strip()
        except Exception:
            continue
    return "kdewallet"


def _kwallet_list_keys(wallet, folder):
    try:
        res = subprocess.run(
            ["kwallet-query", "-l", wallet, "-f", folder],
            capture_output=True, text=True, timeout=3
        )
        if res.returncode == 0:
            return [l.strip() for l in res.stdout.splitlines() if l.strip()]
    except Exception:
        pass
    return []


def _kwallet_read(wallet, folder, key):
    try:
        res = subprocess.run(
            ["kwallet-query", "-r", key, "-f", folder, wallet],
            capture_output=True, timeout=3
        )
        if res.returncode == 0 and res.stdout.strip():
            return res.stdout.strip()
    except Exception:
        pass
    return None


def _extract_uuid_from_key(kkey):
    """
    KWallet key format: {4223e1c0-587e-455e-9621-27c2d3d6111d};802-11-wireless-security
    Need to extract just the UUID without any braces.
    Split on ; first, then strip braces from the uuid part.
    """
    uuid_part = kkey.split(";")[0]       # '{4223e1c0-587e-455e-9621-27c2d3d6111d}'
    uuid      = uuid_part.strip("{}")    # '4223e1c0-587e-455e-9621-27c2d3d6111d'
    return uuid


def extract_wifi_passwords():
    wifi_details    = []
    connections_dir = "/etc/NetworkManager/system-connections/"

    print("\n[*] Extracting Wi-Fi passwords...")

    # Step 1: build UUID -> {ssid, psk} map from .nmconnection files
    try:
        ls_res = subprocess.run(
            ["sudo", "ls", connections_dir],
            capture_output=True, text=True
        )
        if ls_res.returncode != 0:
            print(f"    [!] Cannot list {connections_dir}: {ls_res.stderr.strip()}")
            return [f"Wi-Fi: Failed to list connections: {ls_res.stderr.strip()}\n"]
        filenames = [f for f in ls_res.stdout.splitlines() if f.strip()]
    except Exception as e:
        return [f"Wi-Fi: Error: {e}\n"]

    uuid_map = {}
    for filename in filenames:
        filepath = os.path.join(connections_dir, filename)
        try:
            res = subprocess.run(
                f"sudo grep -E '^id=|^uuid=|^psk=' '{filepath}'",
                shell=True, capture_output=True, text=True
            )
            lines = {
                l.split("=", 1)[0]: l.split("=", 1)[1]
                for l in res.stdout.splitlines() if "=" in l
            }
            ssid = lines.get("id", filename)
            uuid = lines.get("uuid", "").strip()
            psk  = lines.get("psk", None)
            if uuid:
                uuid_map[uuid] = {"ssid": ssid, "psk": psk}
        except Exception as e:
            wifi_details.append(f"{filename} : Error reading file - {e}")

    # Step 2: pull passwords from KWallet "Network Management" folder
    wallet       = _get_wallet_name()
    kwallet_keys = _kwallet_list_keys(wallet, "Network Management")

    kwallet_psk_map = {}
    for kkey in kwallet_keys:
        uuid = _extract_uuid_from_key(kkey)   # clean UUID, no braces
        raw  = _kwallet_read(wallet, "Network Management", kkey)
        if not raw:
            continue
        try:
            text = raw.decode(errors="ignore") if isinstance(raw, bytes) else raw
            data = json.loads(text)
            psk  = data.get("psk") or data.get("password")
            if psk:
                kwallet_psk_map[uuid] = psk
        except json.JSONDecodeError:
            # Not JSON — use raw string directly
            val = raw.decode(errors="ignore") if isinstance(raw, bytes) else str(raw)
            if val:
                kwallet_psk_map[uuid] = val

    # Step 3: merge and output, deduplicate by SSID+psk
    seen = set()
    for uuid, info in uuid_map.items():
        ssid = info["ssid"]
        psk  = info["psk"] or kwallet_psk_map.get(uuid)
        key  = f"{ssid}:{psk}"
        if key in seen:
            continue
        seen.add(key)

        if psk:
            print(f"    [+] {ssid}: {psk}")
            wifi_details.append(f"{ssid} : {psk}")
        else:
            print(f"    [-] {ssid}: [NO PASSWORD FOUND]")
            wifi_details.append(f"{ssid} : [NO PASSWORD FOUND]")

    return wifi_details


if __name__ == "__main__":
    if os.geteuid() != 0:
        if subprocess.call(["sudo", "-n", "true"], stderr=subprocess.DEVNULL) != 0:
            print("[*] Sudo privileges required for Wi-Fi extraction.")
            print("    Please enter your sudo password below:")
            try:
                subprocess.check_call(["sudo", "-v"])
            except subprocess.CalledProcessError:
                print("\n[!] Sudo auth failed. Wi-Fi extraction will fail.\n")
    else:
        print("[!] WARNING: Running as root. Browser password extraction WILL FAIL.")
        print("    Run as normal user: python3 Password_Auditor.py\n")

    all_output = []

    all_output.append("=== Wi-Fi Profiles and Passwords ===\n")
    wifi_data = extract_wifi_passwords()
    all_output.extend([f + "\n" for f in wifi_data])

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

    final_report = f"{name}_report.txt"
    with open(final_report, "w", encoding="utf-8") as f:
        f.writelines(all_output)

    print(f"\n[✔] Report saved: {final_report}")
    print("NOTE: This report contains sensitive information. Handle it securely.\n")
