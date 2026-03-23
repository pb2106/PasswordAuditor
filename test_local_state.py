import json, os
path = os.path.expanduser("~/.config/chromium/Local State")
try:
    with open(path, "r") as f:
        js = json.load(f)
    if "os_crypt" in js and "encrypted_key" in js["os_crypt"]:
        print("Found encrypted_key:", js["os_crypt"]["encrypted_key"][:40] + "...")
    else:
        print("No encrypted_key found in os_crypt")
except Exception as e:
    print("Error:", e)
