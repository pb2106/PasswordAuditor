import os, sqlite3, shutil
import secretstorage
from hashlib import pbkdf2_hmac
from Crypto.Cipher import AES

BASE = os.path.expanduser("~/.config/chromium")
LOGIN_DB = f"{BASE}/Default/Login Data"
TMP_DB = "/tmp/chromium_login_test.db"
shutil.copy2(LOGIN_DB, TMP_DB)

bus = secretstorage.dbus_init()
collection = secretstorage.get_default_collection(bus)
print("Locked:", collection.is_locked())

secret = None
for item in collection.get_all_items():
    label = item.get_label()
    if "Safe Storage" in label:
        secret = item.get_secret()
        print("Found secret for:", label)
        break

if not secret:
    print("No secret found in libsecret. Falling back to default 'peanuts'...")
    secret = b"peanuts"

key = pbkdf2_hmac("sha1", secret, b"saltysalt", 1, 16)

def decrypt_pw(enc):
    if enc[:3] in (b"v10", b"v11"):
        enc = enc[3:]
    iv = b" " * 16
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted = cipher.decrypt(enc)
    pad_len = decrypted[-1]
    return decrypted[:-pad_len].decode(errors="ignore")

db = sqlite3.connect(TMP_DB)
cur = db.cursor()
cur.execute("SELECT origin_url, username_value, password_value FROM logins")
rows = cur.fetchall()
print(f"Found {len(rows)} rows in logins table.")
for url, user, enc in rows:
    if not enc: continue
    if isinstance(enc, memoryview): enc = enc.tobytes()
    print("Encrypted starts with:", enc[:3])
    try:
        pwd = decrypt_pw(enc)
        print("Decrypted:", repr(user), repr(pwd))
    except Exception as e:
        print("Decrypt failed:", e)

