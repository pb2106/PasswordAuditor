#  Password Auditor — Linux/KDE Edition

```
██████╗  █████╗ ███████╗███████╗ ██████╗ ██╗   ██╗██████╗ ████████╗ ██████╗ ██████╗ 
██╔══██╗██╔══██╗╚══███╔╝██╔════╝██╔═══██╗██║   ██║██╔══██╗╚══██╔══╝██╔═══██╗██╔══██╗
██████╔╝███████║  ███╔╝ █████╗  ██║   ██║██║   ██║██████╔╝   ██║   ██║   ██║██████╔╝
██╔═══╝ ██╔══██║ ███╔╝  ██╔══╝  ██║▄▄ ██║██║   ██║██╔═══╝    ██║   ██║   ██║██╔═══╝ 
██║     ██║  ██║███████╗███████╗╚██████╔╝╚██████╔╝██║        ██║   ╚██████╔╝██║     
╚═╝     ╚═╝  ╚═╝╚══════╝╚══════╝ ╚══▀▀═╝  ╚═════╝ ╚═╝        ╚═╝    ╚═════╝ ╚═╝     
```

>  **For educational purposes only.** Run it on systems you own. We are not responsible for what you do with this.

---

## // WHAT IT DOES

Rips credentials straight from your own machine:

- 📶 **Wi-Fi passwords** — reads NetworkManager profiles + pulls secrets from KWallet
- 🌐 **Browser logins** — decrypts saved passwords from all Chromium-based browsers using the AES key stored in KWallet
- 💾 **Saves a report** — everything dumped to a local `.txt` file

---

## // REQUIREMENTS

**System:**
- KDE Plasma (KWallet must be running and unlocked)
- NetworkManager
- `kwallet-query` + `qdbus` — already on your system if you're on KDE
- `sudo` — needed to read NetworkManager connection files

**Python:**
```
pycryptodome
```

---

## // SETUP

```bash
git clone https://github.com/pb2106/PasswordAuditor.git
cd PasswordAuditor

python3 -m venv venv
source venv/bin/activate

pip install -r requirements.txt
```

---

## // USAGE

```bash
python3 Password_Auditor.py
```

> ⚡ Run as a **normal user**, NOT root. KWallet is inaccessible as root and browser decryption will fail.

You'll be prompted for sudo (needed for Wi-Fi files only). Everything else runs in userspace.

Output lands here:
```
<username>_<macaddress>_report.txt
```

> 🚨 Add `*_report.txt` to your `.gitignore`. Do NOT commit this file — it contains plaintext credentials.

---

## // HOW IT WORKS

### Wi-Fi

NetworkManager keeps connection profiles in `/etc/NetworkManager/system-connections/`. Some store the password inline as `psk=`. Most don't — they set `psk-flags=1` which means *"ask the secrets agent"*.

On KDE, that agent is **KWallet**. The password lives in the `Network Management` folder, keyed by UUID:

```
{uuid};802-11-wireless-security  →  { "psk": "yourpassword" }
```

The tool:
1. Reads all `.nmconnection` files → builds a `UUID → SSID` map
2. Lists keys in KWallet `Network Management` folder
3. Pulls and parses the JSON blob for each UUID
4. Merges everything into one clean output

### Browser Passwords

Chromium browsers store logins in a SQLite DB:
```
~/.config/<browser>/Default/Login Data
```

Each password is encrypted with **AES-128-CBC**. The key is derived from a secret stored in KWallet (`Chromium Keys` folder, `Chromium Safe Storage` key) using:
```
PBKDF2-SHA1(secret, salt=b"saltysalt", iterations=1, keylen=16)
```

The tool:
1. Resolves the real wallet name dynamically via `qdbus`
2. Fuzzy-matches KWallet folders against the browser name — **no hardcoded folder/key names**
3. Derives the AES key from whatever secret it finds
4. Decrypts every entry in the SQLite DB

---

## // SUPPORTED BROWSERS

| Browser   | Path |
|-----------|------|
| Chromium  | `~/.config/chromium` |
| Chrome    | `~/.config/google-chrome` |
| Edge      | `~/.config/microsoft-edge` |
| Brave     | `~/.config/BraveSoftware/Brave-Browser` |
| Opera     | `~/.config/opera` |

Adding a new browser takes one line in `browser_pass.py`:
```python
"vivaldi": ("vivaldi", "~/.config/vivaldi"),
```

---

## // FILE STRUCTURE

```
PasswordAuditor/
├── Password_Auditor.py   # entry point — Wi-Fi + report
├── browser_pass.py       # browser decryption + KWallet discovery
├── requirements.txt      # deps
└── README.md
```

---

## // AUTHORS

- **G Abhiram**
- **Chirag Anil Ramamurthy**
- **Prabhav M Naik** *(Contributor)*

---

## // DISCLAIMER

This tool is for **educational purposes only**. It is designed to show how credentials are stored locally on Linux systems. Only use it on machines you own or have explicit permission to audit. Misuse is your problem, not ours.
