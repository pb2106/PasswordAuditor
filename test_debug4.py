from Crypto.Cipher import AES
from hashlib import pbkdf2_hmac

enc = bytes.fromhex("763131d371328cba999c1d9f29c8339fbc2636")
assert enc[:3] == b"v11"
enc = enc[3:]
print("Ciphertext hex:", enc.hex())

for secret in [b"peanuts", b"chrome_safe_storage", b"Chromium Safe Storage"]:
    key = pbkdf2_hmac("sha1", secret, b"saltysalt", 1, 16)
    cipher = AES.new(key, AES.MODE_CBC, b" " * 16)
    dec = cipher.decrypt(enc)
    print(f"Secret: {secret}")
    print(f"Decrypted hex: {dec.hex()}")
    print(f"Last byte (pad_len): {dec[-1]}")
    try:
        unpadded = dec[:-dec[-1]]
        print(f"Unpadded: {repr(unpadded.decode(errors='ignore'))}")
    except Exception as e:
        print(f"Error: {e}")
    print("---")
