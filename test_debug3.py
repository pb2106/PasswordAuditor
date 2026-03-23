import sqlite3
db = sqlite3.connect("/tmp/chromium_login_test.db")
cur = db.cursor()
cur.execute("SELECT origin_url, username_value, password_value FROM logins")
for url, user, enc in cur.fetchall():
    print("User:", user)
    print("Enc hex:", enc.hex())
