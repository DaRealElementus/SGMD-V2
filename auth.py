"""
Outdated code, no longer used in the project.
"""


import sqlite3
import hashlib

def sha256_hash(data: str) -> str:
    """Returns the SHA-256 hash of the input data as a hexadecimal string."""
    return hashlib.sha256(data.encode()).hexdigest()


## DB simulator, no longer used



DB_PATH = "chatbot.db"

def init_db(cursor):
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS USRs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        mac_address TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL
    )
    ''')
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS HISTORY (
        id INTEGER NOT NULL PRIMARY KEY,
        history TEXT,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (id) REFERENCES USRs(id)
    )
    ''')

def authenticate_user(cursor, mac_hashed, pw_hashed):
    cursor.execute("SELECT id FROM USRs WHERE mac_address = ? AND password = ?", (mac_hashed, pw_hashed))
    result = cursor.fetchone()
    return result[0] if result else None

def signup_user(cursor, mac_hashed, pw_hashed):
    try:
        cursor.execute("INSERT INTO USRs (mac_address, password) VALUES (?, ?)", (mac_hashed, pw_hashed))
        print("Signup successful.")
    except sqlite3.IntegrityError:
        print("MAC address already registered.")

# Optional: Standalone signup and login functions for CLI use
def signup(mac_address: str, password: str):
    mac_hash = sha256_hash(mac_address)
    pass_hash = sha256_hash(password)
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    init_db(cursor)
    try:
        cursor.execute("INSERT INTO USRs (mac_address, password) VALUES (?, ?)", (mac_hash, pass_hash))
        conn.commit()
        print("Signup successful.")
    except sqlite3.IntegrityError:
        print("MAC address already registered.")
    finally:
        conn.close()

def login(mac_address: str, password: str) -> int:
    mac_hash = sha256_hash(mac_address)
    pass_hash = sha256_hash(password)
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM USRs WHERE mac_address = ? AND password = ?", (mac_hash, pass_hash))
    result = cursor.fetchone()
    conn.close()
    if result:
        print("Login successful.")
        return result[0]
    else:
        print("Login failed.")
        return -1
