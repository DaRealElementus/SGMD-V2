# main.py
"""
Outdated code, no longer used in the project.
"""


### Server-client side theory test, doesnt actually run server or client
## used to unserstand Sqlite3, hashing, and user authentication

from llama_wrapper import chat_loop
from auth import authenticate_user, signup_user, init_db
import hashlib
import sqlite3
import uuid




def sha256_hash(data: str) -> str:
    """Returns the SHA-256 hash of the input data as a hexadecimal string."""
    return hashlib.sha256(data.encode()).hexdigest()


def get_mac_address() -> str:
    """Returns the MAC address of the first network interface as a string."""
    mac = uuid.getnode()
    mac_str = ':'.join(f'{(mac >> i) & 0xff:02x}' for i in range(40, -1, -8))
    return mac_str

def save_history(cursor, conn, user_id, history):
    # This will overwrite the previous history for the user
    cursor.execute("INSERT OR REPLACE INTO HISTORY (id, history) VALUES (?, ?)", (user_id, history))
    conn.commit()

def main():
    db_conn = sqlite3.connect("chatbot.db")
    db_cursor = db_conn.cursor()
    
    init_db(db_cursor)  # ensure DB is initialized

    print("=== Welcome to Secure LLaMA Chat ===")
    mac = get_mac_address()
    password = input("Enter your password: ")

    mac_hashed = sha256_hash(mac)
    pw_hashed = sha256_hash(password)

    # Try to authenticate, if not found, offer signup
    user_id = authenticate_user(db_cursor, mac_hashed, pw_hashed)
    if user_id:
        print("Login successful. Starting chat...")
        chat_loop(user_id, db_cursor, db_conn, mac, password)
    else:
        print("Authentication failed.")
        choice = input("No account found. Would you like to sign up? (y/n): ").lower()
        if choice == "y":
            signup_user(db_cursor, mac_hashed, pw_hashed)
            db_conn.commit()
            print("Signup complete. Please restart the program.")
        else:
            print("Exiting.")

    db_conn.close()

if __name__ == "__main__":
    main()
