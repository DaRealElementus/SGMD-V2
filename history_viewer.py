"""
Outdated code, no longer used in the project.
"""\


import sqlite3
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, hashes
from cryptography.hazmat.backends import default_backend
import base64


# for begging the history, outdated code as it is now done in the server env

import uuid

def get_mac_address() -> str:
    """Returns the MAC address of the first network interface as a string."""
    mac = uuid.getnode()
    mac_str = ':'.join(f'{(mac >> i) & 0xff:02x}' for i in range(40, -1, -8))
    return mac_str

def derive_key(mac_address: str, password: str) -> bytes:
    combined = mac_address + password
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(combined.encode())
    return digest.finalize()

def decrypt_history(ciphertext: str, mac_address: str, password: str) -> str:
    key = derive_key(mac_address, password)
    data = base64.b64decode(ciphertext)
    iv = data[:16]
    ct = data[16:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded = decryptor.update(ct) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    return (unpadder.update(padded) + unpadder.finalize()).decode()

def main():
    db_path = "chatbot.db"
    user_id = input("Enter user ID: ").strip()
    mac_address = get_mac_address()
    password = input("Enter password: ").strip()

    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT history FROM HISTORY WHERE id=?", (user_id,))
    result = cursor.fetchone()
    if not result or not result[0]:
        print("No history found for this user.")
        return

    encrypted_history = result[0]
    try:
        history = decrypt_history(encrypted_history, mac_address, password)
        print("\n--- Decrypted History ---\n")
        print(history)
    except Exception as e:
        print("Failed to decrypt history. Wrong MAC/password or corrupted data.")
        print(f"Error: {e}")

    conn.close()

if __name__ == "__main__":
    main()