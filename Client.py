import requests
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import base64
import hashlib
import re

SERVER = "http://127.0.0.1:5000"  # Change to your server's IP if needed

def is_sha256(s: str) -> bool:
    return bool(re.fullmatch(r"[a-fA-F0-9]{64}", s))

def sha256_hash(value: str) -> bytes:
    return hashlib.sha256(value.encode()).digest()

def normalize_and_hash(username: str, password: str):
    if not is_sha256(username):
        username = sha256_hash(username)
    if not is_sha256(password):
        password = sha256_hash(password)
    return username.hex(), password.hex()

def register(username, password):
    username, password = normalize_and_hash(username, password)
    resp = requests.post(f"{SERVER}/register", json={
        "username": username,
        "password": password
        })
    return resp.json()

def login(username, password):
    username, password = normalize_and_hash(username, password)
    resp = requests.post(f"{SERVER}/login", json={
        "username": username,
        "password": password
        })
    return resp.json()

def derive_key(username: str, password: str) -> bytes:
    combined = username + password
    return sha256_hash(combined)

def decrypt_history(ciphertext: str, username: str, password: str) -> str:
    key = derive_key(username, password)
    data = base64.b64decode(ciphertext)
    iv = data[:16]
    ct = data[16:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded = decryptor.update(ct) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    return (unpadder.update(padded) + unpadder.finalize()).decode()

def auto_register_and_login(username, password):
    reg_result = register(username, password)
    if reg_result.get("success"):
        print("User registered.")
        return login(username, password)
    elif "already exists" in reg_result.get("message", ""):
        print("User already exists, logging in...")
        return login(username, password)
    else:
        print("Registration failed:", reg_result.get("message", "Unknown error"))
        return {"success": False}

def main():
    print("=== CLT Chat Client ===")
    username = input("Username: ")
    password = input("Password: ")

    login_result = auto_register_and_login(username, password)
    if not login_result.get("success"):
        print(login_result.get("message", "Login failed."))
        return

    # Hash username and password for all further requests
    username, password = normalize_and_hash(username, password)

    user_id = login_result["user_id"]
    print("Login successful.")

    print("Type 'exit' to quit.")
    while True:
        user_input = input("You: ")
        if user_input.lower() == ("exit" or "quit"):
            break
        resp = requests.post(f"{SERVER}/chat", json={
            "user_id": user_id,
            "username": username,
            "password": password,
            "message": user_input
        })
        encrypted_response = resp.json()["response"]
        response = decrypt_history(encrypted_response, username, password)
        print(f"Bot: {response}")

if __name__ == "__main__":
    main()