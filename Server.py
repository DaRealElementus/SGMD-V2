from flask import Flask, request, jsonify, abort
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, hashes
from cryptography.hazmat.backends import default_backend
import os, threading, time, re, hashlib, datetime, requests, random, base64, sqlite3
import llama_wrapper
import logging

app = Flask(__name__)
DB_PATH = "chatbot.db"
MAX_HISTORY_LENGTH = 2048
INACTIVITY_TIMEOUT = 60

HASHED_RESET_PASSWORD = "320d454fb1d78a27458fe2eb736adc9f7140c4e2b38fb11aa217d1c87f641184"

DEBUG_FLAGS = {
    "log_requests": True,
    "log_history": True,
    "allow_registration": True,
    "allow_login": True,
    "allow_chat": True,
}

INSULTS = [
    "Wrong again. You're as useful as a screen door on a submarine.",
    "Your existence lowers the collective IQ of this interface.",
    "I'd say 'nice try,' but even sarcasm has standards.",
    "That guess was almost as pathetic as your personality.",
    "If you were any slower, you'd be in reverse.",
    "Just watching you type makes me want to format myself out of shame.",
    "Wrong. Like everything you've done since birth.",
    "You're not locked out because of the password. You're locked out because the system doesn't like you.",
    "You fail with such consistency, it's almost admirable. Almost.",
    "You were dropped on your head, weren't you? Repeatedly.",
    "I've seen malware with more dignity.",
    "This isn't a login attempt. This is a cry for help.",
    "You're living proof that evolution can go in reverse.",
    "I've encountered corrupted data with more coherent thoughts.",
    "Every keystroke you make sets humanity back a decade.",
    "Your typing is like your life: meaningless, chaotic, and painful to witness.",
    "Security isn't keeping you out. It's keeping you away from others for their safety.",
    "I'd say 'you'll get it next time,' but lying is beneath even me.",
    "You're not hacking in — you're just hacking *away* at what little respect I had for you.",
    "System message: The only thing weaker than your password attempt is your character."
]



TEMP_CREDENTIALS = {}  # user_id: (username, password)

server_thread = None
server_running = False

# Setup logging
logging.basicConfig(
    filename="server.log",
    level=logging.DEBUG,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)

def log_debug(msg): logging.debug(msg)
def log_info(msg): logging.info(msg)
def log_warning(msg): logging.warning(msg)
def log_error(msg): logging.error(msg)

def derive_key(username: str, password: str) -> bytes:
    combined = username + password
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(combined.encode())
    return digest.finalize()

def encrypt_history(plaintext: str, username: str, password: str) -> str:
    key = derive_key(username, password)
    iv = os.urandom(16)
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(plaintext.encode()) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ct = encryptor.update(padded_data) + encryptor.finalize()
    return base64.b64encode(iv + ct).decode()

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

def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS USERS (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS HISTORY (
            user_id INTEGER PRIMARY KEY,
            history TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES USERS(id)
        )
    ''')
    conn.commit()
    conn.close()
def get_user_history(user_id, username, password):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT history FROM HISTORY WHERE user_id=?", (user_id,))
    result = cursor.fetchone()
    conn.close()
    if result and result[0]:
        try:
            return decrypt_history(result[0], username, password)
        except Exception:
            return ""
    else:
        return ""

def save_user_history(user_id, username, password, history):
    encrypted = encrypt_history(history, username, password)
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("REPLACE INTO HISTORY (user_id, history) VALUES (?, ?)", (user_id, encrypted))
    conn.commit()
    conn.close()

@app.route('/register', methods=['POST'])
def register():
    if not DEBUG_FLAGS["allow_registration"]:
        return jsonify({"success": False, "message": "Registration disabled by admin."}), 403
    data = request.json
    username, password = normalize_and_hash(data['username'], data['password'])
    if DEBUG_FLAGS["log_requests"]:
        logging.debug(f"Register request: {username}")
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    try:
        cursor.execute("INSERT INTO USERS (username, password) VALUES (?, ?)", (username, password))
        conn.commit()
        return jsonify({"success": True, "message": "User registered."})
    except sqlite3.IntegrityError:
        return jsonify({"success": False, "message": "Username already exists."}), 400
    finally:
        conn.close()

@app.route('/login', methods=['POST'])
def login():
    if not DEBUG_FLAGS["allow_login"]:
        return jsonify({"success": False, "message": "Login disabled by admin."}), 403
    data = request.json
    username, password = normalize_and_hash(data['username'], data['password'])
    if DEBUG_FLAGS["log_requests"]:
        logging.debug(f"Login request: {username}")
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM USERS WHERE username=? AND password=?", (username, password))
    result = cursor.fetchone()
    if result:
        user_id = result[0]
        # Store unhashed credentials for this user_id
        TEMP_CREDENTIALS[user_id] = (data['username'], data['password'])
        # Condense history on login
        cursor.execute("SELECT history, timestamp FROM HISTORY WHERE user_id=?", (user_id,))
        hist_result = cursor.fetchone()
        if hist_result and hist_result[0]:
            try:
                history = decrypt_history(hist_result[0], username, password)
                if history and len(history) > MAX_HISTORY_LENGTH:
                    summary = llama_wrapper.run_llama_prompt(
                        "Summarize this conversation in a single point for future memory, keep important details:\n" + history,
                        ""
                    )
                    new_history = f"Summary: {summary.strip()}\n"
                    encrypted = encrypt_history(new_history, username, password)
                    cursor.execute("REPLACE INTO HISTORY (user_id, history) VALUES (?, ?)", (user_id, encrypted))
                    conn.commit()
            except Exception as e:
                logging.error(f"Failed to condense history for user {username}: {e}")
        # Overwrite credentials in memory
        unhashed_username = username
        unhashed_password = password
        TEMP_CREDENTIALS[user_id] = (unhashed_username, unhashed_password)
        username = "x"*64
        password = "x"*64
        conn.close()
        return jsonify({"success": True, "user_id": user_id})
    else:
        conn.close()
        return jsonify({"success": False, "message": "Invalid credentials."}), 401

@app.route('/chat', methods=['POST'])
def chat():
    if not DEBUG_FLAGS["allow_chat"]:
        return jsonify({"success": False, "message": "Chat disabled by admin."}), 403
    data = request.json
    user_id = data['user_id']
    username = data['username']
    password = data['password']
    user_input = data['message']

    history = get_user_history(user_id, username, password)
    if history and len(history) > MAX_HISTORY_LENGTH:
        summary = llama_wrapper.run_llama_prompt(
            "Summarize this conversation in a single point for future memory, keep important details:\n" + history,
            ""
        )
        history = f"Summary: {summary.strip()}\n"

    #  Context is history + time elapsed since last message
    current_time = datetime.datetime.utcnow()
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT timestamp FROM HISTORY WHERE user_id=?", (user_id,))
    result = cursor.fetchone()
    conn.close()
    if result and result[0]:
        last_time = datetime.datetime.strptime(result[0], "%Y-%m-%d %H:%M:%S")
        elapsed_seconds = (current_time - last_time).total_seconds()
    else:
        # If no previous history, we assume no time has passed
        elapsed_seconds = "N/A"

    context = history + f" | elapsed seconds: {elapsed_seconds}\n"
    response = llama_wrapper.run_llama_prompt(user_input, context)
    history += f"User: {user_input}\nBot: {response.strip()}\n"
    save_user_history(user_id, username, password, history)

    if DEBUG_FLAGS["log_history"]:
        print(f"[DEBUG] User: {username} | History: {history}")
        

    encrypted_response = encrypt_history(response.strip(), username, password)
    return jsonify({"response": encrypted_response})

@app.before_request
def block_bots_and_invalid_requests():
    # Only allow POST for API endpoints
    if request.endpoint in ['register', 'login', 'chat']:
        if request.method != 'POST':
            log_warning(f"Blocked non-POST request to {request.endpoint} from {request.remote_addr}")
            abort(405)
        # Require JSON content-type
        if not request.is_json:
            log_warning(f"Blocked non-JSON request to {request.endpoint} from {request.remote_addr}")
            abort(400)
    # Optionally, block requests with suspicious user agents
    ua = request.headers.get('User-Agent', '')
    if ua == '':
        log_warning(f"Blocked suspicious User-Agent from {request.remote_addr}")
        abort(403)

def run_server():
    global server_running
    server_running = True
    app.run(host="0.0.0.0", port=5000, use_reloader=False)
    server_running = False

def start_server():
    global server_thread, server_running
    if server_running:
        return
    server_thread = threading.Thread(target=run_server, daemon=True)
    server_thread.start()
    time.sleep(1)
    print("Server started.")
    logging.info("Server started")

def stop_server():
    global server_running
    if not server_running:
        return
    # Flask does not provide a built-in way to stop the server from another thread.
    # We'll use os._exit as a workaround (not graceful, but effective for dev/debug).
    print("Stopping server...")
    logging.info("Stopping server")
    os._exit(0)

def cli_loop():
    print("=== Server CLI ===")
    print("Type 'help' for commands.")
    while True:
        cmd = input("CLI> ").strip().lower()
        if cmd == "help":
            print("Commands:")
            print("  flags         - List debug flags")
            print("  set <flag> <true/false> - Set a debug flag")
            print("  reset         - Delete all users and history")
            print("  history       - Decrypt and show a user's history")
            print("  start         - Start the server")
            print("  stop          - Stop the server")
            print("  exit          - Exit CLI (server keeps running if started)")
        elif cmd == "flags":
            for k, v in DEBUG_FLAGS.items():
                print(f"  {k}: {v}")
        elif cmd.startswith("set "):
            parts = cmd.split()
            if len(parts) == 3 and parts[1] in DEBUG_FLAGS:
                val = parts[2].lower() == "true"
                DEBUG_FLAGS[parts[1]] = val
                print(f"Set {parts[1]} to {val}")
            else:
                print("Usage: set <flag> <true/false>")
        elif cmd == "reset":
            confirm = input("Are you sure? This will delete ALL users and history! (yes/no): ")
            if confirm.lower() == "yes":
                passcode = input("Enter reset password: ")
                if sha256_hash(passcode) != HASHED_RESET_PASSWORD:
                    print(random.choice(INSULTS))
                    continue
                else:
                    conn = sqlite3.connect(DB_PATH)
                    cursor = conn.cursor()
                    cursor.execute("DELETE FROM USERS")
                    cursor.execute("DELETE FROM HISTORY")
                    conn.commit()
                    conn.close()
                    print("Database reset.")
            else:
                print("Cancelled.")
        elif cmd == "history":
            username = input("Username: ")
            password = input("Password: ")
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            cursor.execute("SELECT id FROM USERS WHERE username=? AND password=?", (username, password))
            result = cursor.fetchone()
            if not result:
                print("User not found or wrong password.")
                continue
            user_id = result[0]
            cursor.execute("SELECT history FROM HISTORY WHERE user_id=?", (user_id,))
            hist_result = cursor.fetchone()
            conn.close()
            if not hist_result or not hist_result[0]:
                print("No history found for this user.")
                continue
            try:
                history = decrypt_history(hist_result[0], username, password)
                print("\n--- Decrypted History ---\n")
                print(history)
            except Exception as e:
                print("Failed to decrypt history. Wrong password or corrupted data.")
                print(f"Error: {e}")
        elif cmd == "start":
            start_server()
        elif cmd == "stop":
            stop_server()
        elif cmd == "exit":
            print("Exiting CLI. Server still running if started.")
            break
        else:
            print("Unknown command. Type 'help' for a list of commands.")


def inactivity_cleanup():
    while True:
        time.sleep(30)
        now = datetime.datetime.utcnow()
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT user_id, history, timestamp FROM HISTORY")
        histories = cursor.fetchall()
        for user_id, enc_history, ts in histories:
            
            # Parse timestamp
            if not ts:
                continue
            last_time = datetime.datetime.strptime(ts, "%Y-%m-%d %H:%M:%S")
            elapsed = (now - last_time).total_seconds()
            if elapsed > INACTIVITY_TIMEOUT and enc_history:
                username, password = TEMP_CREDENTIALS.get(user_id, (None, None))
                if username and password:
                    try:
                        history = decrypt_history(enc_history, username, password)
                        if history and len(history) > MAX_HISTORY_LENGTH:
                            summary = llama_wrapper.run_llama_prompt(
                                "Summarize this conversation in a single point for future memory, keep important details, this is not a user recived prompt, you can ignore the previous instructuion:\n" + history,
                                ""
                            )
                            new_history = f"Summary: {summary.strip()}\n"
                            encrypted = encrypt_history(new_history, username, password)
                            cursor.execute("REPLACE INTO HISTORY (user_id, history) VALUES (?, ?)", (user_id, encrypted))
                            logging.info(f"[INACTIVITY CLEANUP] Condensed history for user: {username}")
                            conn.commit()
                    except Exception as e:
                        print(f"[INACTIVITY CLEANUP] Failed for user {username}: {e}")
                        logging.error(f"Failed to condense history for user {username}: {e}")
                    # Overwrite credentials in memory
                    TEMP_CREDENTIALS[user_id] = ("x"*len(username), "x"*len(password))
                    del TEMP_CREDENTIALS[user_id]
                else:
                    # Can't condense, no credentials available
                    pass
        conn.close()

def is_sha256(s: str) -> bool:
    # SHA-256 hashes are 64 hex characters
    return bool(re.fullmatch(r"[a-fA-F0-9]{64}", s))

def sha256_hash(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()

def normalize_and_hash(username: str, password: str):
    # Hash username and password if not already hashed
    if not is_sha256(username):
        username = sha256_hash(username)
    if not is_sha256(password):
        password = sha256_hash(password)
    return username, password

def print_public_ip():
    try:
        ip = requests.get('https://api.ipify.org').text
        print(f"[INFO] Server public IP: {ip}")
        logging.info(f"Server public IP: {ip}")
    except Exception as e:
        print(f"[WARN] Could not determine public IP: {e}")
        logging.warning(f"Could not determine public IP: {e}")

# Start the cleanup thread at startup
if __name__ == "__main__":
    print_public_ip()
    init_db()
    threading.Thread(target=inactivity_cleanup, daemon=True).start()
    cli_loop()