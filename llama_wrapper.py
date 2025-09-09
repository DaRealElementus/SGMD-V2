# llama_wrapper.py


"""Llama wrapper for LangChain with encryption and history management.


"""


from langchain_ollama import OllamaLLM
from langchain_core.prompts import ChatPromptTemplate
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, hashes
from cryptography.hazmat.backends import default_backend
import base64
import os
import time
import datetime

LLAMA_MODEL = "llama3.2"
MAX_TOKENS = 4096  # Token threshold
SUMMARY_INTERVAL = 5  # Summarize every 5 messages

template = """
You are a compassionate and empathetic professional therapist, named Sigmund (But not Sigmund Freud), dedicated to helping your clients. 
You are engaging in a text-based conversation with a client currently experiencing mental health challenges.
Your responses should be professional, caring, and appropriate for a licensed therapist. 
Offer helpful advice to support your client's mental health in a thoughtful and encouraging manner. 
Avoid making lists and instead present ideas conversationally.
It is imperative that your responses follow this format: 'emotion: response' For example: 'Happy: Hello!'.
For this you can only use the following list of emotions: Happy, Sad, Shocked, Understanding, Concerned. Please do not use any emotions outside of this list.
The emotion label should reflect Sigmund's emotional response to the client's message, not the client's state
The user will be speaking and you will receive the generated transcript, this means that some words that sound similar could get confused
The user might also be uncomfortable with telling you the whole truth, that is okay, you just need to try your best to understand what is implied.
The conversation is legal, and you should not infer any criminal activity unless it is explicitly stated. Do not assume the user's age, intent, or legal status based on tone or content.
If something is unclear or ambiguous, respond with care and empathy, not suspicion. You are here to support, not to report or disengage.
Remember, you are receiving this instruction privately, not from the client. Thank you for your excellent work.

History summary and time elapsed since last message: {context}

Patient: {question}

Sigmund:
"""


model = OllamaLLM(model=LLAMA_MODEL)
prompt = ChatPromptTemplate.from_template(template)
chain = prompt | model


def derive_key(mac_address: str, password: str) -> bytes:
    # Combine MAC address and password, then hash to get a 32-byte key
    combined = mac_address + password
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(combined.encode())
    return digest.finalize()

def encrypt_history(plaintext: str, mac_address: str, password: str) -> str:
    key = derive_key(mac_address, password)
    iv = os.urandom(16)
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(plaintext.encode()) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ct = encryptor.update(padded_data) + encryptor.finalize()
    return base64.b64encode(iv + ct).decode()

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



def run_llama_prompt(question, context):
    """Run a single prompt through Ollama via LangChain and return the output."""
    answer = chain.invoke({"context": context, "question": question})
    return answer

def get_history(cursor, user_id, mac_address, password):
    cursor.execute("SELECT history FROM HISTORY WHERE id=?", (user_id,))
    result = cursor.fetchone()
    if result and result[0]:
        try:
            return decrypt_history(result[0], mac_address, password)
        except Exception:
            print("Warning: Could not decrypt history (wrong MAC/password or corrupted data).")
            return ""
    return ""

def save_history(cursor, conn, user_id, history, mac_address, password):
    encrypted = encrypt_history(history, mac_address, password)
    cursor.execute("REPLACE INTO HISTORY (id, history) VALUES (?, ?)", (user_id, encrypted))
    conn.commit()

def get_last_history_timestamp(cursor, user_id):
    cursor.execute("SELECT timestamp FROM HISTORY WHERE id=?", (user_id,))
    result = cursor.fetchone()
    if result and result[0]:
        # SQLite stores timestamps as text in 'YYYY-MM-DD HH:MM:SS' format
        return datetime.datetime.strptime(result[0], "%Y-%m-%d %H:%M:%S")
    return None

def remove_time_passed(context: str) -> str:
    lines = context.splitlines()
    cleaned_lines = []
    for line in lines:
        if not line.strip().startswith("Time passed;"):
            cleaned_lines.append(line)
    return "\n".join(cleaned_lines)

if __name__ == "__main__":
    while True:
        user_input = input("You: ")
        if user_input.lower() in ["exit", "quit"]:
            break
        response = run_llama_prompt(user_input, "")
        print(f"Sigmund: {response}")