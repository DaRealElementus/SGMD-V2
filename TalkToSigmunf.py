import Client
import requests
SERVER = Client.SERVER
import WhisperSTT
import JustTalking
MODEL_SIZE = WhisperSTT.MODEL_SIZE
COMPUTE_TYPE = WhisperSTT.COMPUTE_TYPE
SAMPLERATE = WhisperSTT.SAMPLERATE
CHANNELS = WhisperSTT.CHANNELS
INPUT_DEVICE_INDEX = WhisperSTT.INPUT_DEVICE_INDEX  # Set to your mic device index, or None for default
from pynput import keyboard

def listenAndRespond(user_id, username, password):
    WhisperSTT.print_input_device_info()
    print("Hold SPACE to record. Release to transcribe. (Ctrl+C to exit)")
    recorder = WhisperSTT.Recorder(SAMPLERATE, CHANNELS, INPUT_DEVICE_INDEX)

    def on_press(key):
        if key == keyboard.Key.space and not recorder.recording:
            recorder.start()

    def on_release(key):
        if key == keyboard.Key.space and recorder.recording:
            audio_np = recorder.stop()
            print("Transcribing...")
            text = WhisperSTT.transcribe_audio(audio_np)
            print("You:", text)
            resp = requests.post(f"{SERVER}/chat", json={
                "user_id": user_id,
                "username": username,
                "password": password,
                "message": text
            })
            # Get encrypted response from server
            encrypted_response = resp.json()["response"]
            # Decrypt server response
            response = Client.decrypt_history(encrypted_response, username, password)
            print("Sigmund:", response)
            JustTalking.justTalking(response)
            return False  # Stop listener

    while True:
        print("Waiting for SPACE...")
        with keyboard.Listener(on_press=on_press, on_release=on_release) as listener:
            listener.join()

def main():
    user_id = input("Enter your user ID: ")
    username = input("Enter your username: ")
    password = input("Enter your password: ")  # Get password input
    login_result = Client.login(username, password) # Attempt login via Client module
    if login_result.get("success"):
        user_id = login_result["user_id"]
        listenAndRespond(user_id, username, password)
    else:
        login_result = Client.auto_register_and_login(username, password)
        user_id = login_result["user_id"]
        listenAndRespond(user_id, username, password)