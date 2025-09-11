# Server URL for chat backend
import dearpygui.dearpygui as dpg
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
recorder = WhisperSTT.Recorder(SAMPLERATE, CHANNELS, INPUT_DEVICE_INDEX)
def on_button_down(sender, app_data, user_data):
    print("Button pressed (down)")
    recorder.start()


def on_button_up(sender, app_data, user_data):
    print("Button released (up)")
    audio_np = recorder.stop()
    print("Transcribing...")
    message = WhisperSTT.transcribe_audio(audio_np)
    user_id, username, password = user_data   # Unpack user credentials
    if message:
        # Display user's message in the chat window
        dpg.add_text(f"You: {message}", parent="chat_display", wrap=480)
        dpg.set_y_scroll("chat_display", -1)  # Scroll to bottom
        dpg.set_value("message_input", "")     # Clear input field

        # Send message to server
        resp = requests.post(f"{SERVER}/chat", json={
            "user_id": user_id,
            "username": username,
            "password": password,
            "message": message
        })
        # Get encrypted response from server
        encrypted_response = resp.json()["response"]
        # Decrypt server response
        response = Client.decrypt_history(encrypted_response, username, password)
        # Display server's response in the chat window
        dpg.add_text(f"Sigmund: {response}", parent="chat_display", wrap=480)
        dpg.set_y_scroll("chat_display", -1)  # Scroll to bottom
    

def send_message_callback(sender, app_data, user_data):
    message = dpg.get_value("message_input")  # Get the message from input field
    user_id, username, password = user_data   # Unpack user credentials
    if message:
        # Display user's message in the chat window
        dpg.add_text(f"You: {message}", parent="chat_display", wrap=480)
        dpg.set_y_scroll("chat_display", -1)  # Scroll to bottom
        dpg.set_value("message_input", "")     # Clear input field

        # Send message to server
        resp = requests.post(f"{SERVER}/chat", json={
            "user_id": user_id,
            "username": username,
            "password": password,
            "message": message
        })
        # Get encrypted response from server
        encrypted_response = resp.json()["response"]
        # Decrypt server response
        response = Client.decrypt_history(encrypted_response, username, password)
        # Display server's response in the chat window
        dpg.add_text(f"Sigmund: {response}", parent="chat_display", wrap=480)
        dpg.set_y_scroll("chat_display", -1)  # Scroll to bottom

def openChat(user_id, username, password):
    # Remove login window if it exists
    if dpg.does_item_exist("Sigmund Chat Login"):
        dpg.delete_item("Sigmund Chat Login")

    # Create main chat window
    with dpg.window(label="Chat Window", tag="main_window", width=500, height=400):
        # Normalize and hash credentials for security
        username, password = Client.normalize_and_hash(username, password)
        # Create chat display area
        with dpg.child_window(tag="chat_display", width=500, height=400, autosize_x=False, autosize_y=False):
            dpg.add_text("Welcome to Sigmund", wrap=480)
        # Input field for user's message
        dpg.add_input_text(
            label="Your Message",
            tag="message_input",
            on_enter=True,  # Send message on Enter key
            callback=send_message_callback,
            user_data=(user_id, username, password),
            width=500
        )
        # Send button
        with dpg.group(horizontal=True):  # Button group
            dpg.add_button(label="Send", callback=send_message_callback, user_data=(user_id, username, password))
            dpg.add_button(label="Voice", tag="hold_btn")

        with dpg.item_handler_registry(tag="hold_btn_handlers") as handler:
            dpg.add_item_clicked_handler(callback=on_button_down, user_data=(user_id, username, password))
            dpg.add_item_deactivated_handler(callback=on_button_up, user_data=(user_id, username, password))


        dpg.bind_item_handler_registry("hold_btn", "hold_btn_handlers")
    dpg.set_primary_window("main_window", True)
        # Set the main chat window as the primary window
