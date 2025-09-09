import dearpygui.dearpygui as dpg  # Import DearPyGui for GUI creation
import Client                      # Import custom Client module for encryption/decryption
import requests                    # Import requests for HTTP communication

SERVER = Client.SERVER  # Server URL for chat backend

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
            dpg.add_button(label="Voice")

    # Set the main chat window as the primary window
    dpg.set_primary_window("main_window", True)
