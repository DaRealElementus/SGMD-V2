import dearpygui.dearpygui as dpg
import Client
import requests
SERVER = "http://121.45.50.210:5000/"
def send_message_callback(sender, app_data, user_data):
    message = dpg.get_value("message_input")
    user_id, username, password = user_data
    if message:
        # Safely update chat display
        dpg.add_text(f"You: {message}", parent="chat_display", wrap=480)
        dpg.set_y_scroll("chat_display", -1)
        dpg.set_value("message_input", "")  # Clear input field
        resp = requests.post(f"{SERVER}/chat", json={
            "user_id": user_id,
            "username": username,
            "password": password,
            "message": message
        })
        encrypted_response = resp.json()["response"]
        response = Client.decrypt_history(encrypted_response, username, password)
        dpg.add_text(f"Sigmund: {response}", parent="chat_display", wrap=480)
        dpg.set_y_scroll("chat_display", -1)


def openChat(user_id, username, password):
    # Context must only be created once
    if dpg.does_item_exist("Sigmund Chat Login"):
        dpg.delete_item("Sigmund Chat Login")

    
    with dpg.window(label="Chat Window", tag="main_window", width=500, height=400):
        username, password = Client.normalize_and_hash(username, password)
        with dpg.child_window(tag="chat_display", width=500, height=400, autosize_x=False, autosize_y=False):
            dpg.add_text("Welcome to Sigmund", wrap=480)
        dpg.add_input_text(
            label="Your Message",
            tag="message_input",
            on_enter=True,
            callback=send_message_callback,
            user_data=(user_id, username, password),
            width=500
        )
        dpg.add_button(label="Send", callback=send_message_callback, user_data=(user_id, username, password))

    # Primary window must be an actual window tag, not viewport title
    dpg.set_primary_window("main_window", True)