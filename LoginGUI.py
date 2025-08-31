import dearpygui.dearpygui as dpg
import Client
import ChatGUI
import os
dpg.create_context()
script_dir = os.path.dirname(os.path.abspath(__file__))
font_path = os.path.join(script_dir, "Arial.ttf")
with dpg.font_registry():
    default_font = dpg.add_font(font_path, 16) #16px
    big_font = dpg.add_font(font_path, 24) #24px
    title_font = dpg.add_font(font_path, 48) # 48px

def loginUser(sender, app_data, user_data):
    username = dpg.get_value("Username_input")
    password = dpg.get_value("Password_input")
    login_result = Client.login(username, password)
    if login_result.get("success"):
        user_id = login_result["user_id"]
        ChatGUI.openChat(user_id, username, password)

    else:
        dpg.set_value("Status", "Try login again")
def registerUser(sender, app_data, user_data):
    username = dpg.get_value("Username_input")
    password = dpg.get_value("Password_input")
    login_result = Client.auto_register_and_login(username, password)
    if login_result.get("success"):
        user_id = login_result["user_id"]
        ChatGUI.openChat(user_id, username, password)
    else:
        dpg.set_value("Status", "Try register again")
with dpg.window(tag="Sigmund Chat Login"):

    with dpg.child_window(width=-1, height=-1):  # fills parent
        dpg.add_spacer(height=120)  # vertical push down
    # 3-column table (left spacer | content | right spacer)
        with dpg.table(header_row=False, resizable=False, policy=dpg.mvTable_SizingStretchProp):
            dpg.add_table_column(init_width_or_weight=1)
            dpg.add_table_column(init_width_or_weight=1)
            dpg.add_table_column(init_width_or_weight=1)

            with dpg.table_row():
                dpg.add_spacer()
                with dpg.group(horizontal=False):
                    dpg.add_spacer(height=40)   # push everything down a bit

                    dpg.add_text("Sigmund Chat Login", bullet=False, tag="title")
                    dpg.add_input_text(width=400, tag="Username_input")
                    dpg.add_input_text(width=400, tag="Password_input", password=True)
                    with dpg.group(horizontal=True):
                        dpg.add_button(label="Enter", callback=loginUser, width=200, tag='enter')
                        dpg.add_button(label="Register", callback=registerUser, width=200, tag='register')

                    dpg.add_text("", tag="Status")   # for feedback messages

                    dpg.add_spacer(height=20)   # bottom padding
                dpg.add_spacer()

dpg.bind_item_font("title", title_font)
dpg.bind_item_font("enter", default_font)
dpg.bind_item_font("register", default_font)

# Center the window in viewport
dpg.create_viewport(title='Sigmund Chat Login', width=600, height=300)
dpg.setup_dearpygui()
dpg.show_viewport()
dpg.set_primary_window("Sigmund Chat Login", True)

# Move window to center of viewport
viewport_width, viewport_height = dpg.get_viewport_width(), dpg.get_viewport_height()
window_width, window_height = 600, 300
dpg.set_item_pos("Sigmund Chat Login", [(viewport_width - window_width)//2, (viewport_height - window_height)//2])

dpg.start_dearpygui()
dpg.destroy_context()