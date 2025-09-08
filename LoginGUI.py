import dearpygui.dearpygui as dpg  # Import DearPyGui for GUI creation
import Client                      # Import custom Client module for authentication
import ChatGUI                     # Import custom ChatGUI module for chat window
import os                          # Import os for file path operations

dpg.create_context()  # Initialize DearPyGui context

# Get the directory of the current script
script_dir = os.path.dirname(os.path.abspath(__file__))
# Set the path to the font file
font_path = os.path.join(script_dir, "Arial.ttf")

# Register fonts to be used in the GUI
with dpg.font_registry():
    default_font = dpg.add_font(font_path, 16) # 16px font for general use
    big_font = dpg.add_font(font_path, 24)     # 24px font for larger text
    title_font = dpg.add_font(font_path, 48)   # 48px font for the title

# Callback for login button
def loginUser(sender, app_data, user_data):
    username = dpg.get_value("Username_input")      # Get username input
    password = dpg.get_value("Password_input")      # Get password input
    login_result = Client.login(username, password) # Attempt login via Client module
    if login_result.get("success"):
        user_id = login_result["user_id"]
        ChatGUI.openChat(user_id, username, password)  # Open chat window on success
    else:
        dpg.set_value("Status", "Try login again")     # Show error message

# Callback for register button
def registerUser(sender, app_data, user_data):
    username = dpg.get_value("Username_input")              # Get username input
    password = dpg.get_value("Password_input")              # Get password input
    login_result = Client.auto_register_and_login(username, password) # Attempt registration and login
    if login_result.get("success"):
        user_id = login_result["user_id"]
        ChatGUI.openChat(user_id, username, password)       # Open chat window on success
    else:
        dpg.set_value("Status", "Try register again")       # Show error message

# Create the main login window
with dpg.window(tag="Sigmund Chat Login"):
    with dpg.child_window(width=-1, height=-1):  # Child window fills parent
        dpg.add_spacer(height=120)  # Add vertical space at the top

        # Create a 3-column table for layout (left spacer | content | right spacer)
        with dpg.table(header_row=False, resizable=False, policy=dpg.mvTable_SizingStretchProp):
            dpg.add_table_column(init_width_or_weight=1)
            dpg.add_table_column(init_width_or_weight=1)
            dpg.add_table_column(init_width_or_weight=1)

            with dpg.table_row():
                dpg.add_spacer()  # Left spacer
                with dpg.group(horizontal=False):  # Main content group
                    dpg.add_spacer(height=40)   # Push content down
                    dpg.add_text("Sigmund Chat Login", bullet=False, tag="title")  # Title
                    dpg.add_input_text(width=410, tag="Username_input")            # Username input
                    dpg.add_input_text(width=410, tag="Password_input", password=True) # Password input
                    with dpg.group(horizontal=True):  # Button group
                        dpg.add_button(label="Login", callback=loginUser, width=200, tag='enter')      # Login button
                        dpg.add_button(label="Register", callback=registerUser, width=200, tag='register') # Register button

                    dpg.add_text("", tag="Status")   # Status text for feedback

                    dpg.add_spacer(height=20)   # Bottom padding
                dpg.add_spacer()  # Right spacer

# Bind fonts to specific items
dpg.bind_item_font("title", title_font)
dpg.bind_item_font("enter", default_font)
dpg.bind_item_font("register", default_font)

# Create and configure the main application viewport
dpg.create_viewport(title='Sigmund Chat Login', width=600, height=300)
dpg.setup_dearpygui()
dpg.maximize_viewport()  # Make the viewport full screen 
dpg.show_viewport()
dpg.set_primary_window("Sigmund Chat Login", True)

# Center the window in the viewport
viewport_width, viewport_height = dpg.get_viewport_width(), dpg.get_viewport_height()
window_width, window_height = 600, 300
dpg.set_item_pos("Sigmund Chat Login", [(viewport_width - window_width)//2, (viewport_height - window_height)//2])

dpg.start_dearpygui()   # Start the DearPyGui event loop
dpg.destroy_context()   # Clean up DearPyGui context after closing
