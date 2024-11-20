from tkinter import Frame, Label, Entry, Checkbutton, Button, BooleanVar, Scale, HORIZONTAL, Toplevel
import configparser
import os
from tkinter.messagebox import showwarning

SETTINGS_FILE_PATH = '/etc/TitanLock/settings.conf'

# Function to create settings tab (frame)
def create_settings_frame(dark_mode_var, save_settings_callback, auto_lock_timeout):
    settings_frame = Frame()
    settings_frame.pack(fill='both', expand=True)

    settings_label = Label(settings_frame, text="Settings", font=("TkDefaultFont", 12, "bold"))
    settings_label.pack(pady=10)

    # Enable dark mode checkbox, bound to the `dark_mode_var`
    dark_mode_check = Checkbutton(settings_frame, text="Enable Dark Mode", variable=dark_mode_var)
    dark_mode_check.pack(pady=5)
    
    # Auto-Lock Timeout Slider
    auto_lock_label = Label(settings_frame, text="Auto-Lock Timeout (seconds)")
    auto_lock_label.pack()
    auto_lock_scale = Scale(settings_frame, from_=5, to=600, orient=HORIZONTAL)
    auto_lock_scale.set(auto_lock_timeout)
    auto_lock_scale.pack()

    master_password_label = Label(settings_frame, text="Set Master Password:")
    master_password_label.pack(pady=5)
    master_password_entry = Entry(settings_frame, show="*")
    master_password_entry.pack(pady=5)

    # Save settings when button is clicked
    save_button = Button(settings_frame, text="Save Settings", command=lambda: save_settings_callback(
        dark_mode_var.get(),    
        auto_lock_scale.get()
    ))
    save_button.pack()

    return settings_frame

# Load settings function
def load_settings():
    """Load settings from the configuration file, or set default values if file doesn't exist."""
    config = configparser.ConfigParser()
    if os.path.exists(SETTINGS_FILE_PATH):
        config.read(SETTINGS_FILE_PATH)
        dark_mode = config.getboolean('Display', 'dark_mode', fallback=False)
        auto_lock_timeout = config.getint('Security', 'auto_lock_timeout', fallback=300)  # Default to 5 minutes (300 seconds)
    else:
        dark_mode = False  # Default value if no config file exists
        auto_lock_timeout = 300

    return {'dark_mode': dark_mode, 'auto_lock_timeout': auto_lock_timeout}

# Save settings function
def save_settings(dark_mode, auto_lock_timeout):
    """Save settings to the configuration file."""
    config = configparser.ConfigParser()
    config['Display'] = {'dark_mode': str(dark_mode)}
    config['Security'] = {'auto_lock_timeout': str(auto_lock_timeout)}

    os.makedirs(os.path.dirname(SETTINGS_FILE_PATH), exist_ok=True)

    with open(SETTINGS_FILE_PATH, 'w') as configfile:
        config.write(configfile)
    print("Settings saved.")

# Additional utility functions
def create_titanlock_folder():
    folder_path = '/etc/TitanLock'
    try:
        if not os.path.exists(folder_path):
            os.makedirs(folder_path)
        else:
            return 0
    except PermissionError:
        print("Permission denied: You need to run this script as root (use 'sudo').")
    except Exception as e:
        print(f"An error occurred while creating the folder: {e}")

def validate_master_key(entered_master_key, master_key_window, verify_password):
    master_key_path = '/etc/TitanLock/masterkey.txt'
    try:
        with open(master_key_path, 'r') as master_key_file:
            stored_master_key_hash = master_key_file.read()
        if verify_password(stored_master_key_hash, entered_master_key):
            print("Master key validated.")
            return True
        else:
            showwarning("Invalid Master Key", "The entered master key is incorrect.")
            return False
    except Exception as e:
        print(f"An error occurred while validating the master key: {e}")
        return False

def open_master_key_window(root, validate_master_key_callback):
    master_key_window = Toplevel(root)
    master_key_window.title("Titan Lock")
    master_key_window.geometry("800x500")

    # Label to prompt for the master key
    master_key_label = Label(master_key_window, text="Enter Master Key:")
    master_key_label.pack(pady=10)

    master_key_entry = Entry(master_key_window, show="*")
    master_key_entry.pack(pady=10)

    # Introductory paragraph for master password guidance
    suggestions_paragraph = Label(master_key_window, text=(
        "Consider the following suggestions for creating a secure master password, based on NIST SP 800-63B standards "
        "for memorized secrets. These guidelines help ensure your password is strong and secure:"
    ), wraplength=500, justify="left")
    suggestions_paragraph.pack(pady=(10, 10), padx=20) # Added spacing after paragraph

    # Updated list of suggestions for a secure master password
    list_items = [
        "Use at least 12 characters (16+ is recommended for stronger security)",
        "Consider using a passphrase of random, unrelated words for memorability",
        "Avoid common words, predictable sequences, or personal information",
        "Ensure uniqueness – do not reuse a password used on other accounts",
        "Avoid patterns like '1234' or repetitive characters (e.g., 'aaaa')"
    ]

    # Add each suggestion as a labeled bullet point with indentation
    for item in list_items:
        list_item_label = Label(master_key_window, text=f"• {item}", anchor="w", justify="left", fg="black", wraplength=500)
        list_item_label.pack(anchor="w", padx=165, pady=2) # Increased padding for indentation and spacing between items
    
    # Submit button triggers master key validation without starting the timer
    submit_button = Button(
        master_key_window,
        text="Submit",
        command=lambda: validate_master_key_callback(master_key_entry.get(), master_key_window)
    )
    submit_button.pack(pady=10)