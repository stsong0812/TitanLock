import customtkinter as ctk
import configparser
import os
from tkinter.messagebox import showwarning

SETTINGS_FILE_PATH = '/etc/TitanLock/settings.conf'


# Function to create settings tab (frame)
def create_settings_frame(master, dark_mode_var, save_settings_callback, auto_lock_timeout, toggle_dark_mode_callback):
    settings_frame = ctk.CTkFrame(master)
    settings_frame.pack(fill="both", expand=True, padx=20, pady=20)

    # Configure grid weights to center content
    settings_frame.grid_rowconfigure(0, weight=1)  # Spacer above content
    settings_frame.grid_rowconfigure(1, weight=0)  # Title
    settings_frame.grid_rowconfigure(2, weight=0)  # Dark mode switch
    settings_frame.grid_rowconfigure(3, weight=0)  # Auto-lock slider
    settings_frame.grid_rowconfigure(4, weight=0)  # Reset button
    settings_frame.grid_rowconfigure(5, weight=0)  # Save button
    settings_frame.grid_rowconfigure(6, weight=1)  # Spacer below content
    settings_frame.grid_columnconfigure(0, weight=1)
    settings_frame.grid_columnconfigure(1, weight=0)  # For slider width
    settings_frame.grid_columnconfigure(2, weight=0)  # For number label
    settings_frame.grid_columnconfigure(3, weight=1)

    # Title Label
    settings_label = ctk.CTkLabel(settings_frame, text="Settings", font=ctk.CTkFont(size=16, weight="bold"))
    settings_label.grid(row=1, column=0, columnspan=4, pady=10, sticky="n")

    # Enable Dark Mode Toggle
    dark_mode_switch = ctk.CTkSwitch(
        settings_frame,
        text="Enable Dark Mode",
        variable=dark_mode_var,
        onvalue=True,
        offvalue=False,
        command=lambda: toggle_dark_mode_callback(dark_mode_var.get())
    )
    dark_mode_switch.grid(row=2, column=0, columnspan=4, pady=10, sticky="n")

    # Auto-Lock Timeout Label
    auto_lock_label = ctk.CTkLabel(settings_frame, text="Auto-Lock Timeout (minutes):")
    auto_lock_label.grid(row=3, column=0, padx=10, pady=(5, 0), sticky="e")

    # Auto-Lock Timeout Slider
    timeout_value_var = ctk.StringVar(value=f"{int(auto_lock_timeout / 60)}")  # Convert seconds to minutes
    auto_lock_scale = ctk.CTkSlider(
        settings_frame,
        from_=1,
        to=10,  # Slider range: 1 to 10 minutes
        number_of_steps=9,  # Allows selection of whole minutes
        command=lambda value: timeout_value_var.set(f"{int(value)}"),  # Update displayed value
        width=200  # Adjusted width for better spacing
    )
    auto_lock_scale.set(auto_lock_timeout / 60)  # Initialize slider value in minutes
    auto_lock_scale.grid(row=3, column=1, columnspan=2, padx=10, pady=(5, 0), sticky="w")

    # Display the current value of the slider next to it
    timeout_display_label = ctk.CTkLabel(settings_frame, textvariable=timeout_value_var)
    timeout_display_label.grid(row=3, column=3, padx=5, pady=(5, 0), sticky="w")  # Close to the slider

    # Reset Settings Button
    reset_button = ctk.CTkButton(
        settings_frame,
        text="Reset to Defaults",
        command=lambda: reset_settings(dark_mode_var, auto_lock_scale, timeout_value_var, toggle_dark_mode_callback)
    )
    reset_button.grid(row=4, column=0, columnspan=4, pady=10, sticky="n")

    # Save Settings Button
    save_button = ctk.CTkButton(
        settings_frame,
        text="Save Settings",
        command=lambda: save_settings_callback(
            dark_mode_var.get(),
            int(auto_lock_scale.get()) * 60  # Convert minutes back to seconds for saving
        )
    )
    save_button.grid(row=5, column=0, columnspan=4, pady=20, sticky="n")

    return settings_frame

# Reset settings to default values
def reset_settings(dark_mode_var, auto_lock_scale, timeout_value_var, toggle_dark_mode_callback):
    """Reset settings to their default values."""
    # Reset Dark Mode to Default
    dark_mode_var.set(False)  # Default dark mode is off
    toggle_dark_mode_callback(dark_mode_var.get())  # Trigger the callback to apply light mode

    # Reset Auto-Lock Timeout to Default
    auto_lock_scale.set(5)  # Default auto-lock timeout is 5 minutes
    timeout_value_var.set("5")

    print("Settings reset to defaults.")

# Load settings function
def load_settings():
    """Load settings from the configuration file, or set default values if file doesn't exist."""
    config = configparser.ConfigParser()
    if os.path.exists(SETTINGS_FILE_PATH):
        config.read(SETTINGS_FILE_PATH)
        dark_mode = config.getboolean('Display', 'dark_mode', fallback=False)
        try:
            auto_lock_timeout = config.getint('Security', 'auto_lock_timeout', fallback=300)
        except ValueError:
            auto_lock_timeout = 300  # Fallback to default if the value is invalid
    else:
        dark_mode = False  # Default value if no config file exists
        auto_lock_timeout = 300

    return {'dark_mode': dark_mode, 'auto_lock_timeout': auto_lock_timeout}


# Save settings function
def save_settings(dark_mode, auto_lock_timeout):
    """Save settings to the configuration file."""
    config = configparser.ConfigParser()
    config['Display'] = {'dark_mode': str(dark_mode)}
    config['Security'] = {'auto_lock_timeout': str(auto_lock_timeout)}  # Save in seconds

    os.makedirs(os.path.dirname(SETTINGS_FILE_PATH), exist_ok=True)

    with open(SETTINGS_FILE_PATH, 'w') as configfile:
        config.write(configfile)
    print("Settings saved.")


# Additional utility functions
def create_titanlock_folder():
    """Create the folder for TitanLock configurations if it doesn't exist."""
    folder_path = '/etc/TitanLock'
    try:
        if not os.path.exists(folder_path):
            os.makedirs(folder_path)
            print("TitanLock folder created.")
        else:
            print("TitanLock folder already exists.")
    except PermissionError:
        print("Permission denied: You need to run this script as root (use 'sudo').")
    except Exception as e:
        print(f"An error occurred while creating the folder: {e}")


def validate_master_key(entered_master_key, master_key_window, verify_password):
    """Validate the master key entered by the user."""
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
    """Open a window for entering the master key."""
    master_key_window = ctk.CTkToplevel(root)
    master_key_window.title("Enter Master Key")
    master_key_window.geometry("500x400")

    # Title Label
    title_label = ctk.CTkLabel(
        master_key_window,
        text="Enter Master Key",
        font=ctk.CTkFont(size=18, weight="bold")
    )
    title_label.pack(pady=10)

    # Entry for master key
    master_key_entry = ctk.CTkEntry(master_key_window, placeholder_text="Master Key", show="*")
    master_key_entry.pack(pady=10)

    # Suggestions for secure passwords
    suggestions_text = (
        "Suggestions for a secure master password:\n\n"
        "• Use at least 12 characters (16+ recommended).\n"
        "• Use a passphrase of unrelated words.\n"
        "• Avoid common patterns or personal information."
    )

    suggestions_label = ctk.CTkLabel(
        master_key_window,
        text=suggestions_text,
        wraplength=450,
        justify="left"
    )
    suggestions_label.pack(pady=10, padx=10)

    # Submit button
    submit_button = ctk.CTkButton(
        master_key_window,
        text="Submit",
        command=lambda: validate_master_key_callback(master_key_entry.get(), master_key_window)
    )
    submit_button.pack(pady=20)

    # Configure grid weights for resizing
    master_key_window.grid_rowconfigure(3, weight=1)
    master_key_window.grid_columnconfigure(0, weight=1)