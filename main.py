import customtkinter as ctk
from passwords_frame import create_passwords_frame, load_passwords
from password_strength_frame import create_password_strength_frame, check_password_strength
from password_generation_frame import create_password_generation_frame, generate_password
from settings_frame import create_settings_frame, save_settings, load_settings, validate_master_key, create_titanlock_folder, open_master_key_window
from threading import Timer
from argon2 import PasswordHasher, exceptions as argon2_exceptions

# Function to toggle dark mode
def toggle_dark_mode(enabled):
    """Toggles between Dark and Light modes."""
    ctk.set_appearance_mode("Dark" if enabled else "Light")

# Set up the customtkinter theme
ctk.set_appearance_mode("System")
ctk.set_default_color_theme("blue")

# Create root window with customtkinter
root = ctk.CTk()
root.title("Titan Lock")
root.geometry("900x600")

# Initially hide the main root window
root.withdraw()

# Initialize Argon2 password hasher
ph = PasswordHasher()

# Load settings at startup
settings = load_settings()
dark_mode_enabled = settings['dark_mode']
auto_lock_timeout = settings['auto_lock_timeout']

dark_mode_var = ctk.BooleanVar(value=dark_mode_enabled)

# Set the initial timeout and timer variable
timeout_timer = None

# Function to lock the app by hiding the main window and showing the master key window
def lock_app():
    if root.state() == "normal":  # Prevent multiple master key windows
        root.withdraw()  # Hide the main window
        open_master_key_window(root, validate_and_reset)

# Function to reset the timer with each activity, only if main window is visible
def reset_timer(event=None):
    global timeout_timer
    if root.state() == "normal":  # Only reset timer if main window is visible
        if timeout_timer:
            timeout_timer.cancel()
        timeout_timer = Timer(auto_lock_timeout, lock_app)
        timeout_timer.start()

# Function to verify the provided password against the stored hash
def verify_password(stored_hash, provided_password):
    try:
        return ph.verify(stored_hash, provided_password)
    except argon2_exceptions.VerifyMismatchError:
        return False

# Function to validate the master key and reset the timer after successful validation
def validate_and_reset(entered_master_key, master_key_window):
    if validate_master_key(entered_master_key, master_key_window, verify_password):
        master_key_window.destroy()
        root.deiconify()
        reset_timer()  # Reset the timer after successful validation

# Bind reset_timer to user actions to reset on any activity
root.bind_all("<Any-KeyPress>", reset_timer)
root.bind_all("<Any-ButtonPress>", reset_timer)
root.bind_all("<Motion>", reset_timer)

# Create notebook-style tabs using customtkinter's CTkTabview
notebook = ctk.CTkTabview(root)
notebook.pack(pady=20, expand=True, fill="both")

# Add the "Passwords" tab
notebook.add("Passwords")
passwords_tab = notebook.tab("Passwords")
passwords_frame, tree = create_passwords_frame(
    master=passwords_tab,
    verify_password_callback=verify_password  # Pass function as callback
)
load_passwords(tree)  # Load passwords on startup

# Add the "Password Strength" tab
notebook.add("Password Strength")
password_strength_tab = notebook.tab("Password Strength")
create_password_strength_frame(
    master=password_strength_tab,
    check_strength_callback=check_password_strength
)

# Add the "Password Generation" tab
notebook.add("Password Generation")
password_generation_tab = notebook.tab("Password Generation")
create_password_generation_frame(
    master=password_generation_tab,
    generate_password_callback=generate_password
)

# Add the "Settings" tab
notebook.add("Settings")
settings_tab = notebook.tab("Settings")
create_settings_frame(
    master=settings_tab,
    dark_mode_var=dark_mode_var,
    save_settings_callback=save_settings,
    auto_lock_timeout=auto_lock_timeout,
    toggle_dark_mode_callback=toggle_dark_mode  # Pass callback for real-time dark mode update
)

# Apply the saved dark mode setting
toggle_dark_mode(dark_mode_enabled)

# Create /etc/TitanLock folder on startup
create_titanlock_folder()

# Open master key window for initial authentication
open_master_key_window(root, validate_and_reset)

# Run the main loop
root.mainloop()