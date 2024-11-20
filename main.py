from tkinter import Tk, Toplevel, BooleanVar, ttk, Label, Entry, Button, Checkbutton
from tkinter.messagebox import showwarning
from passwords_frame import create_passwords_frame, add_entry, remove_entry, toggle_password_visibility, load_passwords
from password_strength_frame import create_password_strength_frame, check_password_strength
from password_generation_frame import create_password_generation_frame, generate_password
from settings_frame import (
    create_settings_frame, save_settings, load_settings, validate_master_key,
    create_titanlock_folder, open_master_key_window
)
from threading import Timer
from argon2 import PasswordHasher, exceptions as argon2_exceptions

# Create root window
root = Tk()
root.title('Titan Lock')
root.geometry('800x500')  # Set (width x height)

# Initially hide the main root window
root.withdraw()

# Initialize the Argon2 password hasher
ph = PasswordHasher()

# Load settings at startup
settings = load_settings()
dark_mode_enabled = settings['dark_mode']
auto_lock_timeout = settings['auto_lock_timeout']

dark_mode_var = BooleanVar(root)
dark_mode_var.trace_add("write", lambda *args: toggle_dark_mode(dark_mode_var.get()))

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
    # Validate the master key using `validate_master_key` from `settings_frame.py`
    if validate_master_key(entered_master_key, master_key_window, verify_password):
        # Close the master key window
        master_key_window.destroy()
        # Show the main window after successful validation
        root.deiconify()
        reset_timer()  # Reset the timer after successful validation

# Bind reset_timer to user actions to reset on any activity
root.bind_all("<Any-KeyPress>", reset_timer)
root.bind_all("<Any-ButtonPress>", reset_timer)
root.bind_all("<Motion>", reset_timer)

# Using notebook widget to create tabs
notebook = ttk.Notebook(root)
notebook.pack(pady=10, expand=True, fill='both')

# Create different tabs (frames)
passwords_frame, tree = create_passwords_frame(notebook, add_entry, remove_entry, toggle_password_visibility)
password_strength_frame, strength_label = create_password_strength_frame(check_password_strength)
password_generation_frame, generated_password_entry = create_password_generation_frame(generate_password)

# Pass `dark_mode_var`, `save_settings` callback, and `auto_lock_timeout` to the settings frame
settings_frame = create_settings_frame(
    dark_mode_var, save_settings, auto_lock_timeout
)

notebook.add(passwords_frame, text='Passwords')
notebook.add(password_strength_frame, text='Password Strength')
notebook.add(password_generation_frame, text='Password Generation')
notebook.add(settings_frame, text='Settings')

def toggle_dark_mode(enabled):
    # Define colors for dark and light mode
    bg_color = "#2E2E2E" if enabled else "#d9d9d9"  # Dark or light background
    fg_color = "#FFFFFF" if enabled else "#000000"  # Dark or light foreground
    selected_tab_color = "#3A3A3A" if enabled else "#d9d9d9"  # Slightly lighter color for selected tab in dark mode
    header_bg_color = "#3E3E3E" if enabled else "#d9d9d9"  # Darker color for the header
    row_bg_color = "#4A4A4A" if enabled else "#FFFFFF"  # Slightly lighter gray for the table rows

    # Update the root window background color
    root.config(bg=bg_color)

    # Create or modify the style for notebook tabs
    style = ttk.Style()
    if enabled:
        style.configure("TNotebook", background=bg_color)
        style.configure("TNotebook.Tab", background=bg_color, foreground=fg_color)

        # Define a slightly lighter color for the active tab in dark mode
        style.map("TNotebook.Tab",
                  background=[("selected", selected_tab_color)],
                  foreground=[("selected", fg_color)])

        # Configure Treeview for dark mode
        style.configure("Treeview", background=row_bg_color, fieldbackground=row_bg_color, foreground=fg_color)
        style.configure("Treeview.Heading", background=header_bg_color, foreground=fg_color)
    else:
        # Reset to default colors in light mode
        style.configure("TNotebook", background="#d9d9d9")
        style.configure("TNotebook.Tab", background="#d9d9d9", foreground="#000000")
        style.map("TNotebook.Tab",
                  background=[("selected", "#d9d9d9")],
                  foreground=[("selected", "#000000")])

        # Configure Treeview for light mode
        style.configure("Treeview", background="#FFFFFF", fieldbackground="#FFFFFF", foreground="#000000")
        style.configure("Treeview.Heading", background="#d9d9d9", foreground="#000000")

    # Update each frame and its widgets
    for frame in [passwords_frame, password_strength_frame, password_generation_frame, settings_frame]:
        frame.config(bg=bg_color)
        for widget in frame.winfo_children():
            if isinstance(widget, (Label, Entry, Button, Checkbutton)):
                widget.config(bg=bg_color, fg=fg_color)

    # Apply the style to notebook and its tabs
    notebook.configure(style="TNotebook")

toggle_dark_mode(dark_mode_enabled)

# Create /etc/TitanLock folder on startup
create_titanlock_folder()

# Load stored passwords (if any) on startup
load_passwords(tree)

# Open master key window for initial authentication
open_master_key_window(root, validate_and_reset)

# Run the main loop
root.mainloop()