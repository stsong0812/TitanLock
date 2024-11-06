from tkinter import Tk, Toplevel, Label, Entry, Button, END, NORMAL, ttk, Checkbutton, BooleanVar
from passwords_frame import create_passwords_frame
from password_strength_frame import create_password_strength_frame
from password_generation_frame import create_password_generation_frame
from settings_frame import create_settings_frame
from tkinter.messagebox import showwarning
from argon2 import PasswordHasher, exceptions as argon2_exceptions
from cryptography.fernet import Fernet
import configparser
import secrets
import string
import re
import os
import csv
import uuid
import time
from threading import Timer

# Define path for settings file
SETTINGS_FILE_PATH = '/etc/TitanLock/settings.conf'

# Load settings function in main.py
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

# Save settings function in main.py
def save_settings(dark_mode, auto_lock_timeout):
    """Save settings to the configuration file."""
    config = configparser.ConfigParser()
    config['Display'] = {'dark_mode': str(dark_mode)}
    config['Security'] = {'auto_lock_timeout': str(auto_lock_timeout)}

    os.makedirs(os.path.dirname(SETTINGS_FILE_PATH), exist_ok=True)

    with open(SETTINGS_FILE_PATH, 'w') as configfile:
        config.write(configfile)
    print("Settings saved.")

def prompt_for_master_key(callback):
    """Prompts the user for the master key."""
    master_key_window = Toplevel(root)
    master_key_window.title("Enter Master Key")
    master_key_window.geometry("300x150")

    master_key_label = Label(master_key_window, text="Enter Master Key:")
    master_key_label.pack(pady=10)

    master_key_entry = Entry(master_key_window, show="*")
    master_key_entry.pack(pady=10)

    # Function to validate the entered master key
    def validate_master_key():
        entered_master_key = master_key_entry.get()
        master_key_path = '/etc/TitanLock/masterkey.txt'

        try:
            with open(master_key_path, 'r') as master_key_file:
                stored_master_key_hash = master_key_file.read()
            if verify_password(stored_master_key_hash, entered_master_key):
                print("Master key validated.")
                callback()  # Call the provided callback function to unmask the password
                master_key_window.destroy()  # Close the master key window
            else:
                showwarning("Invalid Master Key", "The entered master key is incorrect.")
        except Exception as e:
            print(f"An error occurred while validating the master key: {e}")

    submit_button = Button(master_key_window, text="Submit", command=validate_master_key)
    submit_button.pack(pady=10)

passwords_masked = True

def toggle_password_visibility():
    global passwords_masked
    passwords_masked = not passwords_masked

    selected_item = tree.selection()  # Get the selected entry

    if selected_item:
        if passwords_masked:
            # If passwords are masked, just mask them
            entry_id = selected_item[0]
            values = tree.item(entry_id)['values']
            website, username = values[0], values[1]

            # Mask the password with six asterisks
            masked_password = '*' * 6
            tree.item(entry_id, values=(website, username, masked_password))
        else:
            # If passwords are to be unmasked, prompt for master key verification
            unmask_password(selected_item[0])
    else:
        print("No entry selected.")

def unmask_password(entry_id):
    """Prompt the user for the master key to unmask the password."""
    values = tree.item(entry_id)['values']
    website, username = values[0], values[1]

    # Create a dialog to enter the master key for verification
    verification_window = Toplevel(root)
    verification_window.title("Titan Lock")
    verification_window.geometry("300x150")

    master_key_label = Label(verification_window, text="Enter Master Key:")
    master_key_label.pack(pady=10)

    master_key_entry = Entry(verification_window, show="*")
    master_key_entry.pack(pady=10)

    def verify_master_key_and_show():
        entered_master_key = master_key_entry.get()
        master_key_path = '/etc/TitanLock/masterkey.txt'

        # Read the stored master key hash
        try:
            with open(master_key_path, 'r') as master_key_file:
                stored_master_key_hash = master_key_file.read()

            # Verify the entered master key against the stored hash
            if verify_password(stored_master_key_hash, entered_master_key):
                # If verified, decrypt the actual password
                encrypted_password = ''
                with open(PASSWORDS_FILE_PATH, mode='r', newline='') as file:
                    reader = csv.reader(file)
                    for row in reader:
                        if row[0] == entry_id:  # Match by the selected entry ID
                            encrypted_password = row[3]  # Get the encrypted password

                real_password = decrypt_password(encrypted_password)

                # Update the tree item to show the real password
                tree.item(entry_id, values=(website, username, real_password))
                verification_window.destroy()  # Close the verification window
            else:
                showwarning("Invalid Master Key", "The entered master key is incorrect.")
        except Exception as e:
            print(f"An error occurred while validating the master key: {e}")

    submit_button = Button(verification_window, text="Submit", command=verify_master_key_and_show)
    submit_button.pack(pady=10)

# Path to the file where entries will be stored
PASSWORDS_FILE_PATH = '/etc/TitanLock/passwords.csv'

# Initialize the Argon2 hasher
ph = PasswordHasher()

# Function to hash a password or master key
def hash_password(password):
    return ph.hash(password)

# Function to verify a password or master key against the stored hash
def verify_password(stored_hash, provided_password):
    try:
        return ph.verify(stored_hash, provided_password)
    except argon2_exceptions.VerifyMismatchError:
        return False

# Path to the file where the encryption key will be stored
KEY_FILE_PATH = '/etc/TitanLock/fernet_key.key'

# Function to generate and store the Fernet encryption key if it doesn't already exist
def load_or_generate_key():
    # Check if the key file exists
    if os.path.exists(KEY_FILE_PATH):
        # Load the existing key from the file
        try:
            with open(KEY_FILE_PATH, 'rb') as key_file:
                key = key_file.read()
                print("Encryption key loaded successfully.")
                return key
        except Exception as e:
            print(f"An error occurred while loading the encryption key: {e}")
            return None
    else:
        # Generate a new key and store it securely
        key = Fernet.generate_key()
        try:
            with open(KEY_FILE_PATH, 'wb') as key_file:
                key_file.write(key)
                print("Encryption key generated and saved successfully.")
                return key
        except Exception as e:
            print(f"An error occurred while saving the encryption key: {e}")
            return None

# Load or generate the encryption key
key = load_or_generate_key()
if key is None:
    print("Failed to load or generate encryption key. Exiting program.")
    exit()

# Initialize the Fernet encryption object with the loaded key
fernet = Fernet(key)

# Function to encrypt a password using AES (Fernet)
def encrypt_password(password):
    return fernet.encrypt(password.encode()).decode()

# Function to decrypt a password using AES (Fernet)
def decrypt_password(encrypted_password):
    return fernet.decrypt(encrypted_password.encode()).decode()

# Function to insert entry into the table and store it in the file
def add_entry(website, username, password):
    if website and username and password:
        # Generate a unique ID for the entry
        entry_id = str(uuid.uuid4())

        # Encrypt the password using AES (Fernet)
        encrypted_password = encrypt_password(password)

        # Mask the password with six asterisks
        masked_password = '*' * 6

        # Insert into the GUI tree with the generated ID and masked password
        tree.insert('', 'end', iid=entry_id, values=(website, username, masked_password))

        # Append the entry to the CSV file (store encrypted password)
        try:
            with open(PASSWORDS_FILE_PATH, mode='a', newline='') as file:
                writer = csv.writer(file)
                writer.writerow([entry_id, website, username, encrypted_password])  # Store the encrypted password in CSV
        except PermissionError:
            showwarning("Permission Error", "Permission denied: Run the program as root.")
        except Exception as e:
            showwarning("Error", f"An error occurred: {e}")

# Function to remove selected entry
def remove_entry():
    selected_item = tree.selection()
    if selected_item:
        entry_id = selected_item[0]  # Get the selected entry's ID
        tree.delete(selected_item)

        # Remove entry from the CSV file
        try:
            # Read all entries from the CSV
            with open(PASSWORDS_FILE_PATH, mode='r', newline='') as file:
                reader = csv.reader(file)
                rows = [row for row in reader if row[0] != entry_id]  # Exclude the entry with the selected ID

            # Write the remaining entries back to the CSV
            with open(PASSWORDS_FILE_PATH, mode='w', newline='') as file:
                writer = csv.writer(file)
                writer.writerows(rows)

        except Exception as e:
            showwarning("Error", f"An error occurred while removing the entry: {e}")
    else:
        showwarning("No Selection", "Please select an entry to remove.")

# Function to load stored passwords from the file and display them in the table
def load_passwords():
    if os.path.exists(PASSWORDS_FILE_PATH):
        try:
            with open(PASSWORDS_FILE_PATH, mode='r', newline='') as file:
                reader = csv.reader(file)
                for row in reader:
                    entry_id, website, username, hashed_password = row
                    # Mask the password with six asterisks
                    masked_password = '*' * 6  # Always display 6 asterisks for the masked password
                    tree.insert('', 'end', iid=entry_id, values=(website, username, masked_password))
        except Exception as e:
            showwarning("Error", f"An error occurred while loading passwords: {e}")

# Function to open an "add entry" window
def open_add_entry_window():
    new_window = Toplevel(root)
    new_window.title("Add New Entry")

    website_label = Label(new_window, text="Website:")
    website_label.pack(pady=5)
    website_entry = Entry(new_window)
    website_entry.pack(pady=5)

    username_label = Label(new_window, text="Username:")
    username_label.pack(pady=5)
    username_entry = Entry(new_window)
    username_entry.pack(pady=5)

    password_label = Label(new_window, text="Password:")
    password_label.pack(pady=5)
    password_entry = Entry(new_window, show="*")
    password_entry.pack(pady=5)

    def submit_new_entry():
        website = website_entry.get()
        username = username_entry.get()
        password = password_entry.get()
        add_entry(website, username, password)
        new_window.destroy()

    submit_button = Button(new_window, text="Submit", command=submit_new_entry)
    submit_button.pack(pady=10)

# Function to check password strength
def check_password_strength(password, strength_label):
    score = 0

    # Password length check with scoring for additional length
    if len(password) >= 16:
        score += 3  # Strong score for longer passwords
    elif len(password) >= 12:
        score += 2
    elif len(password) >= 8:
        score += 1

    # Check if it contains multiple random, unrelated words (e.g., a passphrase)
    if re.search(r'(\w+\s+){2,}\w+', password):  # checks for at least three words with spaces
        score += 2

    # Check for absence of common patterns or personal info
    common_patterns = ['password', '1234', 'abcd', 'qwerty', 'user', 'admin']
    if not any(pattern in password.lower() for pattern in common_patterns):
        score += 1

    # Check for character variety, though not strictly enforcing complexity
    if any(char.isupper() for char in password) and any(char.islower() for char in password):
        score += 1  # Includes both uppercase and lowercase for additional variety
    if any(char.isdigit() for char in password):
        score += 1  # Includes numbers
    if any(char in "!@#$%^&*(),.?\":{}|<>" for char in password):
        score += 1  # Includes special characters

    # Display password strength based on cumulative score
    if score >= 7:
        strength_label.config(text="Password strength: Strong", fg="green")
    elif 4 <= score < 7:
        strength_label.config(text="Password strength: Moderate", fg="orange")
    else:
        strength_label.config(text="Password strength: Weak", fg="red")
    
# Password generation algorithm 
def generate_password(length, include_uppercase, include_numbers, include_special_chars):
    try:
        # Validate length
        length = int(length)
        if length < 6 or length > 20:
            showwarning("Invalid Length", "Password length must be between 6 and 20 characters.")
            return
    except ValueError:
        showwarning("Invalid Input", "Please enter a valid number for password length.")
        return

    # Build character pool based on user selections
    characters = string.ascii_lowercase  # Start with lowercase letters
    
    if include_uppercase:
        characters += string.ascii_uppercase
    if include_numbers:
        characters += string.digits
    if include_special_chars:
        characters += string.punctuation

    # Check if no options were selected
    if not (include_uppercase or include_numbers or include_special_chars):
        showwarning("No Options Selected", "Please select at least one character type (uppercase, numbers, special characters).")
        return

    # Generate the password using the selected character set and length
    password = ''.join(secrets.choice(characters) for _ in range(length))
    
    # Display the generated password in the appropriate entry field
    generated_password_entry.config(state=NORMAL)  # Allow editing
    generated_password_entry.delete(0, END)  # Clear current value
    generated_password_entry.insert(0, password)  # Insert new password

# Create root window
root = Tk()
root.title('Titan Lock')
root.geometry('800x500')    # Set (width x height)

# Load settings at startup
settings = load_settings()
dark_mode_enabled = settings['dark_mode']

# Initialize the dark mode variable after creating `root`
dark_mode_var = BooleanVar(root)
dark_mode_var.trace_add("write", lambda *args: toggle_dark_mode(dark_mode_var.get()))

# Set the initial timeout and timer variable
timeout_duration = settings['auto_lock_timeout']
timeout_timer = None

# Function to lock the app by hiding the main window and showing the master key window
def lock_app():
    if root.state() == "normal":  # Prevent multiple master key windows
        root.withdraw()  # Hide the main window
        open_master_key_window()  # Reopen master key window for re-authentication

# Function to reset the timer with each activity, only if main window is visible
def reset_timer(event=None):
    global timeout_timer
    if root.state() == "normal":  # Only reset timer if main window is visible
        if timeout_timer:
            timeout_timer.cancel()
        timeout_timer = Timer(timeout_duration, lock_app)
        timeout_timer.start()

# Bind reset_timer to user actions to reset on any activity
root.bind_all("<Any-KeyPress>", reset_timer)
root.bind_all("<Any-ButtonPress>", reset_timer)
root.bind_all("<Motion>", reset_timer)

# Start the timer for the first time
reset_timer()   

# Load settings at startup
settings = load_settings()
dark_mode_enabled = settings['dark_mode']
auto_lock_timeout = settings['auto_lock_timeout']  # Retrieve auto_lock_timeout

# Initialize the dark mode variable after creating `root`
dark_mode_var = BooleanVar(root)
dark_mode_var.set(dark_mode_enabled)  # Set initial dark mode state
dark_mode_var.trace_add("write", lambda *args: toggle_dark_mode(dark_mode_var.get()))

# Using notebook widget to create tabs
notebook = ttk.Notebook(root)
notebook.pack(pady=10, expand=True, fill='both')

# Create different tabs (frames)
passwords_frame, tree = create_passwords_frame(notebook, open_add_entry_window, remove_entry, toggle_password_visibility)
password_strength_frame, strength_label = create_password_strength_frame(check_password_strength)
password_generation_frame, generated_password_entry = create_password_generation_frame(generate_password)

# Pass `dark_mode_var`, `save_settings` callback, and `auto_lock_timeout` to the settings frame
settings_frame = create_settings_frame(dark_mode_var, save_settings, auto_lock_timeout)

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

# Function to create a folder in /etc/ called TitanLock
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

# Function to validate the master key and only start the timer if validation is successful
def validate_master_key(entered_master_key, master_key_window):
    master_key_path = '/etc/TitanLock/masterkey.txt'
    try:
        with open(master_key_path, 'r') as master_key_file:
            stored_master_key_hash = master_key_file.read()
        if verify_password(stored_master_key_hash, entered_master_key):
            print("Master key validated.")
            master_key_window.destroy()  # Close the master key window
            root.deiconify()  # Show main window
            reset_timer()  # Start the auto-lock timer after unlocking
        else:
            showwarning("Invalid Master Key", "The entered master key is incorrect.")
    except Exception as e:
        print(f"An error occurred while validating the master key: {e}")
        
# Initialize the timeout duration when loading settings
timeout_duration = settings['auto_lock_timeout']

# When saving settings, update the timeout duration
def save_settings_callback(dark_mode, auto_lock_timeout):
    save_settings(dark_mode, auto_lock_timeout)
    global timeout_duration
    timeout_duration = auto_lock_timeout
    reset_timer()  # Reset timer with new duration after saving


def open_master_key_window():
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
    suggestions_paragraph.pack(pady=(10, 10), padx=20)  # Added spacing after paragraph

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
        list_item_label.pack(anchor="w", padx=165, pady=2)  # Increased padding for indentation and spacing between items

    # Label to display password strength
    password_strength_label = Label(master_key_window, text="Password strength: ")
    password_strength_label.pack(pady=10)
    
    # Submit button triggers master key validation without starting the timer
    submit_button = Button(
        master_key_window,
        text="Submit",
        command=lambda: validate_master_key(master_key_entry.get(), master_key_window)
    )
    submit_button.pack(pady=10)

    # Function to check the master password strength
    def check_master_password_strength(event=None):
        password = master_key_entry.get()
        score = 0

        # Password length check with scoring for additional length
        if len(password) >= 16:
            score += 3  # Strong score for longer passwords
        elif len(password) >= 12:
            score += 2
        elif len(password) >= 8:
            score += 1

        # Check if it contains multiple random, unrelated words (e.g., a passphrase)
        if re.search(r'(\w+\s+){2,}\w+', password):  # checks for at least three words with spaces
            score += 2

        # Check for absence of common patterns or personal info
        common_patterns = ['password', '1234', 'abcd', 'qwerty', 'user', 'admin']
        if not any(pattern in password.lower() for pattern in common_patterns):
            score += 1

        # Check for character variety, though not strictly enforcing complexity
        if any(char.isupper() for char in password) and any(char.islower() for char in password):
            score += 1  # Includes both uppercase and lowercase for additional variety
        if any(char.isdigit() for char in password):
            score += 1  # Includes numbers
        if any(char in "!@#$%^&*(),.?\":{}|<>" for char in password):
            score += 1  # Includes special characters

        # Display password strength based on cumulative score
        if score >= 7:
            password_strength_label.config(text="Password strength: Strong", fg="green")
        elif 4 <= score < 7:
            password_strength_label.config(text="Password strength: Moderate", fg="orange")
        else:
            password_strength_label.config(text="Password strength: Weak", fg="red")

    # Bind the password strength function to the Entry widget
    master_key_entry.bind("<KeyRelease>", check_master_password_strength)

    # Button to submit the master key
    submit_button = Button(
        master_key_window,
        text="Submit",
        command=lambda: validate_master_key(master_key_entry.get(), master_key_window)
    )
    
root.bind_all("<Any-KeyPress>", reset_timer)
root.bind_all("<Any-ButtonPress>", reset_timer)
root.bind_all("<Motion>", reset_timer)


# Hide main window initially until master key is entered
root.withdraw()
open_master_key_window()

# Create /etc/TitanLock folder on startup
create_titanlock_folder()

# Load stored passwords (if any) on startup
load_passwords()

root.mainloop()