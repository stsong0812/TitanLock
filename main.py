from tkinter import Tk, Toplevel, Label, Entry, Button, END, NORMAL, DISABLED
from tkinter import ttk
from passwords_frame import create_passwords_frame
from password_strength_frame import create_password_strength_frame
from password_generation_frame import create_password_generation_frame
from settings_frame import create_settings_frame
from tkinter.messagebox import showwarning
from argon2 import PasswordHasher, exceptions as argon2_exceptions
from cryptography.fernet import Fernet
import secrets
import string
import re
import os
import csv
import uuid

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

# AES (Fernet) key generation and encryption/decryption functions
# For the demo, we generate a new key each time. In practice, securely store and load this key.
key = Fernet.generate_key()  # In practice, store this securely and load it when needed.
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
def check_password_strength(password):
    score = 0

    # Password length check
    if len(password) >= 12:
        score += 2
    elif len(password) >= 8:
        score += 1
    
    # Checking for lowercase characters
    if re.search(r'[a-z]', password):
        score += 1
    # Checking for uppercase characters
    if re.search(r'[A-Z]', password):
        score += 1
    # Checking for digits
    if re.search(r'[0-9]', password):
        score += 1
    # Checking for special characters
    if re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        score += 1

    # Check for common passwords (simple example)
    common_passwords = ["password", "123456", "123456789", "qwerty", "abc123"]
    if password.lower() in common_passwords:
        score -= 2

    # Display password strength based on score
    if score >= 5:
        strength_label.config(text="Password strength: Strong")
    elif 3 <= score < 5:
        strength_label.config(text="Password strength: Moderate")
    else:
        strength_label.config(text="Password strength: Weak")
    
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

# Using notebook widget to create tabs
notebook = ttk.Notebook(root)
notebook.pack(pady=10, expand=True, fill='both')

# Create different tabs (frames)
passwords_frame, tree = create_passwords_frame(notebook, open_add_entry_window, remove_entry, toggle_password_visibility)
password_strength_frame, strength_label = create_password_strength_frame(check_password_strength)
password_generation_frame, generated_password_entry = create_password_generation_frame(generate_password)
settings_frame = create_settings_frame()

notebook.add(passwords_frame, text='Passwords')
notebook.add(password_strength_frame, text='Password Strength')
notebook.add(password_generation_frame, text='Password Generation')
notebook.add(settings_frame, text='Settings')

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

# Include master key function with validation
def open_master_key_window():
    master_key_window = Toplevel(root)
    master_key_window.title("Titan Lock")
    master_key_window.geometry("300x150")

    master_key_label = Label(master_key_window, text="Enter Master Key:")
    master_key_label.pack(pady=10)

    master_key_entry = Entry(master_key_window, show="*")
    master_key_entry.pack(pady=10)

    # Validate master key function with hashing
    def validate_master_key():
        master_key_path = '/etc/TitanLock/masterkey.txt'
        entered_master_key = master_key_entry.get()

        # If master key file does not exist, create it with a hashed key
        if not os.path.exists(master_key_path):
            try:
                hashed_master_key = hash_password(entered_master_key)
                with open(master_key_path, 'w') as master_key_file:
                    master_key_file.write(hashed_master_key)  # Store the hashed key
                    print(f"Master key file created at {master_key_path}")
                    master_key_window.destroy()
                    root.deiconify()  # Unlock the main window``
            except Exception as e:
                print(f"An error occurred while creating the file: {e}")
        else:
            # If master key file exists, validate the entered key
            try:
                with open(master_key_path, 'r') as master_key_file:
                    stored_master_key_hash = master_key_file.read()
                if verify_password(stored_master_key_hash, entered_master_key):
                    print("Master key validated.")
                    master_key_window.destroy()  # Close the master key window
                    root.deiconify()  # Unlock the main window
                else:
                    showwarning("Invalid Master Key", "The entered master key is incorrect.")
            except Exception as e:
                print(f"An error occurred while validating the master key: {e}")

    submit_button = Button(master_key_window, text="Submit", command=validate_master_key)
    submit_button.pack(pady=10)

# Hide main window initially until master key is entered
root.withdraw()
open_master_key_window()

# Create /etc/TitanLock folder on startup
create_titanlock_folder()

# Load stored passwords (if any) on startup
load_passwords()

root.mainloop()