from tkinter import Frame, Label, Button, ttk, Toplevel, Entry
import csv
import os
import uuid  # Import uuid to generate unique IDs
from cryptography.fernet import Fernet  # Import Fernet for encryption and decryption
from tkinter.messagebox import showwarning
from argon2 import PasswordHasher, exceptions as argon2_exceptions  # Import Argon2 for password hashing

PASSWORDS_FILE_PATH = '/etc/TitanLock/passwords.csv'
KEY_FILE_PATH = '/etc/TitanLock/fernet_key.key'
MASTER_KEY_PATH = '/etc/TitanLock/masterkey.txt'

# Initialize the Argon2 password hasher
ph = PasswordHasher()

# Load or generate an encryption key
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

# Load the encryption key
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

# Function to create passwords tab (frame)
def create_passwords_frame(notebook, add_entry_callback, remove_entry_callback, toggle_password_visibility_callback):
    # Frame for managing passwords
    passwords_frame = Frame(notebook)
    passwords_frame.pack(fill='both', expand=True)

    # Label to describe the frame
    passwords_label = Label(passwords_frame, text="Passwords", font=("TkDefaultFont", 12, "bold"))
    passwords_label.pack(pady=10)

    # Treeview to display the stored passwords
    tree = ttk.Treeview(passwords_frame, columns=("Website", "Username", "Password"), show='headings')
    tree.heading("Website", text="Website")
    tree.heading("Username", text="Username")
    tree.heading("Password", text="Password")

    # Set column widths
    tree.column("Website", width=150)
    tree.column("Username", width=120)
    tree.column("Password", width=120)

    # Pack the treeview into the frame
    tree.pack(pady=10, fill='both', expand=True)

    # Button to add new password entries
    add_entry_button = Button(passwords_frame, text="Add New Entry", command=lambda: open_add_entry_window(tree))
    add_entry_button.pack(pady=10)

    # Button to remove selected password entries
    remove_entry_button = Button(passwords_frame, text="Remove Selected Entry", command=lambda: remove_entry(tree))
    remove_entry_button.pack(pady=10)
    
    # Button to show/hide passwords
    toggle_button = Button(passwords_frame, text="Show/Hide Passwords", command=lambda: toggle_password_visibility(tree))
    toggle_button.pack(pady=10)

    return passwords_frame, tree

# Function to open a window to add a new entry
def open_add_entry_window(tree):
    # Create a new window for adding an entry
    add_window = Toplevel()
    add_window.title("Add New Entry")
    add_window.geometry("300x250")

    # Labels and entries for website, username, and password
    website_label = Label(add_window, text="Website:")
    website_label.pack(pady=5)
    website_entry = Entry(add_window)
    website_entry.pack(pady=5)

    username_label = Label(add_window, text="Username:")
    username_label.pack(pady=5)
    username_entry = Entry(add_window)
    username_entry.pack(pady=5)

    password_label = Label(add_window, text="Password:")
    password_label.pack(pady=5)
    password_entry = Entry(add_window, show="*")
    password_entry.pack(pady=5)

    # Button to submit the new entry
    submit_button = Button(add_window, text="Add Entry", command=lambda: add_entry(website_entry.get(), username_entry.get(), password_entry.get(), tree, add_window))
    submit_button.pack(pady=10)

# Function to add entry to the passwords file and treeview
def add_entry(website, username, password, tree, window):
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
        
        # Close the add entry window
        window.destroy()
    else:
        showwarning("Invalid Input", "All fields are required to add an entry.")

# Function to remove selected entry from passwords file and treeview
def remove_entry(tree):
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

# Function to prompt for master password and verify before unmasking passwords
def prompt_for_master_password(callback):
    # Create a new window for entering the master key
    prompt_window = Toplevel()
    prompt_window.title("Enter Master Key")
    prompt_window.geometry("300x150")

    master_key_label = Label(prompt_window, text="Enter Master Key:")
    master_key_label.pack(pady=10)

    master_key_entry = Entry(prompt_window, show="*")
    master_key_entry.pack(pady=10)

    def on_submit():
        entered_master_key = master_key_entry.get()
        if verify_master_key(entered_master_key):
            prompt_window.destroy()
            callback()  # Execute the callback if the master key is valid
        else:
            showwarning("Invalid Master Key", "The entered master key is incorrect.")

    submit_button = Button(prompt_window, text="Submit", command=on_submit)
    submit_button.pack(pady=10)

# Function to toggle the visibility of passwords
def toggle_password_visibility(tree):
    passwords_masked = not getattr(toggle_password_visibility, 'passwords_masked', True)
    toggle_password_visibility.passwords_masked = passwords_masked

    selected_item = tree.selection()  # Get the selected entry

    if selected_item:
        entry_id = selected_item[0]
        values = tree.item(entry_id)['values']
        website, username = values[0], values[1]

        if passwords_masked:
            # Mask the password with six asterisks
            masked_password = '*' * 6
            tree.item(entry_id, values=(website, username, masked_password))
        else:
            # Prompt for master password before unmasking
            def unmask_password():
                try:
                    with open(PASSWORDS_FILE_PATH, mode='r', newline='') as file:
                        reader = csv.reader(file)
                        for row in reader:
                            if row[0] == entry_id:
                                encrypted_password = row[3]
                                real_password = decrypt_password(encrypted_password)
                                tree.item(entry_id, values=(website, username, real_password))
                except Exception as e:
                    showwarning("Error", f"An error occurred while decrypting the password: {e}")

            prompt_for_master_password(unmask_password)

# Function to verify the master key
def verify_master_key(entered_master_key):
    try:
        with open(MASTER_KEY_PATH, 'r') as master_key_file:
            stored_master_key_hash = master_key_file.read()
        return ph.verify(stored_master_key_hash, entered_master_key)
    except argon2_exceptions.VerifyMismatchError:
        return False
    except Exception as e:
        print(f"An error occurred while validating the master key: {e}")
        return False

# Function to load stored passwords from the file and display them in the table
def load_passwords(tree):
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