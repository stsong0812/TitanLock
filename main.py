from tkinter import Tk, Toplevel, Label, Entry, Button, END, NORMAL, DISABLED
from tkinter import ttk
from passwords_frame import create_passwords_frame
from password_strength_frame import create_password_strength_frame
from password_generation_frame import create_password_generation_frame
from settings_frame import create_settings_frame
from tkinter.messagebox import showwarning
import secrets
import string
import re
import os
import csv
import uuid

# Path to the file where entries will be stored
PASSWORDS_FILE_PATH = '/etc/TitanLock/passwords.csv'

# Function to insert entry into the table and store it in the file
def add_entry(website, username, password):
    if website and username and password:
        # Generate a unique ID for the entry
        entry_id = str(uuid.uuid4())

        # Insert into the GUI tree with the generated ID
        tree.insert('', 'end', iid=entry_id, values=(website, username, password))

        # Append the entry to the CSV file
        try:
            with open(PASSWORDS_FILE_PATH, mode='a', newline='') as file:
                writer = csv.writer(file)
                writer.writerow([entry_id, website, username, password])  # Include ID in CSV
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
                    entry_id, website, username, password = row
                    tree.insert('', 'end', iid=entry_id, values=(website, username, password))
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

# Include function to check password strength here:
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
    generated_password_entry.config(state=DISABLED)  # Disable editing

# Create root window
root = Tk()
root.title('Titan Lock')
root.geometry('800x500')    # Set (width x height)

# Using notebook widget to create tabs
# https://www.tutorialspoint.com/notebook-widget-in-tkinter
notebook = ttk.Notebook(root)
notebook.pack(pady=10, expand=True, fill='both')

# Create different tabs (frames)
passwords_frame, tree = create_passwords_frame(notebook, open_add_entry_window, remove_entry)
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
    master_key_window.geometry('800x500')

    master_key_label = Label(master_key_window, text="Enter Master Key:")
    master_key_label.pack(pady=20)

    master_key_entry = Entry(master_key_window, show="*")
    master_key_entry.pack(pady=5)

    # Function to validate key
    def validate_master_key():
        master_key_path = '/etc/TitanLock/masterkey.txt'
        entered_master_key = master_key_entry.get()

        # If master key file does not exist, create it
        if not os.path.exists(master_key_path):
            try:
                with open(master_key_path, 'w') as master_key_file:
                    master_key_file.write(entered_master_key)  # Write the master key to the file
                    print(f"Master key file created at {master_key_path}")
                    master_key_window.destroy()
                    root.deiconify()  # Unlock the main window
            except Exception as e:
                print(f"An error occurred while creating the file: {e}")
        else:
            # If master key file exists, validate the entered key
            try:
                with open(master_key_path, 'r') as master_key_file:
                    stored_master_key = master_key_file.read()
                if entered_master_key == stored_master_key:
                    print("Master key validated.")
                    master_key_window.destroy()  # Close the master key window
                    root.deiconify()  # Unlock the main window
                else:
                    showwarning("Invalid Master Key", "The entered master key is incorrect.")
            except Exception as e:
                print(f"An error occurred while validating the master key: {e}")

    submit_button = Button(master_key_window, text="Submit", command=validate_master_key)
    submit_button.pack(pady=10)

# Create the folder if it doesn't exist
create_titanlock_folder()

# Load stored passwords into the table
load_passwords()

# Open the master key entry window (blocking the main window until validated)
root.withdraw()  # Hide the main window
open_master_key_window()

# Run the Tkinter event loop
root.mainloop()