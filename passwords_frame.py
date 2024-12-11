from tkinter import ttk, simpledialog, messagebox
import customtkinter as ctk
import csv
import os
from cryptography.fernet import Fernet

# Global counter for IDs
next_id = 1  # Start from 1

# In-memory storage for demonstration purposes
password_data = []

# Function to create the passwords management frame
def create_passwords_frame(master, verify_password_callback):
    passwords_frame = ctk.CTkFrame(master)
    passwords_frame.pack(fill="both", expand=True, padx=20, pady=20)

    # Title label
    passwords_label = ctk.CTkLabel(passwords_frame, text="Manage Passwords", font=ctk.CTkFont(size=16, weight="bold"))
    passwords_label.pack(pady=10)

    # Treeview to display stored passwords
    tree = ttk.Treeview(passwords_frame, columns=("ID", "Website", "Username", "Password"), show="headings")
    tree.heading("ID", text="ID")
    tree.heading("Website", text="Website")
    tree.heading("Username", text="Username")
    tree.heading("Password", text="Password")
    tree.column("ID", width=50)
    tree.column("Website", width=150)
    tree.column("Username", width=150)
    tree.column("Password", width=150)
    tree.pack(pady=10, fill="both", expand=True)

    # Function to add a new password
    def add_password():
        global next_id  # Access the global counter
        website = simpledialog.askstring("Add Password", "Enter website:")
        username = simpledialog.askstring("Add Password", "Enter username:")
        password = simpledialog.askstring("Add Password", "Enter password:")

        if website and username and password:
            record_id = next_id  # Use the current value of the global counter
            next_id += 1  # Increment the global counter
            masked_password = "******"  # Fixed masking for display
            tree.insert("", "end", values=(record_id, website, username, masked_password))
            password_data.append((record_id, website, username, password))

            # Append the new password to the CSV file
            csv_file_path = "/etc/TitanLock/passwords.csv"
            key_file_path = "/etc/TitanLock/fernet_key.key"

            if not os.path.exists(key_file_path):
                messagebox.showerror("Error", "Encryption key not found. Cannot save password.")
                return

            try:
                with open(key_file_path, "rb") as key_file:
                    fernet_key = key_file.read()
                fernet = Fernet(fernet_key)

                encrypted_password = fernet.encrypt(password.encode()).decode()

                # Append the new row to the CSV file
                with open(csv_file_path, mode="a", newline="", encoding="utf-8") as csvfile:
                    csvwriter = csv.writer(csvfile)
                    csvwriter.writerow([record_id, website, username, encrypted_password])

            except Exception as e:
                print(f"Error saving password to CSV: {e}")
                messagebox.showerror("Error", "Failed to save password. Please try again.")

    # Function to remove a selected password
    def remove_password():
        selected_item = tree.selection()
        if not selected_item:
            messagebox.showinfo("Remove Entry", "Please select an entry to remove.")
            return

        for item in selected_item:
            # Get the data of the selected item
            values = tree.item(item, "values")
            record_id, website, username, _ = values

            # Remove from the in-memory data
            for i, entry in enumerate(password_data):
                if entry[0] == int(record_id):  # Match by ID (convert record_id to int)
                    del password_data[i]
                    break

            # Remove the item from the Treeview
            tree.delete(item)

            # Remove the entry from the CSV file
            csv_file_path = "/etc/TitanLock/passwords.csv"
            if os.path.exists(csv_file_path):
                try:
                    # Read the entire CSV file
                    with open(csv_file_path, mode="r", newline="", encoding="utf-8") as csvfile:
                        csvreader = list(csv.reader(csvfile))

                    # Filter out the row with the matching ID
                    updated_rows = [row for row in csvreader if int(row[0]) != int(record_id)]

                    # Overwrite the CSV file with the updated rows
                    with open(csv_file_path, mode="w", newline="", encoding="utf-8") as csvfile:
                        csvwriter = csv.writer(csvfile)
                        csvwriter.writerows(updated_rows)

                    print(f"Entry with ID {record_id} removed from CSV.")
                except Exception as e:
                    print(f"Error removing entry from CSV: {e}")
                    messagebox.showerror("Error", "Failed to update the CSV file. Please try again.")

        messagebox.showinfo("Remove Entry", "Selected entry has been removed.")

    # Function to toggle between showing and hiding passwords
    def toggle_passwords():
        if toggle_passwords.showing:
            # Hide passwords
            for i, (record_id, website, username, password) in enumerate(password_data):
                try:
                    item = tree.get_children()[i]
                    tree.item(item, values=(record_id, website, username, "******"))  # Mask password
                except IndexError:
                    print(f"No item in treeview for index {i}")
            toggle_passwords.showing = False
            show_button.configure(text="Show Passwords")
        else:
            # Show selected password
            selected_item = tree.selection()
            if not selected_item:
                messagebox.showinfo("Toggle Password", "Please select an entry to view its password.")
                return

            master_password = simpledialog.askstring("Verify Master Password", "Enter master password:", show="*")
            try:
                with open("/etc/TitanLock/masterkey.txt", "r") as hash_file:
                    stored_hash = hash_file.read().strip()
                if verify_password_callback(stored_hash, master_password):
                    for item in selected_item:
                        # Get the selected item's values
                        values = tree.item(item, "values")
                        record_id = int(values[0])  # Match by ID (convert record_id to int)

                        # Find the corresponding entry in password_data
                        for entry in password_data:
                            if entry[0] == record_id:  # Match by ID
                                _, website, username, password = entry
                                # Update the treeview item to show the actual password
                                tree.item(item, values=(record_id, website, username, password))
                                break
                    toggle_passwords.showing = True
                    show_button.configure(text="Hide Passwords")
                else:
                    messagebox.showerror("Invalid Master Password", "The master password is incorrect.")
            except Exception as e:
                print(f"Error verifying master password: {e}")

    # Initialize toggle state
    toggle_passwords.showing = False

    # Button frame
    button_frame = ctk.CTkFrame(passwords_frame)
    button_frame.pack(pady=10)

    add_button = ctk.CTkButton(button_frame, text="Add Password", command=add_password)
    add_button.grid(row=0, column=0, padx=5)

    show_button = ctk.CTkButton(button_frame, text="Show Passwords", command=toggle_passwords)
    show_button.grid(row=0, column=1, padx=5)

    remove_button = ctk.CTkButton(button_frame, text="Remove Entry", command=remove_password)
    remove_button.grid(row=0, column=2, padx=5)

    return passwords_frame, tree

# Function to load passwords from a CSV file and decrypt them
def load_passwords(tree):
    global next_id  # Access the global counter
    csv_file_path = "/etc/TitanLock/passwords.csv"
    key_file_path = "/etc/TitanLock/fernet_key.key"

    if not os.path.exists(csv_file_path):
        print(f"No CSV file found at {csv_file_path}. Skipping load.")
        return
    if not os.path.exists(key_file_path):
        print(f"No key file found at {key_file_path}. Cannot decrypt passwords.")
        return

    try:
        with open(key_file_path, "rb") as key_file:
            fernet_key = key_file.read()
        fernet = Fernet(fernet_key)

        with open(csv_file_path, mode="r", newline="", encoding="utf-8") as csvfile:
            csvreader = csv.reader(csvfile)
            for row in csvreader:
                if len(row) != 4:
                    print(f"Skipping invalid row: {row}")
                    continue
                record_id, website, username, encrypted_password = row
                try:
                    decrypted_password = fernet.decrypt(encrypted_password.encode()).decode()
                except Exception as e:
                    print(f"Decryption failed for row {row}: {e}")
                    continue
                password_data.append((int(record_id), website, username, decrypted_password))
                masked_password = "******"  # Fixed masking for display
                tree.insert("", "end", values=(record_id, website, username, masked_password))
                next_id = max(next_id, int(record_id) + 1)  # Update the counter to avoid duplicates
        print("Passwords loaded successfully.")
    except Exception as e:
        print(f"Error loading passwords from CSV: {e}")