import customtkinter as ctk
import string
import secrets
from tkinter.messagebox import showwarning

# Function to create password generation tab (frame)
def create_password_generation_frame(master, generate_password_callback):
    # Frame for the password generation tab
    password_generation_frame = ctk.CTkFrame(master)
    password_generation_frame.pack(fill="both", expand=True, padx=20, pady=20)

    # Configure grid weights to center all content
    password_generation_frame.grid_rowconfigure(0, weight=1)  # Spacer above content
    password_generation_frame.grid_rowconfigure(1, weight=0)  # Title
    password_generation_frame.grid_rowconfigure(2, weight=0)  # Length label and entry
    password_generation_frame.grid_rowconfigure(3, weight=0)  # Checkboxes
    password_generation_frame.grid_rowconfigure(4, weight=0)  # Password field
    password_generation_frame.grid_rowconfigure(5, weight=0)  # Copy button
    password_generation_frame.grid_rowconfigure(6, weight=1)  # Spacer below content
    password_generation_frame.grid_columnconfigure(0, weight=1)
    password_generation_frame.grid_columnconfigure(1, weight=1)

    # Title Label
    password_generation_label = ctk.CTkLabel(
        password_generation_frame,
        text="Password Generator",
        font=ctk.CTkFont(size=16, weight="bold")
    )
    password_generation_label.grid(row=1, column=0, columnspan=2, pady=10, sticky="n")

    # Password Length Input
    length_label = ctk.CTkLabel(password_generation_frame, text="Password Length (6-20 characters):")
    length_label.grid(row=2, column=0, columnspan=2, padx=10, pady=5, sticky="n")
    length_entry = ctk.CTkEntry(password_generation_frame, placeholder_text="Enter length", width=200)
    length_entry.grid(row=3, column=0, columnspan=2, padx=10, pady=5, sticky="n")

    # Boolean variables for options
    include_uppercase = ctk.BooleanVar(value=True)
    include_numbers = ctk.BooleanVar(value=True)
    include_special_chars = ctk.BooleanVar(value=True)

    # Checkboxes for character options
    uppercase_check = ctk.CTkCheckBox(password_generation_frame, text="Include Uppercase Letters", variable=include_uppercase)
    uppercase_check.grid(row=4, column=0, columnspan=2, padx=10, pady=2, sticky="n")
    numbers_check = ctk.CTkCheckBox(password_generation_frame, text="Include Numbers", variable=include_numbers)
    numbers_check.grid(row=5, column=0, columnspan=2, padx=10, pady=2, sticky="n")
    special_chars_check = ctk.CTkCheckBox(password_generation_frame, text="Include Special Characters", variable=include_special_chars)
    special_chars_check.grid(row=6, column=0, columnspan=2, padx=10, pady=2, sticky="n")

    # Generated Password Entry
    generated_password_entry = ctk.CTkEntry(password_generation_frame, state="normal", placeholder_text="Generated password", width=200)
    generated_password_entry.grid(row=7, column=0, columnspan=2, padx=10, pady=10, sticky="n")

    # Generate Button
    generate_button = ctk.CTkButton(
        password_generation_frame,
        text="Generate Password",
        command=lambda: generate_password_callback(
            length_entry.get(),
            include_uppercase.get(),
            include_numbers.get(),
            include_special_chars.get(),
            generated_password_entry
        )
    )
    generate_button.grid(row=8, column=0, columnspan=2, pady=10, sticky="n")

    # Copy Button
    def copy_to_clipboard():
        password = generated_password_entry.get()
        if password:  # Only copy if there's a password in the field
            master.clipboard_clear()
            master.clipboard_append(password)
            master.update()  # Ensures the clipboard content is updated
            ctk.CTkLabel(password_generation_frame, text="Password copied!").grid(row=9, column=0, columnspan=2, pady=5)

    copy_button = ctk.CTkButton(
        password_generation_frame,
        text="Copy Password",
        command=copy_to_clipboard
    )
    copy_button.grid(row=9, column=0, columnspan=2, pady=10, sticky="n")

    return password_generation_frame, generated_password_entry

# Password generation algorithm
def generate_password(length, include_uppercase, include_numbers, include_special_chars, generated_password_entry):
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
    generated_password_entry.configure(state="normal")  # Enable editing
    generated_password_entry.delete(0, 'end')  # Clear current value
    generated_password_entry.insert(0, password)  # Insert new password
    generated_password_entry.configure(state="disabled")  # Disable editing


# Explicit exports
__all__ = ["create_password_generation_frame", "generate_password"]