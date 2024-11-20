from tkinter import Frame, Label, Entry, Checkbutton, BooleanVar, Button
import string
import secrets
from tkinter.messagebox import showwarning

# Function to create password generation tab (frame)
def create_password_generation_frame(generate_password_callback):
    password_generation_frame = Frame()
    password_generation_frame.pack(fill='both', expand=True)

    password_generation_label = Label(password_generation_frame, text="Password Generator", font=("TkDefaultFont", 12, "bold"))
    password_generation_label.pack(pady=10)

    length_label = Label(password_generation_frame, text="Password Length (6-20 characters):")
    length_label.pack(pady=5)
    length_entry = Entry(password_generation_frame)
    length_entry.pack(pady=5)

    include_uppercase = BooleanVar(value=True)
    include_numbers = BooleanVar(value=True)
    include_special_chars = BooleanVar(value=True)

    paragraph_text = ('At least one of the following must be checked (All 3 are recommended):')
    paragraph_label = Label(password_generation_frame, text=paragraph_text, wraplength=500, justify="left")
    paragraph_label.pack(pady=10)

    uppercase_check = Checkbutton(password_generation_frame, text="Include Uppercase Letters", variable=include_uppercase)
    uppercase_check.pack(pady=2)
    numbers_check = Checkbutton(password_generation_frame, text="Include Numbers", variable=include_numbers)
    numbers_check.pack(pady=2)
    special_chars_check = Checkbutton(password_generation_frame, text="Include Special Characters", variable=include_special_chars)
    special_chars_check.pack(pady=2)

    generated_password_entry = Entry(password_generation_frame, state='disabled')
    generated_password_entry.pack(pady=5)

    # Modify the command to pass generated_password_entry to generate_password
    generate_button = Button(password_generation_frame, text="Generate Password", command=lambda: generate_password_callback(
        length_entry.get(), include_uppercase.get(), include_numbers.get(), include_special_chars.get(), generated_password_entry
    ))
    generate_button.pack(pady=10)

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
    generated_password_entry.config(state='normal')  # Allow editing
    generated_password_entry.delete(0, 'end')  # Clear current value
    generated_password_entry.insert(0, password)  # Insert new password
    generated_password_entry.config(state='disabled')  # Disable editing