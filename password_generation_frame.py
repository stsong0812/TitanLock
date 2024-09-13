from tkinter import Frame, Label, Entry, Checkbutton, BooleanVar, Button

# Function to create password tab (frame)
def create_password_generation_frame(generate_password_callback):
    # Currently holds demo logic for checkboxes 
    password_generation_frame = Frame()
    password_generation_frame.pack(fill='both', expand=True)

    password_generation_label = Label(password_generation_frame, text="Generate a password here")
    password_generation_label.pack(pady=10)

    length_label = Label(password_generation_frame, text="Password Length:")
    length_label.pack(pady=5)
    length_entry = Entry(password_generation_frame)
    length_entry.pack(pady=5)

    include_uppercase = BooleanVar()
    include_numbers = BooleanVar()
    include_special_chars = BooleanVar()

    uppercase_check = Checkbutton(password_generation_frame, text="Include Uppercase Letters", variable=include_uppercase)
    uppercase_check.pack(pady=2)
    numbers_check = Checkbutton(password_generation_frame, text="Include Numbers", variable=include_numbers)
    numbers_check.pack(pady=2)
    special_chars_check = Checkbutton(password_generation_frame, text="Include Special Characters", variable=include_special_chars)
    special_chars_check.pack(pady=2)

    generate_button = Button(password_generation_frame, text="Generate Password", command=lambda: generate_password_callback(length_entry.get(), include_uppercase.get(), include_numbers.get(), include_special_chars.get()))
    generate_button.pack(pady=10)

    generated_password_entry = Entry(password_generation_frame, state='disabled')
    generated_password_entry.pack(pady=5)

    return password_generation_frame, generated_password_entry