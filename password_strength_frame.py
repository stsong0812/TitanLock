from tkinter import Frame, Label, Entry, Button

# Fucntion to create password strenght tab (frame)
def create_password_strength_frame(check_strength_callback):
    # Demo strength checker used is in main.py
    password_strength_frame = Frame()
    password_strength_frame.pack(fill='both', expand=True)

    password_strength_label = Label(password_strength_frame, text="Enter a password to check its strength")
    password_strength_label.pack(pady=10)

    password_entry_strength = Entry(password_strength_frame, show="*")
    password_entry_strength.pack(pady=5)

    check_strength_button = Button(password_strength_frame, text="Check Strength", command=lambda: check_strength_callback(password_entry_strength.get()))
    check_strength_button.pack(pady=5)

    strength_label = Label(password_strength_frame, text="Password strength: ")
    strength_label.pack(pady=10)

    return password_strength_frame, strength_label