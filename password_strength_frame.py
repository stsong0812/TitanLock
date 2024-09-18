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

    paragraph_text = ('This tool helps you check the strength of your password loosely following password guidelines outlined by the National Institute of Security and Technology:')
    paragraph_label = Label(password_strength_frame, text=paragraph_text, wraplength=500, justify="left")
    paragraph_label.pack(pady=10)


    # Unordered list items
    list_items = [
        "At least 8 characters long",
        "Includes both uppercase and lowercase letters",
        "Contains numbers",
        "Includes special characters (e.g., !, @, #, etc.)",
        "Avoid common phrases and passwords"
    ]

    # Add list items as labels with a bullet
    for item in list_items:
        list_item_label = Label(password_strength_frame, text=f"• {item}", anchor="w", justify="left")
        list_item_label.pack(anchor="w", padx=250)

    return password_strength_frame, strength_label