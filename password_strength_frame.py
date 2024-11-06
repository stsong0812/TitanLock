from tkinter import Frame, Label, Entry, Button

# Function to create password strength tab (frame)
def create_password_strength_frame(check_strength_callback):
    # Frame for password strength checker
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

    # Updated introductory paragraph for master password guidance
    paragraph_text = (
        "This tool helps you check the strength of your master password, following recommendations from the "
        "National Institute of Standards and Technology (NIST) for memorized secrets in publication SP 800-63B:"
    )
    paragraph_label = Label(password_strength_frame, text=paragraph_text, wraplength=500, justify="left")
    paragraph_label.pack(pady=10)

    # Updated list items based on NIST recommendations for master passwords
    list_items = [
        "Use at least 12 characters (16+ is recommended for stronger security)",
        "Consider using a passphrase of random, unrelated words for memorability",
        "Avoid common words, predictable sequences, or personal information",
        "Ensure uniqueness – do not reuse a password used on other accounts",
        "Avoid patterns like '1234' or repetitive characters (e.g., 'aaaa')"
    ]

    # Display each suggestion as a labeled bullet point
    for item in list_items:
        list_item_label = Label(password_strength_frame, text=f"• {item}", anchor="w", justify="left")
        list_item_label.pack(anchor="w", padx=165)

    return password_strength_frame, strength_label