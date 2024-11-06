from tkinter import Frame, Label, Entry, Button

# Function to create password strength tab (frame)
def create_password_strength_frame(check_strength_callback):
    # Frame for password strength checker
    password_strength_frame = Frame()
    password_strength_frame.pack(fill='both', expand=True)

    # Label for instruction
    password_strength_label = Label(password_strength_frame, text="Enter a password to check its strength")
    password_strength_label.pack(pady=10)

    # Entry for entering password to check strength
    password_entry_strength = Entry(password_strength_frame, show="*")
    password_entry_strength.pack(pady=5)

    # Label to display the strength of the password
    strength_label = Label(password_strength_frame, text="Password strength: ")
    strength_label.pack(pady=10)

    # Bind the real-time strength-checking function
    password_entry_strength.bind("<KeyRelease>", lambda event: check_strength_callback(password_entry_strength.get(), strength_label))

    # Introductory paragraph for guidance
    paragraph_text = (
        "This tool helps you check the strength of your master password, following recommendations from the "
        "National Institute of Standards and Technology (NIST) for memorized secrets in publication SP 800-63B:"
    )
    paragraph_label = Label(password_strength_frame, text=paragraph_text, wraplength=500, justify="left")
    paragraph_label.pack(pady=10, padx=20)

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
        list_item_label = Label(password_strength_frame, text=f"• {item}", anchor="w", justify="left", wraplength=500)
        list_item_label.pack(anchor="w", padx=165, pady=2)

    return password_strength_frame, strength_label