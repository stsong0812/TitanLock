import customtkinter as ctk
import re

# Function to create the password strength tab (frame)
def create_password_strength_frame(master, check_strength_callback):
    # Frame for the password strength checker
    password_strength_frame = ctk.CTkFrame(master)
    password_strength_frame.pack(fill="both", expand=True, padx=20, pady=20)

    # Configure grid weights for centering all content
    password_strength_frame.grid_rowconfigure(0, weight=1)  # Spacer above content
    password_strength_frame.grid_rowconfigure(1, weight=0)  # Content rows
    password_strength_frame.grid_rowconfigure(2, weight=0)
    password_strength_frame.grid_rowconfigure(3, weight=0)
    password_strength_frame.grid_rowconfigure(4, weight=0)
    password_strength_frame.grid_rowconfigure(5, weight=1)  # Spacer below content
    password_strength_frame.grid_columnconfigure(0, weight=1)  # Center content horizontally

    # Title Label
    password_strength_label = ctk.CTkLabel(
        password_strength_frame, 
        text="Password Strength Checker", 
        font=ctk.CTkFont(size=16, weight="bold")
    )
    password_strength_label.grid(row=1, column=0, pady=10, sticky="n")

    # Entry for entering a password to check its strength
    password_entry_strength = ctk.CTkEntry(password_strength_frame, placeholder_text="Enter password", show="*")
    password_entry_strength.grid(row=2, column=0, pady=10, sticky="ew", padx=100)  # Center entry field

    # Label to display the strength of the password
    strength_label = ctk.CTkLabel(password_strength_frame, text="Password strength: ", font=ctk.CTkFont(size=12))
    strength_label.grid(row=3, column=0, pady=10, sticky="n")

    # Bind the real-time strength-checking function
    password_entry_strength.bind("<KeyRelease>", lambda event: check_strength_callback(password_entry_strength.get(), strength_label))

    # Paragraph for guidance on password strength
    paragraph_text = (
        "This tool helps you check the strength of your master password, following recommendations from the "
        "National Institute of Standards and Technology (NIST) for memorized secrets in publication SP 800-63B:"
    )
    paragraph_label = ctk.CTkLabel(password_strength_frame, text=paragraph_text, wraplength=600, justify="center")
    paragraph_label.grid(row=4, column=0, pady=10, sticky="n")

    # Recommendations list based on NIST guidelines
    list_items = [
        "Use at least 12 characters (16+ is recommended for stronger security)",
        "Consider using a passphrase of random, unrelated words for memorability",
        "Avoid common words, predictable sequences, or personal information",
        "Ensure uniqueness – do not reuse a password used on other accounts",
        "Avoid patterns like '1234' or repetitive characters (e.g., 'aaaa')"
    ]

    # Frame for recommendations to center-align the list
    recommendations_frame = ctk.CTkFrame(password_strength_frame)
    recommendations_frame.grid(row=5, column=0, pady=10, sticky="n")
    recommendations_frame.grid_columnconfigure(0, weight=1)

    # Display each recommendation as a labeled bullet point
    for index, item in enumerate(list_items):
        list_item_label = ctk.CTkLabel(
            recommendations_frame, text=f"• {item}", anchor="w", wraplength=600, justify="left"
        )
        list_item_label.grid(row=index, column=0, padx=10, pady=2, sticky="w")

    return password_strength_frame, strength_label

# Function to check password strength
def check_password_strength(password, strength_label):
    score = 0

    # Password length check with scoring for additional length
    if len(password) >= 16:
        score += 3  # Strong score for longer passwords
    elif len(password) >= 12:
        score += 2
    elif len(password) >= 8:
        score += 1

    # Check if it contains multiple random, unrelated words (e.g., a passphrase)
    if re.search(r'(\w+\s+){2,}\w+', password):  # Checks for at least three words with spaces
        score += 2

    # Check for absence of common patterns or personal info
    common_patterns = ['password', '1234', 'abcd', 'qwerty', 'user', 'admin']
    if not any(pattern in password.lower() for pattern in common_patterns):
        score += 1

    # Check for character variety, though not strictly enforcing complexity
    if any(char.isupper() for char in password) and any(char.islower() for char in password):
        score += 1  # Includes both uppercase and lowercase for additional variety
    if any(char.isdigit() for char in password):
        score += 1  # Includes numbers
    if any(char in "!@#$%^&*(),.?\":{}|<>" for char in password):
        score += 1  # Includes special characters

    # Display password strength based on cumulative score
    if score >= 7:
        strength_label.configure(text="Password strength: Strong", text_color="green")
    elif 4 <= score < 7:
        strength_label.configure(text="Password strength: Moderate", text_color="orange")
    else:
        strength_label.configure(text="Password strength: Weak", text_color="red")