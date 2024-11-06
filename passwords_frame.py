from tkinter import Frame, Label, Button, ttk

# Function to create passwords tab (frame)
def create_passwords_frame(notebook, add_entry_callback, remove_entry_callback, toggle_password_visibility):
    # Frame for managing passwords
    passwords_frame = Frame(notebook)
    passwords_frame.pack(fill='both', expand=True)

    # Label to describe the frame
    passwords_label = Label(passwords_frame, text="Passwords", font=("TkDefaultFont", 12, "bold"))
    passwords_label.pack(pady=10)

    # Treeview to display the stored passwords
    tree = ttk.Treeview(passwords_frame, columns=("Website", "Username", "Password"), show='headings')
    tree.heading("Website", text="Website")
    tree.heading("Username", text="Username")
    tree.heading("Password", text="Password")

    # Set column widths
    tree.column("Website", width=150)
    tree.column("Username", width=120)
    tree.column("Password", width=120)

    # Pack the treeview into the frame
    tree.pack(pady=10, fill='both', expand=True)

    # Button to add new password entries
    add_entry_button = Button(passwords_frame, text="Add New Entry", command=add_entry_callback)
    add_entry_button.pack(pady=10)

    # Button to remove selected password entries
    remove_entry_button = Button(passwords_frame, text="Remove Selected Entry", command=remove_entry_callback)
    remove_entry_button.pack(pady=10)
    
    # Button to show/hide passwords
    toggle_button = Button(passwords_frame, text="Show/Hide Passwords", command=toggle_password_visibility)
    toggle_button.pack(pady=10)

    return passwords_frame, tree