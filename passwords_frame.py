from tkinter import Frame, Label, Button, ttk
from tkinter.messagebox import showwarning

# Function to create passwords tab (frame)
def create_passwords_frame(notebook, add_entry_callback, remove_entry_callback, toggle_password_visibility):
    # Still need to implement password masking / password revealing
    passwords_frame = Frame(notebook)
    passwords_frame.pack(fill='both', expand=True)

    passwords_label = Label(passwords_frame, text="Manage your passwords here")
    passwords_label.pack(pady=10)

    tree = ttk.Treeview(passwords_frame, columns=("Website", "Username", "Password"), show='headings')
    tree.heading("Website", text="Website")
    tree.heading("Username", text="Username")
    tree.heading("Password", text="Password")

    tree.column("Website", width=150)
    tree.column("Username", width=120)
    tree.column("Password", width=120)

    tree.pack(pady=10, fill='both', expand=True)

    add_entry_button = Button(passwords_frame, text="Add New Entry", command=add_entry_callback)
    add_entry_button.pack(pady=10)

    remove_entry_button = Button(passwords_frame, text="Remove Selected Entry", command=remove_entry_callback)
    remove_entry_button.pack(pady=10)
    
    # Add a Show/Hide Passwords button
    toggle_button = Button(passwords_frame, text="Show/Hide Passwords", command=toggle_password_visibility)
    toggle_button.pack(pady=10)

    return passwords_frame, tree