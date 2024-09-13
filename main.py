from tkinter import Tk, Toplevel, Label, Entry, Button, END, NORMAL, DISABLED
from tkinter import ttk
from passwords_frame import create_passwords_frame
from password_strength_frame import create_password_strength_frame
from password_generation_frame import create_password_generation_frame
from settings_frame import create_settings_frame

# Function to insert entry into the table
def add_entry(website, username, password):
    if website and username and password:
        tree.insert('', 'end', values=(website, username, password))

# Function to open an "add entry" window
def open_add_entry_window():
    new_window = Toplevel(root)     # Create new window
    new_window.title("Add New Entry")

    # Website field
    website_label = Label(new_window, text="Website:")
    website_label.pack(pady=5)
    website_entry = Entry(new_window)
    website_entry.pack(pady=5)

    # Username field
    username_label = Label(new_window, text="Username:")
    username_label.pack(pady=5)
    username_entry = Entry(new_window)
    username_entry.pack(pady=5)

    # Password field
    password_label = Label(new_window, text="Password:")
    password_label.pack(pady=5)
    password_entry = Entry(new_window, show="*")
    password_entry.pack(pady=5)

    # Submit button functionality
    def submit_new_entry():
        website = website_entry.get()
        username = username_entry.get()
        password = password_entry.get()
        add_entry(website, username, password)
        new_window.destroy()    # Close window

    submit_button = Button(new_window, text="Submit", command=submit_new_entry)
    submit_button.pack(pady=10)

# Include function to check password strength here:
def check_password_strength(password):
    # Simple placeholder function
    '''
    POSSIBLE PASSWORD STRENGHT LOGIC:
        - Using user input password as parameter:
            - Increase strenght depending on complexity
                - (Length, variety, etc...)
    '''
    if password:
        if len(password) < 5:
            strength_label.config(text="Password strength: Weak")
        elif len(password) < 10:
            strength_label.config(text="Password strength: Medium")
        else:
            strength_label.config(text="Password strength: Strong")
    else:
        strength_label.config(text="Please enter a password")

# Include function to generate passwords here:
def generate_password(length, include_uppercase, include_numbers, include_special_chars):
    # Password generation logic here
    '''
    POSSIBLE PASSWORD GENERATION LOGIC:
        - Import random library to randomize generated passwords
        - Import string for ascii lowercase, uppercase, digits, and special chars
        - Check if uppercase, numbers, special characters boolean varaibles are true
        - Initialize generated password variable with specified length
            - Use random library to randomize order of input parameters
    '''
    generated_password_entry.config(state=NORMAL)
    generated_password_entry.delete(0, END)
    generated_password_entry.insert(0, "GeneratedPassword123!")  # Placeholder text
    generated_password_entry.config(state=DISABLED)

# Create root window
root = Tk()
root.title('Titan Lock')
root.geometry('800x500')    # Set (width x height)

# Using notebook widget to create tabs
# https://www.tutorialspoint.com/notebook-widget-in-tkinter
notebook = ttk.Notebook(root)
notebook.pack(pady=10, expand=True, fill='both')

# Create different tabs (frames)
passwords_frame, tree = create_passwords_frame(notebook, open_add_entry_window)
password_strength_frame, strength_label = create_password_strength_frame(check_password_strength)
password_generation_frame, generated_password_entry = create_password_generation_frame(generate_password)
settings_frame = create_settings_frame()

notebook.add(passwords_frame, text='Passwords')
notebook.add(password_strength_frame, text='Password Strength')
notebook.add(password_generation_frame, text='Password Generation')
notebook.add(settings_frame, text='Settings')

# Include master key function
def open_master_key_window():
    # Demo master key window
    # Need to implement a "set master password" function
    '''
     POSSIBLE INITIAL MASTER KEY LOGIC:
        - Implement a "set master key" function on first program opening
        - Hash (using SHA256 algorithm) and store specified master key in a text file
            - Hashing can be done using the hashlib library
        - Let user enter the application

    POSSIBLE SUBSEQUENT MASTER KEY LOGIC:
        - Prompt user to input the master key
        - Hash the entered master key and compare to the one stored locally
        - If hashes match, user is verified and let user enter application
    '''
    master_key_window = Toplevel(root)
    master_key_window.title("Enter Master Key")
    master_key_window.geometry('800x500')

    master_key_label = Label(master_key_window, text="Enter Master Key:")
    master_key_label.pack(pady=10)

    master_key_entry = Entry(master_key_window, show="*")
    master_key_entry.pack(pady=5)

    # Function to validate key
    def validate_master_key():
        master_key = master_key_entry.get()
        if master_key:
            master_key_window.destroy()
            root.deiconify()

    submit_button = Button(master_key_window, text="Submit", command=validate_master_key)
    submit_button.pack(pady=10)

    root.withdraw()

# Main application loop
open_master_key_window()
root.mainloop()