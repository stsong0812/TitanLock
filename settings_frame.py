from tkinter import Frame, Label, Entry, Checkbutton, BooleanVar, Button

def create_settings_frame(dark_mode_var, save_settings):
    settings_frame = Frame()
    settings_frame.pack(fill='both', expand=True)

    settings_label = Label(settings_frame, text="Settings")
    settings_label.pack(pady=10)

    # Enable dark mode checkbox, bound to the `dark_mode_var`
    dark_mode_check = Checkbutton(settings_frame, text="Enable Dark Mode", variable=dark_mode_var)
    dark_mode_check.pack(pady=5)

    master_password_label = Label(settings_frame, text="Set Master Password:")
    master_password_label.pack(pady=5)
    master_password_entry = Entry(settings_frame, show="*")
    master_password_entry.pack(pady=5)

    # Save settings when button is clicked
    save_button = Button(settings_frame, text="Save Settings", command=lambda: save_settings(dark_mode_var.get()))
    save_button.pack(pady=10)

    return settings_frame