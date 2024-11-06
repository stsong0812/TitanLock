from tkinter import Frame, Label, Entry, Checkbutton, Button, Checkbutton, Button, Scale, HORIZONTAL

def create_settings_frame(dark_mode_var, save_settings_callback, auto_lock_timeout):
    settings_frame = Frame()
    settings_frame.pack(fill='both', expand=True)

    settings_label = Label(settings_frame, text="Settings")
    settings_label.pack(pady=10)

    # Enable dark mode checkbox, bound to the `dark_mode_var`
    dark_mode_check = Checkbutton(settings_frame, text="Enable Dark Mode", variable=dark_mode_var)
    dark_mode_check.pack(pady=5)
    
    # Auto-Lock Timeout Slider
    auto_lock_label = Label(settings_frame, text="Auto-Lock Timeout (seconds)")
    auto_lock_label.pack()
    auto_lock_scale = Scale(settings_frame, from_=5, to=600, orient=HORIZONTAL)
    auto_lock_scale.set(auto_lock_timeout)
    auto_lock_scale.pack()

    master_password_label = Label(settings_frame, text="Set Master Password:")
    master_password_label.pack(pady=5)
    master_password_entry = Entry(settings_frame, show="*")
    master_password_entry.pack(pady=5)

    # Save settings when button is clicked
    save_button = Button(settings_frame, text="Save Settings", command=lambda: save_settings_callback(
        dark_mode_var.get(),
        auto_lock_scale.get()
    ))
    save_button.pack()

    return settings_frame