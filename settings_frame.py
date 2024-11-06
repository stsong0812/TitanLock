from tkinter import Frame, Label, Scale, HORIZONTAL, Checkbutton, Button

def create_settings_frame(dark_mode_var, save_settings_callback, auto_lock_timeout):
    settings_frame = Frame()

    # Dark Mode Toggle
    dark_mode_label = Label(settings_frame, text="Enable Dark Mode")
    dark_mode_label.pack()
    dark_mode_checkbox = Checkbutton(settings_frame, variable=dark_mode_var)
    dark_mode_checkbox.pack()

    # Auto-Lock Timeout Slider
    auto_lock_label = Label(settings_frame, text="Auto-Lock Timeout (seconds)")
    auto_lock_label.pack()
    auto_lock_scale = Scale(settings_frame, from_=5, to=600, orient=HORIZONTAL)
    auto_lock_scale.set(auto_lock_timeout)
    auto_lock_scale.pack()

    # Save Button
    save_button = Button(settings_frame, text="Save Settings", command=lambda: save_settings_callback(
        dark_mode_var.get(),
        auto_lock_scale.get()
    ))
    save_button.pack()

    return settings_frame