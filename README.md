# TitanLock

(Group Members) 

    - Steven Song
    - Alexandru Gonzales
    - Davil Gizean

(Primary Language) Python

(Third-Party Libraries) 

    - customtkinter - For enhanced and modern Tkinter UI components.
    - cryptography.fernet - For secure encryption and decryption.
    - argon2 - For password hashing and verification.

(Summary) A centralized password manager that utilizes a simple and easy to use GUI. TitanLock not only securely stores passwords, but test and generates them.
The app contains four tabs which include the passwords tab, password strength tab, password generation tab, and settings tab. The main components of the application include, masterkey hashing and storage, password encryption and storage, password strength checking, and password generation. Currently the only supported version is for Unix systems.

(Requirements) On Unix System:

    - pip install customtkinter
    - pip install cryptography
    - pip install argon2-cffi

(How to Use) Using the source files, run the python script with the command (using sudo):

    sudo python3 main.py