import secrets
#using secrets instead of random bc it's more secure
import string

def generate_password():
    length = secrets.choice(range(8, 13))  # Randomly choose password length between 8 and 12
    characters = string.ascii_letters + string.digits + string.punctuation
    password = ''.join(secrets.choice(characters) for _ in range(length))
    return password

# Generate a password
print("Generated Password:", generate_password())
