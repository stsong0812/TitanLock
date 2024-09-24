import os
import re

def load_file(filename):
    # Load the content of a file and return it as a list of lines.
    try:
        with open(filename, 'r') as file:
            content = file.readlines()
        return content
    except FileNotFoundError:
        print(f"Error: The file '{filename}' was not found.")
        return []

def print_file_content(content):
    # Print the content of the file with line numbers.
    if not content:
        print("No content to display.")
        return
    
    for index, line in enumerate(content):
        print(f"{index + 1}: {line.strip()}")

def choose_option(content):
    # Ask the user to choose a line and return the selected line.
    while True:
        try:
            choice = int(input("Enter the number of the line you want to test: "))
            if 1 <= choice <= len(content):
                return content[choice - 1].strip()
            else:
                print("Invalid choice. Please enter a valid line number.")
        except ValueError:
            print("Invalid input. Please enter a number.")

def test_password_strength(password):
    # Test the strength of the password and return a score.
    score = 0
    
    # Check length
    if len(password) >= 8:
        score += 1
    if len(password) >= 12:
        score += 1
    
    # Check for uppercase letters
    if re.search(r'[A-Z]', password):
        score += 1
    
    # Check for lowercase letters
    if re.search(r'[a-z]', password):
        score += 1
    
    # Check for digits
    if re.search(r'[0-9]', password):
        score += 1
    
    # Check for special characters
    if re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        score += 1

    # Check for common passwords (simple example)
    common_passwords = ["password", "123456", "123456789", "qwerty", "abc123"]
    if password.lower() in common_passwords:
        score -= 2  # Deduct points for common passwords
    
    return score

def main():
    # Dynamically determine the path to the file in the same directory as the script
    script_dir = os.path.dirname(__file__)  # Get the directory of the script
    file_path = os.path.join(script_dir, 'storage.txt')  # File is in the same directory
    
    content = load_file(file_path)
    
    if not content:
        return
    
    print("File content:")
    print_file_content(content)
    
    selected_password = choose_option(content)
    
    print(f"\nYou chose the following password to test:\n{selected_password}")
    
    score = test_password_strength(selected_password)
    print(f"\nPassword strength score: {score}/7")
    
    # Interpretation of the score
    if score == 7:
        print("Excellent password!")
    elif score >= 5:
        print("Strong password.")
    elif score >= 3:
        print("Moderate password.")
    else:
        print("Weak password. Consider using a longer and more complex password.")

if __name__ == "__main__":
    main()