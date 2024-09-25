from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import base64

#THIS IS INCOMPLETE AND MUST BE FINISHED!!!!!!!!! 
#Dont use the functions defined in this file untill I remove these comments and confirm functionality on my local machine

# Encrypt a plaintext message using AES-CBC
def encrypt(tempKey, plaintext):
    iv = get_random_bytes(16)  # Generate a random IV
    cipher = AES.new(tempKey, AES.MODE_CBC, iv)
    plainText_pad = pad(plaintext.encode(), AES.block_size)
    cipherText = cipher.encrypt(plainText_pad)
    encrypted = iv + cipherText
    return base64.b64encode(encrypted).decode('utf-8')  # Return as Base64 encoded string

# Decrypt an AES-CBC encrypted message
def decrypt(tempKey, encryptedText):
    try:
        encryptedText = base64.b64decode(encryptedText)  # Decode from Base64
        iv = encryptedText[:16]  # Extract IV from the first 16 bytes
        cipherText = encryptedText[16:]  # Extract the actual ciphertext
        cipher = AES.new(tempKey, AES.MODE_CBC, iv)
        decrypted = unpad(cipher.decrypt(cipherText), AES.block_size)
        return decrypted.decode('utf-8')
    except (ValueError, KeyError) as e:
        print(f"Decryption error: {e}")
        return None
