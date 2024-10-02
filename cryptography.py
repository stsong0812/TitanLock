from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import base64


#derive an aes key from the user provided masterKey
def derivedAESKey(masterKey):
    masterKey = masterKey.encode() if isinstance(masterKey, str) else masterKey 
    aes_key = SHA256.new(masterKey).digest()
    return aes_key

#function to load the stored aes_key from the created key file
def loadKey():
    try:
        with open("key.bin", "rb") as keyFile:
            return keyFile.read()
    except FileNotFoundError:
        return None

#function to create the master aes key used for decryption, simply pass the entered master key to this function
def createMasterKey(masterKey):
    storedKey = loadKey()
    if not storedKey:
        aes_key = derivedAESKey(masterKey)
        with open("key.bin", "wb") as keyFile:
            keyFile.write(aes_key)

# Encrypt a plaintext message using AES-CBC
def encrypt(aes_key, plaintext):
    iv = get_random_bytes(16) 
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    plainText_pad = pad(plaintext.encode(), AES.block_size)
    cipherText = cipher.encrypt(plainText_pad)
    encrypted = iv + cipherText
    return base64.b64encode(encrypted).decode('utf-8')

# Decrypt an AES-CBC encrypted message
def decrypt(aes_key, encryptedText):
    encryptedText = base64.b64decode(encryptedText)
    iv = encryptedText[:16]
    cipherText = encryptedText[16:]
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    decrypted = unpad(cipher.decrypt(cipherText), AES.block_size)
    return decrypted.decode('utf-8')

