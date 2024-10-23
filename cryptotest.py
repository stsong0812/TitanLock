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
    #The encryption function starts by generating a random IV of 16 bytes
    iv = get_random_bytes(16) 
    #Then it creates a cipher object using the AES algorithim using the generated IV and the aes_key we derived from the master
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    #the plaintext is padded to the AES block size to compensate for  varying password lengths
    plainText_pad = pad(plaintext.encode(), AES.block_size)
    #the padded text is then encrypted using the cipher object relying on the encryption function in PyCryptodome
    cipherText = cipher.encrypt(plainText_pad)
    #The IV is then added to the beggining of the cipher for decryption,
    encrypted = iv + cipherText
    #then the final encrypted text is encoded in Base64 and returned as a string
    return base64.b64encode(encrypted).decode('utf-8')

# Decrypt an AES-CBC encrypted message
def decrypt(aes_key, encryptedText):
    #The decryption function starts by decoding the encrypted text
    encryptedText = base64.b64decode(encryptedText)
    #the IV is then seperated from the decoded data, the encryption function adds it to the beggining of the password so we seperate the first 16 bytes
    iv = encryptedText[:16]
    #the ciphered text is then seperated from the IV into its own object
    cipherText = encryptedText[16:]
    #The cipher object is created using the IV we seperated from the encrypted password,
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    #The cipher is decrypted using the cipher object, and then it is unpadded
    decrypted = unpad(cipher.decrypt(cipherText), AES.block_size)
    #The password is then decoded and returned in the form of plaintext as a string
    return decrypted.decode('utf-8')

