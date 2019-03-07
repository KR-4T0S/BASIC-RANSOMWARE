"""
@author: Team PEMDAS
"""
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding, hmac, hashes

# Global Constants
CONST_LEN_KEY = 32
CONST_LEN_IV = 16
CONST_LEN_BLOCK = 128

def main():
    C, IV, tag, key, HMACKey, ext = MyfileEncrypt("2dd.jpg")
    MyfileDecrypt(C, IV, tag, key, HMACKey, ext)

def Myencrypt(message, key, HMACKey):
    # Prompt error if key < 32 bytes
    if len(key) < CONST_LEN_KEY:
        print("[!] Error. Key must be 32 bytes. Try again. [!]")
        return None, None
    else:
        # Generate random 16 Bytes IV
        IV = os.urandom(CONST_LEN_IV)
        
        # Padding for CBC
        padder = padding.PKCS7(CONST_LEN_BLOCK).padder()
        paddedMessage = padder.update(message) + padder.finalize()
        
        # Start cipher with key and IV
        cipher = Cipher(algorithms.AES(key), 
                        modes.CBC(IV), 
                        default_backend())
        encryptor = cipher.encryptor()
        C = encryptor.update(paddedMessage) + encryptor.finalize()
        
        # Generate tag from HMAC key and using SHA256
        tag = hmac.HMAC(HMACKey,
                  hashes.SHA256(), 
                  default_backend())
        tag.update(C)
        tag = tag.finalize()
        
        return (C, IV, tag)

def Mydecrypt(C, IV, tag, key, HMACKey):
    # Prompt error if key < 32 bytes
    if len(key) < CONST_LEN_KEY:
        print("[!] Error. Key must be 32 bytes. Try again. [!]")
        return None
    else:
        # Tag check using SHA256
        tagCheck = hmac.HMAC(HMACKey, 
                             hashes.SHA256(), 
                             default_backend())
        tagCheck.update(C)
        tagCheck.verify(tag)
        
        # Start cipher with key and IV
        cipher = Cipher(algorithms.AES(key), 
                        modes.CBC(IV), 
                        default_backend())
        
        # Decrypt
        decryptor = cipher.decryptor()
        paddedMessage = decryptor.update(C) + decryptor.finalize()
        
        # Unpad the decrypted bytes
        unpadder = padding.PKCS7(CONST_LEN_BLOCK).unpadder()
        M = unpadder.update(paddedMessage) + unpadder.finalize()
        
        return (M)

def MyfileEncrypt(filepath):
    # Generate Key and IV
    key = os.urandom(CONST_LEN_KEY)
    HMACKey = os.urandom(CONST_LEN_KEY)
    
    # Get file extension
    name, ext = os.path.splitext(filepath)
    
    # Open File
    mode = "rb" # Set to read bits
    with open(filepath, mode) as file:
        M = file.read()
        file.close()
    
    # Encrypt string file data
    C, IV, tag = Myencrypt(M, key, HMACKey)
    
    return (C, IV, tag, key, HMACKey, ext)

def MyfileDecrypt(C, IV, tag, key, HMACKey, ext):
    # Call encryption for entire message, CBC does block cipher on its own.
    M = Mydecrypt(C, IV, tag, key, HMACKey)
    
    # Temp file name and string
    newFile = "temp" + ext
    
    # Write file
    mode = "wb" # Set to read bits
    with open(newFile, mode) as file:
        file.write(M)
        file.close()

if __name__ == "__main__": main()