"""
@author: Team PEMDAS
"""
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding

# Global Constants
CONST_LEN_KEY = 32
CONST_LEN_IV = 16
CONST_LEN_BLOCK = 128

def main():
    # Testing encrypt and decrypt w/random message bytes and random key
    key = b'asdasdasdasdasdasdasdasdasdasdas' # valid key
    msg = b'this is a RANDOM message'
    
    # Init encrypt/decrypt
    cipher, iv = Myencrypt(msg, key) # First encrypt
    message = Mydecrypt(cipher, iv, key) # Then decrypt
    
    print(msg) # Print original message (binary)
    print()
    print(cipher) # Print encrypted message
    print()
    print(message) # Print decrypted message

def Myencrypt(message, key):
    # Prompt error if key < 32 bytes
    print("Key length: " + str(len(key)))
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
        
        # Return Cipher (C) and Initialization Vector (IV)
        return (C, IV)

def Mydecrypt(C, IV, key):
    if len(key) < CONST_LEN_KEY:
        print("[!] Error. Key must be 32 bytes. Try again. [!]")
        return None
    else:
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
        
        # Return plaintext message (M)
        return M
    
if __name__ == "__main__": main()