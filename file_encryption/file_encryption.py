"""
@author: Team PEMDAS
"""
import os
import rsa_key
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding, hmac, hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding as asympadding

# Global Constants
CONST_LEN_KEY = 32
CONST_LEN_IV = 16
CONST_LEN_BLOCK = 128
CONST_KEY_PUBLIC_PATH = "rsa_key_public.pem"
CONST_KEY_PRIVATE_PATH = "rsa_key_private.pem"

def main():
    RSACipher, C, IV, tag, ext = MyRSAEncrypt("2dd.jpg", CONST_KEY_PUBLIC_PATH)
    MyRSADecrypt(RSACipher, C, IV, tag, ext, CONST_KEY_PRIVATE_PATH)
    

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
    
    # Write encrypted file
    new_name = name + "_enc" + ext
    with open(new_name, 'wb') as file:
        file.write(C)
    
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

def MyRSAEncrypt(filepath, RSA_Publickey_filepath):
    # Check for RSA keys if exist. Else generate.
    rsa_key.main()
    
    # File encryption
    C, IV, tag, key_enc, key_HMAC, ext = MyfileEncrypt(filepath)
    
    # Get pub key from pem file
    mode = "rb" # Set to read bits
    with open(RSA_Publickey_filepath, mode) as file:
        key_pub = serialization.load_pem_public_key(
                    file.read(),
                    backend = default_backend()
                )
    
    # Concatenate encryption key with HMAC key
    key_rsa = key_enc + key_HMAC
    
    # Encrypt concatenated keys
    RSACipher = key_pub.encrypt(
                key_rsa,
                asympadding.OAEP(
                    mgf = asympadding.MGF1(
                            algorithm=hashes.SHA256()
                            ),
                    algorithm = hashes.SHA256(),
                    label = None
                )
            )
    
    return RSACipher, C, IV, tag, ext

def MyRSADecrypt(RSACipher, C, IV, tag, ext, RSA_Privatekey_filepath):
    # Get priv key from pem file
    mode = "rb" # Set to read bits
    with open(RSA_Privatekey_filepath, mode) as file:
        key_priv = serialization.load_pem_private_key(
                    file.read(),
                    password = None,
                    backend = default_backend()
                )
    
    # Decrypt RSACipher
    key_rsa = key_priv.decrypt(
                RSACipher,
                asympadding.OAEP(
                    mgf = asympadding.MGF1(
                            algorithm=hashes.SHA256()
                            ),
                    algorithm = hashes.SHA256(),
                    label = None
                )
            )
    
    # Get Enc Key and HMAC Key from RSA Key [key_enc + key_HMAC]
    key_enc = key_rsa[:CONST_LEN_KEY]
    key_HMAC = key_rsa[CONST_LEN_KEY:]
    
    # Decrypt file
    MyfileDecrypt(C, IV, tag, key_enc, key_HMAC, ext)

if __name__ == "__main__": main()