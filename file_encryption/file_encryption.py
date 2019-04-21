"""
@author: Team PEMDAS
"""
import os
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

def MyRSAEncrypt(filepath, RSA_Publickey_filepath):
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