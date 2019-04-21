"""
@author: Team PEMDAS
"""
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

def MyfileDecrypt(C, IV, tag, key, HMACKey, ext):
    # Call encryption for entire message, CBC does block cipher on its own.
    M = Mydecrypt(C, IV, tag, key, HMACKey)
    
    return (M)
        
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
    M = MyfileDecrypt(C, IV, tag, key_enc, key_HMAC, ext)
    
    return (M)