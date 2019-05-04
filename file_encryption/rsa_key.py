"""
@author: Team PEMDAS
"""
import os.path
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import requests
from base64 import b64encode

# Global Constants
CONST_PUBLIC_EXPONENT = 65537
CONST_KEY_LENGTH = 2048
CONST_KEY_PUBLIC_PATH = "rsa_key_public.pem"
CONST_KEY_PRIVATE_PATH = "rsa_key_private.pem"
CONST_API = "https://pemdas.me/api/keys"
CONST_API_KEY = "pemdascecs378"

def main():
    if not haskeys():
        keygen()

def haskeys():
    # Check for rsa_key_public.pem and rsa_key_private.pem in program root dir
    if not os.path.isfile(CONST_KEY_PUBLIC_PATH):
        print("Missing keys.")
        print("[!] Keys will be generated [!]")
        return False
    else:
        print("Public and Private keys exist.")
        return True

def keygen(): 
    #################
    ## PRIVATE KEY ##
    #################
    # Generate new RSA private key with given backend, e, and key size.
    key_private = rsa.generate_private_key(
        public_exponent = CONST_PUBLIC_EXPONENT,
        key_size = CONST_KEY_LENGTH,
        backend = default_backend()
    )
    
    # Serialize private key without encryption.
    pem_private = key_private.private_bytes(
        encoding = serialization.Encoding.PEM, 
        format = serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm = serialization.NoEncryption()
    )
    
    ################
    ## PUBLIC KEY ##
    ################
    # Generate new RSA public key using private key.
    key_public = key_private.public_key()
    
    # Serialize public key
    pem_public = key_public.public_bytes(
        encoding = serialization.Encoding.PEM,
        format = serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    
    ################
    ## POST  KEYS ##
    ################
    post_data = {}
    # Load data into collection
    post_data["private"] = b64encode(pem_private).decode("utf-8")
    post_data["public"] = b64encode(pem_public).decode("utf-8")
    post_data["secretKey"] = CONST_API_KEY
    
    # Make POST request
    r = requests.post(CONST_API, 
                      json=post_data)
    print(r.status_code)
    
    # Write serialized key into file
    with open(CONST_KEY_PUBLIC_PATH, 'wb') as file:
        file.write(pem_public)
        file.close()
        
    

if __name__ == "__main__": main()