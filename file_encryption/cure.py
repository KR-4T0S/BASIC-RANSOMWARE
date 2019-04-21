"""
@author: Team PEMDAS
"""

import os
import json
import time
import rsa_key
import file_decryption as dec
from base64 import b64decode

# Global Constants
CONST_KEY_PUBLIC_PATH = "rsa_key_public.pem"
CONST_KEY_PRIVATE_PATH = "rsa_key_private.pem"
CONST_SRC_ENC = "file_encryption.py"
CONST_SRC_DEC = "file_decryption.py"
CONST_SRC_KEYGEN = "rsa_key.py"
CONST_SRC_RANSOMWARE = "ransomware.py"
CONST_SRC_CURE = "cure.py"
CONST_SRC_EXE_ENC = "ransomware.exe"
CONST_SRC_EXE_DEC = "cure.exe"
CONST_FOLDER_CACHE = "__pycache__"
CONST_FOLDER_BUILD = "build"

def main():
    # Simple prompt
    print("..~~**~~..~~**~~..~~**~~..~~**~~..")
    print("Fine, you'll get your files back.")
    print("..~~**~~..~~**~~..~~**~~..~~**~~..")
    
    # Check for RSA keys if exist. Else generate.
    rsa_key.main()
    
    # Start walk (decrypt)
    walk_dec()
    time.sleep(10)

def walk_dec():
     # Begin file walk
    rootDir = "." # Root is where program starts
    exclude = [CONST_FOLDER_CACHE, CONST_FOLDER_BUILD]
    for dirName, subdirList, fileList in os.walk(rootDir):
        subdirList[:] = [d for d in subdirList if d not in exclude]
        # Get directory names for debugging
        print("[+] %s" % dirName)
        
        for file_name in fileList:
            
            # Contactenate file info into a path
            file_path = os.path.join(dirName, file_name)
            
            if ( not file_name in 
                [CONST_KEY_PUBLIC_PATH, 
                 CONST_KEY_PRIVATE_PATH,
                 CONST_SRC_ENC,
                 CONST_SRC_DEC,
                 CONST_SRC_KEYGEN,
                 CONST_SRC_RANSOMWARE,
                 CONST_SRC_CURE,
                 CONST_SRC_EXE_ENC,
                 CONST_SRC_EXE_DEC] ):
                    # Get file names for debugging
                    print("[*] %s" % file_path)
                    
                    # Open JSON File and read data
                    with open(file_path, "r", encoding="utf-8") as file:
                        file_data = json.load(file)
                        file.close()
                    
                    # Grab data
                    RSACipher = b64decode(file_data["RSACipher"])
                    C = b64decode(file_data["C"])
                    IV = b64decode(file_data["IV"])
                    tag = b64decode(file_data["tag"])
                    ext = file_data["ext"]

                    # Decrypt
                    M = dec.MyRSADecrypt(RSACipher, C, IV, tag, ext, CONST_KEY_PRIVATE_PATH)
                    
                    # Re-Create original file
                    name, extension = os.path.splitext(file_name)
                    file_name_new = name + ext
                    with open(file_name_new, "wb") as file:
                        file.write(M)
                        file.close()
                    
                    # Delete encrypted file
                    os.remove(file_path)
                    
if __name__ == "__main__": main()