#!/usr/bin/env python3

import base64
import os
import argparse
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

def encrypt(key, text):
    iv = get_random_bytes(AES.block_size)
    cipher = AES.new(key,AES.MODE_CBC , iv)
    padded_text = pad(text, AES.block_size)
    encryption = base64.b64encode(cipher.encrypt(padded_text))
    return encryption, iv

def decrypt(key, encrypted_text, iv):
    try:
        cipher = AES.new(key , AES.MODE_CBC , iv)
        decrypted = cipher.decrypt(base64.b64decode(encrypted_text))
        decrypted_text = unpad(decrypted, AES.block_size)
        return decrypted_text
    except :
        print("Wrong Password")
        exit()

def traverse(drive):
    req_files = []
    for root,_,files in os.walk(drive):
        for file_name in files:
            file_path = os.path.join(root, file_name)
            req_files.append(file_path)
    return req_files

def encryptor(file , key):
    with open(file , "rb") as f:
        file_contents = f.read()

    encrypted_file_contents, iv = encrypt(key , file_contents)

    with open(file , "wb") as f:
        f.write(iv + encrypted_file_contents)

def decryptor(file , key):
    with open(file , "rb") as f:
        file_contents = f.read()
    iv = file_contents[:AES.block_size]
    file_contents = file_contents[AES.block_size:]
    decrypted_contents = decrypt(key, file_contents, iv)

    with open(file , "wb") as f:
        f.write(decrypted_contents)

def main():
    parser = argparse.ArgumentParser(description=" *** Script To Encrypt Or Decrypt a Drive ***")
    parser.add_argument("--encrypt", type=str , help="Encrypts the drive")
    parser.add_argument("--decrypt" , type=str ,help="Decrypts the drive")
    parser.add_argument("-p", "--password", type=str , required=True , help="Password")
    args = parser.parse_args()
    
    if args.encrypt and args.decrypt:
        print("Cannot Encrypt and Decrypt same time")
        exit(1)

    password = args.password
    key = hashlib.sha256(password.encode()).digest()
    if not os.path.exists(args.encrypt or args.decrypt):
        print("Path Doesnt Exists")
        exit(1)

    files_found = traverse(args.encrypt or args.decrypt)
    if args.encrypt:
        for file in files_found:
            encryptor(file , key)
            print(f"Encrypted -> {file}")
    if args.decrypt:
        for file in files_found:
            decryptor(file, key)
            print(f"Decrypted -> {file}")

if __name__ == "__main__":
    main()
