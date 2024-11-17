#!/usr/bin/env python3

import base64
import pickle
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import hashlib
import os
from getpass import getpass
import random

def encrypt(key, text):
    cipher = AES.new(key, AES.MODE_ECB)
    padded_text = pad(text.encode(), AES.block_size)
    encryption = base64.b64encode(cipher.encrypt(padded_text))
    return encryption.decode()

def decrypt(key, encrypted_text):
    cipher = AES.new(key, AES.MODE_ECB)
    decrypted = cipher.decrypt(base64.b64decode(encrypted_text.encode()))
    decrypted_text = unpad(decrypted, AES.block_size).decode()
    return decrypted_text

def create_password():
    # Creating a more diverse set of characters
    chars = [chr(i) for i in range(65, 91)] + [chr(i) for i in range(97, 123)] + ["!", "@", "#", "$", "%", "^", "&", "*", "(", ")", "_", "-", "="] + [str(i) for i in range(10)]
    password = "".join(random.choices(chars, k=20))
    print(f"Password created is -> {password}")
    return password

def store(key):
    url = input("Enter the URL (optional) -> ") or "uu"
    username = input("Enter the USERNAME -> ")
    password = input("Enter the PASSWORD -> ") or create_password()
    field = input("Enter optional text -> ") or "ff"

    info = [url, username, password, field]
    for i in range(len(info)):
        info[i] = encrypt(key, info[i])

    # Store the encrypted data
    with open("password.bin", "ab") as file:
        pickle.dump(info, file)
    print("[+] Record Saved!")

def show(key):
    try:
        with open("password.bin", "rb") as file:
            while True:
                try:
                    info = pickle.load(file)
                    for i in range(len(info)):
                        info[i] = decrypt(key, info[i])

                    info[0] = " " if info[0] == "uu" else info[0]
                    print(f"URL => {info[0]}")
                    print(f"USERNAME => {info[1]}")
                    print(f"PASSWORD => {info[2]}")
                    info[3] = " " if info[3] == "ff" else info[3]
                    print(f"EXTRA INFO => {info[3]}")
                    print("-" * 40)
                except EOFError:
                    break
    except FileNotFoundError:
        print("[!] No Passwords were Saved before ")
        exit()

def delete(key):
    try:
        with open("password.bin", "rb") as file:
            infos = []
            while True:
                try:
                    infos.append(pickle.load(file))
                except EOFError:
                    break
    except FileNotFoundError:
        print("[!] No Passwords were Saved before ")
        exit()

    username = input("Enter the username -> ")
    password = input("Enter the password -> ")

    for i in range(len(infos)):
        for j in range(len(infos[i])):
            infos[i][j] = decrypt(key, infos[i][j])

    for i in range(len(infos)):
        if username in infos[i] and password in infos[i]:
            print("[*] Record Found")
            choice = input("Do you want to delete? (y/N) -> ")
            if choice.lower() != "n":
                del infos[i]
                print("[*] Record Deleted")
            else:
                print("[*] Record Not Deleted")
            break
    else:
        print("[!] No Record Found!")

    # Write the remaining records back to the file
    with open("password.bin", "wb") as file:
        for info in infos:
            pickle.dump(info, file)

def set_password():
    password1 = getpass("Enter a password for password manager -> ")
    password2 = getpass("Enter the password again -> ")
    if password1 != password2:
        print("[!] Passwords do not match.")
        exit()

    key = hashlib.sha256(password2.encode()).digest()
    try:
        with open("dump.bin", "wb") as file:
            pickle.dump(key, file)
        print("[+] Password Created")
    except:
        print("[!] Error occurred during creating a password saving file!")

def check_password(password):
    try:
        with open("dump.bin", "rb") as file:
            key = pickle.load(file)
        return hashlib.sha256(password.encode()).digest() == key
    except FileNotFoundError:
        return False

def menu(key):
    key = hashlib.sha256(key.encode()).digest()
    print("1. Show Passwords")
    print("2. Save New Passwords")
    print("3. Delete Passwords")
    print("99. Exit")
    choice = int(input("Enter choice -> "))

    match choice:
        case 1:
            show(key)
        case 2:
            store(key)
        case 3:
            delete(key)
        case 99:
            exit()
        case _:
            print("[!] Enter a valid choice")

if __name__ == "__main__":
    if not os.path.exists("dump.bin"):
        set_password()
        exit()
    for _ in range(5):
        password = getpass("Enter your password -> ")
        if check_password(password):
            menu(password)
            break
        else:
            print(f"[!] You have {5 - (_ + 1)} tries left.")
