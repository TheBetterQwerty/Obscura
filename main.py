import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import hashlib
import os
from getpass import getpass

def encrypt(key, message):
    cipher = AES.new(key, AES.MODE_ECB)
    padded_message = pad(message.encode("utf-8"), AES.block_size)
    enc = base64.b64encode(cipher.encrypt(padded_message))
    return enc.decode('utf-8')

def decrypt(key, enc_message):
    cipher = AES.new(key, AES.MODE_ECB)
    dec = cipher.decrypt(base64.b64decode(enc_message.encode("utf-8")))
    dec_message = unpad(dec, AES.block_size).decode('utf-8')
    return dec_message

def store(key):
    url = input("Enter the url (optional): ")
    username = input("Enter the username: ")
    password = input("Enter the password: ")
    field = input("Enter extra info (optional): ")

    if url == "":
        url = "uu"
    if field == "":
        field = "ff"

    url = encrypt(key, url)
    username = encrypt(key, username)
    password = encrypt(key, password)
    field = encrypt(key, field)

    # Writing to file
    with open("pass.txt", "a") as file:
        file.write("*" * 100)
        file.write(f"{url} ")
        file.write(f"{username} ")
        file.write(f"{password} ")
        file.write(f"{field} ")
        file.write("*" * 100)
    print("[+] Records Stored")

def show(key):
    with open("pass.txt") as file:
        file_contents = file.read().split("*" * 100)
    file_contents = [file for file in file_contents if file != ""]

    if (len(file_contents) < 1):
        print("Password Manager Is empty ")
        exit()

    for file in file_contents:
        file = file.split()
        print("*" * 50)
        url = decrypt(key, file[0])
        if url != "uu":
            print(f"Url     : {url}")
        print(f"Username: {decrypt(key, file[1])}")
        print(f"Password: {decrypt(key, file[2])}")
        field = decrypt(key, file[-1])
        if field != "ff":
            print(f"Field   : {field}")
        print("*" * 50)

def delete(key):
    username , password = input("Enter the Username and password divided by a (~): ").split("~")
    username = encrypt(key , username)
    password = encrypt(key , password)

    with open("pass.txt" , "r") as file:
        file_contents = file.read().split("*" * 100)
    file_contents = [file for file in file_contents if file != ""]

    for i in range(len(file_contents)):
        file_contents[i] = file_contents[i].split()
    
    for file in file_contents:
        if username in file and password in file:
            del file_contents[file_contents.index(file)]
            print("[+] Record Deleted! ")
    
    with open("pass.txt" , "w") as file:
        file.close()
    for i in range(len(file_contents)):
        with open("pass.txt", "a") as file:
            file.write("*" * 100)
            file.write(f"{file_contents[i][0]} ")
            file.write(f"{file_contents[i][1]} ")
            file.write(f"{file_contents[i][2]} ")
            file.write(f"{file_contents[i][-1]} ")
            file.write("*" * 100)


def first_time():
    password = getpass("Enter a Password for Password Manager: ")
    password2 = getpass("Enter the password again: ")
    if password != password2:
        print("Passwords Dont Match. Try again!")
        exit()
    
    key = hashlib.sha256(password2.encode()).digest()
    try:
        with open("dump.txt", "w") as file:
            file.write(str(key))
            print("[+] Password Saved!")
    except Exception as e:
        print(f"Error: {e}")

def check_password(password):
    with open("dump.txt") as file:
        byte_key = file.read()[2:-1]
        byte_key = bytes(eval(f'b"{byte_key}"'))

    key = hashlib.sha256(password.encode()).digest()
    return byte_key == key

def menu(key):
    key = hashlib.sha256(key.encode()).digest()
    print(f"{'*' * 25} PassWord Manager {'*' * 25}")
    print(f"   1> Show Passwords ")
    print(f"   2> Store New Password ")
    print(f"   3> Delete a Record ")
    print(f"  99> Exit ")
    choice = int(input("-> "))
    if choice == 1:
        show(key)
    elif choice == 2:
        store(key)
    elif choice == 3:
        delete(key)
    else:
        exit()

if __name__ == "__main__":
    if not os.path.exists("dump.txt"):
        first_time()
        exit()
    
    for _ in range(5):
        password = getpass("Enter Passcode: ")
        if check_password(password):
            menu(password)
            break
        else:
            print(f"Invalid password you have {5 - (_+1)} tries left.")

