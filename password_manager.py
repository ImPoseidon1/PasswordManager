import base64
import os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

def write_key(master_pass):
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=480000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(master_pass.encode()))
    with open("key.key", "wb") as key_file:  # the salt has to be stored in some retrievable location.
        key_file.write(key)
    with open("salt.salt", "wb") as salt_file:
        salt_file.write(salt)

def load_key(master_pass):
    with open("salt.salt", "rb") as salt_file:
        salt = salt_file.read()
    with open("key.key", "rb") as key_file:
        stored_key = key_file.read()
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=480000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(master_pass.encode()))
    if key == stored_key:
        return key
    else:
        raise ValueError("Incorrect master password.")

master_pass = input("What is your master password? ")

# Uncomment the line below if using for the first time to create the key.
# write_key(master_pass)

try:
    key = load_key(master_pass)
    fer = Fernet(key)
except ValueError as e:
    print("Incorrect Master Password")
    exit()

def viewAllPasswords():
    try:
        with open('password.txt', 'r') as f:
            for line in f.readlines():
                data = line.rstrip()
                user, password = data.split("|")
                print("User:", user, " Password:", fer.decrypt(password.encode()).decode())
    except Exception as e:
        print("password.txt file does not exist", e)

def addNewPassword():
    name = input("Account Name: ")
    pwd = input("Password: ")

    try:
        with open('password.txt', 'a') as f:
            f.write(name + "|" + fer.encrypt(pwd.encode()).decode() + "\n")
    except Exception as e:
        print("An error occurred while adding a password:", e)

while True:
    mode = input("Do you want to view passwords or add a new password (view, add)? Press 'z' to quit the program: ").lower()
    if mode == "z":
        break
    elif mode == "view":
        viewAllPasswords()
    elif mode == "add":
        addNewPassword()
    else:
        print("Invalid mode selected.")

