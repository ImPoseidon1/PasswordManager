# Password Manager

A simple password manager that securely stores your passwords using encryption. This project utilizes the `cryptography` library for encryption and decryption of passwords.

## Features

- Securely encrypts and decrypts passwords.
- Stores account names and their corresponding encrypted passwords.
- Allows users to add new passwords and view stored passwords.
- Uses a master password for encryption and decryption.

## Prerequisites
- `cryptography` library

You can install the `cryptography` library using pip:

```bash
pip install cryptography
```
# Usage 

- When prompted, enter your master password which would unlock all your passwords.
- If you are using this for the first time, uncomment the write_key(master_pass) line. Then comment it back after you have inputted your master password.
