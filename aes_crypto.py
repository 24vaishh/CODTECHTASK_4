import os
import hashlib
import base64
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
from tkinter import filedialog, simpledialog, messagebox, Tk

BLOCK_SIZE = 16
KEY_SIZE = 32  # AES-256
SALT_SIZE = 16
IV_SIZE = 16
HEADER = b"ENCRYPTED"

def pad(data):
    pad_len = BLOCK_SIZE - len(data) % BLOCK_SIZE
    return data + bytes([pad_len] * pad_len)

def unpad(data):
    pad_len = data[-1]
    return data[:-pad_len]

def derive_key(password, salt):
    return PBKDF2(password, salt, dkLen=KEY_SIZE, count=100000)

def encrypt_file(file_path, password):
    with open(file_path, 'rb') as f:
        plaintext = f.read()

    salt = get_random_bytes(SALT_SIZE)
    iv = get_random_bytes(IV_SIZE)
    key = derive_key(password.encode(), salt)

    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(plaintext))

    encrypted_data = HEADER + salt + iv + ciphertext
    encrypted_path = file_path + ".enc"

    with open(encrypted_path, 'wb') as f:
        f.write(encrypted_data)

    messagebox.showinfo("Success", f"File encrypted as {encrypted_path}")

def decrypt_file(file_path, password):
    with open(file_path, 'rb') as f:
        file_data = f.read()

    if not file_data.startswith(HEADER):
        messagebox.showerror("Error", "Invalid encrypted file!")
        return

    salt = file_data[len(HEADER):len(HEADER)+SALT_SIZE]
    iv = file_data[len(HEADER)+SALT_SIZE:len(HEADER)+SALT_SIZE+IV_SIZE]
    ciphertext = file_data[len(HEADER)+SALT_SIZE+IV_SIZE:]

    key = derive_key(password.encode(), salt)
    cipher = AES.new(key, AES.MODE_CBC, iv)

    try:
        decrypted_data = unpad(cipher.decrypt(ciphertext))
        decrypted_path = file_path.replace(".enc", ".dec")

        with open(decrypted_path, 'wb') as f:
            f.write(decrypted_data)

        messagebox.showinfo("Success", f"File decrypted as {decrypted_path}")
    except ValueError:
        messagebox.showerror("Error", "Wrong password or corrupted file!")

# GUI with Tkinter
def gui():
    root = Tk()
    root.withdraw()

    while True:
        choice = simpledialog.askstring("AES File Tool", "Choose:\n1. Encrypt\n2. Decrypt\n3. Exit")
        if not choice:
            break
        if choice == "1":
            file_path = filedialog.askopenfilename(title="Select File to Encrypt")
            if file_path:
                pwd = simpledialog.askstring("Password", "Enter password for encryption:", show='*')
                if pwd:
                    encrypt_file(file_path, pwd)
        elif choice == "2":
            file_path = filedialog.askopenfilename(title="Select File to Decrypt")
            if file_path:
                pwd = simpledialog.askstring("Password", "Enter password for decryption:", show='*')
                if pwd:
                    decrypt_file(file_path, pwd)
        elif choice == "3":
            break
        else:
            messagebox.showerror("Invalid", "Please choose 1, 2, or 3.")

if __name__ == "__main__":
    gui()
