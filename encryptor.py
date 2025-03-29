import os
import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import base64
import secrets

# Key Derivation Function
def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

# Encrypt File (In-Place)
def encrypt_file(file_path, password):
    salt = secrets.token_bytes(16)
    key = derive_key(password, salt)
    iv = secrets.token_bytes(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    
    with open(file_path, 'rb') as f:
        plaintext = f.read()
    
    padding_length = 16 - (len(plaintext) % 16)
    plaintext += bytes([padding_length]) * padding_length
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    
    with open(file_path, 'wb') as f:
        f.write(salt + iv + ciphertext)
    
    messagebox.showinfo("Success", "File encrypted successfully.")

# Decrypt File (In-Place)
def decrypt_file(file_path, password):
    with open(file_path, 'rb') as f:
        data = f.read()
    
    salt, iv, ciphertext = data[:16], data[16:32], data[32:]
    key = derive_key(password, salt)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    
    try:
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        padding_length = plaintext[-1]
        if padding_length < 1 or padding_length > 16:
            raise ValueError("Incorrect password or corrupted file.")
        plaintext = plaintext[:-padding_length]
    except Exception:
        messagebox.showerror("Error", "Incorrect password or corrupted file.")
        return
    
    with open(file_path, 'wb') as f:
        f.write(plaintext)
    
    messagebox.showinfo("Success", "File decrypted successfully.")

# GUI Application
def select_file(action):
    file_path = filedialog.askopenfilename()
    if not file_path:
        return
    
    password = simpledialog.askstring("Password", "Enter encryption password:", show='*')
    if not password:
        messagebox.showerror("Error", "Password cannot be empty.")
        return
    
    if action == "encrypt":
        encrypt_file(file_path, password)
    else:
        decrypt_file(file_path, password)

# Initialize GUI
root = tk.Tk()
root.title("AES File Encryptor")
root.geometry("500x350")
root.configure(bg="#34495E")

frame = tk.Frame(root, bg="#2C3E50", padx=20, pady=20)
frame.pack(expand=True, fill="both")

title_label = tk.Label(frame, text="AES File Encryptor", font=("Arial", 18, "bold"), fg="#ECF0F1", bg="#2C3E50")
title_label.pack(pady=20)

encrypt_button = tk.Button(frame, text="Encrypt File", command=lambda: select_file("encrypt"), font=("Arial", 14, "bold"), bg="#E74C3C", fg="white", padx=15, pady=10, relief="raised", bd=3)
decrypt_button = tk.Button(frame, text="Decrypt File", command=lambda: select_file("decrypt"), font=("Arial", 14, "bold"), bg="#27AE60", fg="white", padx=15, pady=10, relief="raised", bd=3)

encrypt_button.pack(pady=15, ipadx=20, fill="x")
decrypt_button.pack(pady=15, ipadx=20, fill="x")

root.mainloop()
