import tkinter as tk
from tkinter import filedialog, simpledialog, messagebox
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet
import os
import base64


# Function to derive a key from a password
def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))


def select_file():
    filepath = filedialog.askopenfilename()
    if filepath:
        selected_file_label.config(text=filepath)
    else:
        selected_file_label.config(text="No file selected")


def encrypt_file():
    filepath = selected_file_label.cget("text")
    if filepath == "No file selected":
        messagebox.showerror("Error", "Please select a file first!")
        return

    password = simpledialog.askstring("Password", "Enter a password for encryption:", show='*')
    if not password:
        messagebox.showerror("Error", "Password is required for encryption!")
        return

    try:
        # Generate a random salt
        salt = os.urandom(16)
        key = derive_key(password, salt)
        cipher = Fernet(key)

        # Read the file to encrypt
        with open(filepath, "rb") as file:
            data = file.read()

        # Encrypt the data
        encrypted_data = cipher.encrypt(data)

        # Let the user choose the save location
        original_filename = os.path.basename(filepath)
        save_path = filedialog.asksaveasfilename(
            initialfile=f"{original_filename}.encrypted",
            filetypes=[("Encrypted Files", "*.encrypted"), ("All Files", "*.*")]
        )
        if not save_path:  # If the user cancels the dialog
            return

        # Save the encrypted file
        with open(save_path, "wb") as enc_file:
            enc_file.write(salt + encrypted_data)

        messagebox.showinfo("Success", f"File encrypted and saved as {save_path}")
    except Exception as e:
        messagebox.showerror("Error", f"An error occurred: {str(e)}")


def decrypt_file():
    filepath = selected_file_label.cget("text")
    if filepath == "No file selected":
        messagebox.showerror("Error", "Please select a file first!")
        return

    password = simpledialog.askstring("Password", "Enter the password for decryption:", show='*')
    if not password:
        messagebox.showerror("Error", "Password is required for decryption!")
        return

    try:
        # Read the encrypted file (extracting the salt)
        with open(filepath, "rb") as file:
            salt = file.read(16)  # The first 16 bytes are the salt
            encrypted_data = file.read()

        # Derive the key using the same salt
        key = derive_key(password, salt)
        cipher = Fernet(key)

        # Decrypt the data
        decrypted_data = cipher.decrypt(encrypted_data)

        # Let the user choose the save location
        original_filename = os.path.basename(filepath).replace(".encrypted", "")
        save_path = filedialog.asksaveasfilename(
            initialfile=original_filename,
            filetypes=[("All Files", "*.*")]
        )
        if not save_path:  # If the user cancels the dialog
            return

        # Save the decrypted file
        with open(save_path, "wb") as dec_file:
            dec_file.write(decrypted_data)

        # Remove the encrypted file
        os.remove(filepath)

        messagebox.showinfo("Success", f"File decrypted and saved as {save_path}")
    except Exception as e:
        messagebox.showerror("Error", f"An error occurred: {str(e)}")


# Create the tkinter GUI
app = tk.Tk()
app.title("File Encryptor and Decryptor with Password")
app.geometry("400x300")

# Select file button
select_file_button = tk.Button(app, text="Select File", command=select_file)
select_file_button.pack(pady=10)

# Selected file label
selected_file_label = tk.Label(app, text="No file selected", wraplength=350, anchor="w")
selected_file_label.pack(pady=5)

# Encrypt file button
encrypt_button = tk.Button(app, text="Encrypt File", command=encrypt_file)
encrypt_button.pack(pady=10)

# Decrypt file button
decrypt_button = tk.Button(app, text="Decrypt File", command=decrypt_file)
decrypt_button.pack(pady=10)

# Instructions
instructions_label = tk.Label(
    app,
    text="Encrypt and decrypt files using a password.\nThe original file extension is preserved.",
    wraplength=350,
    anchor="w"
)
instructions_label.pack(pady=10)

# Run the app
app.mainloop()
