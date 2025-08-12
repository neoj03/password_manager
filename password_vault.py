import sqlite3, hashlib
from tkinter import *
from tkinter import simpledialog
from functools import partial
import uuid
import base64
import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet
from PIL import Image, ImageTk

backend = default_backend()
salt = b'2444'

kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=salt,
    iterations=100000,
    backend=backend
)

encryptionKey = 0

def encrypt(message: bytes, key: bytes) -> bytes:
    return Fernet(key).encrypt(message)

def decrypt(message: bytes, token: bytes) -> bytes:
    return Fernet(token).decrypt(message)

#Database Code 
with sqlite3.connect('password_vault.db') as db:
    cursor = db.cursor()

cursor.execute("""
CREATE TABLE IF NOT EXISTS masterpassword(
id INTEGER PRIMARY KEY,
password TEXT NOT NULL,
recoveryKey TEXT NOT NULL); 
""")

cursor.execute("""
CREATE TABLE IF NOT EXISTS vault(
id INTEGER PRIMARY KEY,
website TEXT NOT NULL,
username TEXT NOT NULL,
password TEXT NOT NULL); 
""")

# Create popup
def popUp(text):
    answer = simpledialog.askstring("Input", text)
   
    return answer


# Initiate Window 
window = Tk()

window.title("Password Vault")

window.config(bg="#29AF40")

def hashPassword(input):
    hash = hashlib.sha256(input)
    hash = hash.hexdigest()

    return hash

def firstScreen():
    for widget in window.winfo_children():
        widget.destroy()

    window.geometry("400x350")
    window.config(bg="black")

    frame = Frame(window, bg="black", padx=30, pady=30)
    frame.place(relx=0.5, rely=0.5, anchor="center")

    label = Label(frame, text="Create Master Password", font=("Arial", 16, "bold"), bg="black", fg="#29AF40")
    label.pack(pady=(0, 15))

    txt = Entry(frame, width=25, show="*",
                bg="black", fg="#29AF40", insertbackground="#29AF40",
                relief="flat", highlightthickness=1, highlightbackground="#29AF40", highlightcolor="#29AF40")
    txt.pack(pady=(0, 10))
    txt.focus()

    label1 = Label(frame, text="Re-enter Master Password", font=("Arial", 12), bg="black", fg="#29AF40")
    label1.pack(pady=(15, 5))

    txt1 = Entry(frame, width=25, show="*",
                 bg="black", fg="#29AF40", insertbackground="#29AF40",
                 relief="flat", highlightthickness=1, highlightbackground="#29AF40", highlightcolor="#29AF40")
    txt1.pack(pady=(0, 10))

    # Show password toggle for both entries
    show_pass_var = IntVar(value=0)

    def toggle_password():
        if show_pass_var.get():
            txt.config(show="")
            txt1.config(show="")
        else:
            txt.config(show="*")
            txt1.config(show="*")

    chk = Checkbutton(frame, text="Show Passwords", variable=show_pass_var, command=toggle_password,
                      bg="black", fg="#29AF40", activebackground="black", activeforeground="#29AF40",
                      selectcolor="black", highlightthickness=0)
    chk.pack(pady=(0, 10))

    label2 = Label(frame, text="", fg="#FF4C4C", bg="black", font=("Arial", 10))
    label2.pack()

    def savePassword():
        if txt.get() == txt1.get():
            sql = "DELETE FROM masterpassword WHERE id = 1"
            cursor.execute(sql)

            hashedPassword = hashPassword(txt.get().encode('utf-8'))
            key = str(uuid.uuid4().hex)
            recoveryKey = hashPassword(key.encode('utf-8'))

            global encryptionKey
            encryptionKey = base64.urlsafe_b64encode(kdf.derive(hashedPassword.encode()))

            insert_password = """INSERT INTO masterpassword(password, recoveryKey) 
                                  VALUES(?, ?)"""
            cursor.execute(insert_password, (hashedPassword, recoveryKey))
            db.commit()

            recoveryScreen(key)
        else:
            label2.config(text="Passwords do not match, try again")

    btn = Button(frame, text="Save", font=("Arial", 12, "bold"),
                 bg="black", fg="#29AF40", activebackground="#146914", activeforeground="#29AF40",
                 relief="flat", highlightthickness=1, highlightbackground="#29AF40", highlightcolor="#29AF40",
                 command=savePassword)
    btn.pack(pady=15, fill="x")

def recoveryScreen(key):
    for widget in window.winfo_children():
        widget.destroy()

    window.geometry("400x250")
    window.config(bg="black")

    frame = Frame(window, bg="black", padx=30, pady=30)
    frame.place(relx=0.5, rely=0.5, anchor="center")

    label = Label(frame, text="Save this key for recovery", font=("Arial", 16, "bold"), bg="black", fg="#29AF40")
    label.pack(pady=(0, 15))

    label1 = Label(frame, text=key, font=("Courier", 14), bg="black", fg="#29AF40")
    label1.pack(pady=(0, 15))

    def done():
        passwordVault()

    btn = Button(frame, text="Done", font=("Arial", 12, "bold"),
                 bg="black", fg="#29AF40", activebackground="#146914", activeforeground="#29AF40",
                 relief="flat", highlightthickness=1, highlightbackground="#29AF40", highlightcolor="#29AF40",
                 command=done)
    btn.pack(fill="x")

def resetScreen():
    for widget in window.winfo_children():
        widget.destroy()

    window.geometry("400x250")
    window.config(bg="black")

    frame = Frame(window, bg="black", padx=30, pady=30)
    frame.place(relx=0.5, rely=0.5, anchor="center")

    label = Label(frame, text="Enter Recovery Key", font=("Arial", 16, "bold"), bg="black", fg="#29AF40")
    label.pack(pady=(0, 15))

    txt = Entry(frame, width=30,
                bg="black", fg="#29AF40", insertbackground="#29AF40",
                relief="flat", highlightthickness=1, highlightbackground="#29AF40", highlightcolor="#29AF40")
    txt.pack(pady=(0, 15))
    txt.focus()

    label1 = Label(frame, text="", fg="#FF4C4C", bg="black", font=("Arial", 10))
    label1.pack()

    def getRecoveryKey():
        recoveryKeyCheck = hashPassword(str(txt.get()).encode('utf-8'))
        cursor.execute("SELECT * FROM masterpassword WHERE id = 1 AND recoveryKey = ?", [(recoveryKeyCheck)])
        return cursor.fetchall()

    def checkRecoveryKey():
        checked = getRecoveryKey()
        if checked:
            firstScreen()
        else:
            txt.delete(0, 'end')
            label1.config(text="Incorrect Recovery Key, try again")

    btn = Button(frame, text="Check Key", font=("Arial", 12, "bold"),
                 bg="black", fg="#29AF40", activebackground="#146914", activeforeground="#29AF40",
                 relief="flat", highlightthickness=1, highlightbackground="#29AF40", highlightcolor="#29AF40",
                 command=checkRecoveryKey)
    btn.pack(pady=10, fill="x")

def loginScreen():
    for widget in window.winfo_children():
        widget.destroy()

    window.geometry("400x300")
    window.config(bg="black")

    # Frame with black background (same as window for seamless look)
    frame = Frame(window, bg="black", padx=30, pady=30)
    frame.place(relx=0.5, rely=0.5, anchor="center")

    # Title label with bright green text
    label = Label(frame, text="Enter Master Password", font=("Arial", 16, "bold"), bg="black", fg="#29AF40")
    label.pack(pady=(0, 15))

    # Password entry with black bg and green fg
    txt = Entry(frame, width=25, show="*", bg="black", fg="#29AF40", insertbackground="#29AF40", relief="flat", highlightthickness=2, highlightbackground="#29AF40", highlightcolor="#29AF40")
    txt.pack(pady=(0, 10))
    txt.focus()

    # Show password toggle variable and function
    show_pass_var = IntVar(value=0)

    def toggle_password():
        if show_pass_var.get():
            txt.config(show="")
        else:
            txt.config(show="*")

    chk = Checkbutton(frame, text="Show Password", variable=show_pass_var, command=toggle_password, bg="black", fg="#29AF40", activebackground="black", activeforeground="#29AF40", selectcolor="black", highlightthickness=0)
    chk.pack(pady=(0, 10))

    # Status label for error messages (bright red for errors)
    status_label = Label(frame, text="", fg="#FF4C4C", bg="black", font=("Arial", 10))
    status_label.pack()

    # Button styles with black bg and green fg, and green borders
    btn_style = {
        "font": ("Arial", 12, "bold"),
        "bg": "black",
        "fg": "#29AF40",
        "activebackground": "#146914",
        "activeforeground": "#29AF40",
        "relief": "flat",
        "highlightthickness": 1,
        "highlightbackground": "#29AF40",
        "highlightcolor": "#29AF40",
        "borderwidth": 0,
        "cursor": "hand2"
    }

    def getMasterPassword():
        checkHashedPassword = hashPassword(txt.get().encode('utf-8'))
        global encryptionKey
        encryptionKey = base64.urlsafe_b64encode(kdf.derive(checkHashedPassword.encode()))

        cursor.execute("SELECT * FROM masterpassword WHERE id = 1 AND password = ?", (checkHashedPassword,))
        return cursor.fetchall()

    def checkPassword(event=None):
        match = getMasterPassword()
        if match:
            passwordVault()
        else:
            txt.delete(0, 'end')
            status_label.config(text="Incorrect Password, try again")

     # Bind Enter key to submit login from password entry and entire window
    txt.bind("<Return>", checkPassword)
    window.bind("<Return>", checkPassword)

    def resetPassword():
        resetScreen()

    def on_press(event):
        event.widget.config(relief="sunken")

    def on_release(event):
        event.widget.config(relief="flat")

    btn_submit = Button(frame, text="Submit", command=checkPassword, **btn_style)
    btn_submit.pack(pady=(15, 5), fill="x")
    btn_submit.bind("<ButtonPress>", on_press)
    btn_submit.bind("<ButtonRelease>", on_release)
    btn_submit.bind("<Enter>", lambda e: e.widget.config(bg="#3AAA3A"))
    btn_submit.bind("<Leave>", lambda e: e.widget.config(bg="black"))

    btn_reset = Button(frame, text="Reset Password", command=resetPassword, **btn_style)
    btn_reset.pack(fill="x")
    btn_reset.bind("<ButtonPress>", on_press)
    btn_reset.bind("<ButtonRelease>", on_release)
    btn_reset.bind("<Enter>", lambda e: e.widget.config(bg="#3AAA3A"))
    btn_reset.bind("<Leave>", lambda e: e.widget.config(bg="black"))




def passwordVault():
    for widget in window.winfo_children():
        widget.destroy()

    window.geometry("800x450")
    window.config(bg="black")

    frame = Frame(window, bg="black", padx=20, pady=20)
    frame.place(relx=0.5, rely=0.5, anchor="center")

    def addEntry():
        website_text = popUp("Website")
        username_text = popUp("Username")
        password_text = popUp("Password")

        if not (website_text and username_text and password_text):
            return  # Cancel if user cancels input dialog

        website_enc = encrypt(website_text.encode(), encryptionKey)
        username_enc = encrypt(username_text.encode(), encryptionKey)
        password_enc = encrypt(password_text.encode(), encryptionKey)

        insert_query = """INSERT INTO vault(website, username, password) VALUES (?, ?, ?)"""
        cursor.execute(insert_query, (website_enc, username_enc, password_enc))
        db.commit()

        passwordVault()  # Refresh vault display

    def removeEntry(entry_id):
        cursor.execute("DELETE FROM vault WHERE id = ?", (entry_id,))
        db.commit()
        passwordVault()  # Refresh vault display

    # Title label
    title_label = Label(frame, text="Password Vault", font=("Arial", 20, "bold"), bg="black", fg="#29AF40")
    title_label.grid(row=0, column=0, columnspan=4, pady=(0, 15))

    # Add button
    add_button = Button(frame, text="Add", font=("Arial", 12, "bold"),
                        bg="black", fg="#29AF40", activebackground="#146914", activeforeground="#29AF40",
                        relief="flat", highlightthickness=1, highlightbackground="#29AF40", highlightcolor="#29AF40",
                        command=addEntry)
    add_button.grid(row=1, column=0, columnspan=4, pady=(0, 20), sticky="ew")

    # Column headers
    headers = ["Website", "Username", "Password", "Action"]
    for col, header in enumerate(headers):
        lbl = Label(frame, text=header, font=("Arial", 14, "bold"), bg="black", fg="#29AF40")
        lbl.grid(row=2, column=col, padx=20, sticky="ew")

    cursor.execute("SELECT * FROM vault")
    entries = cursor.fetchall()

    for i, entry in enumerate(entries):
        decrypted_website = decrypt(entry[1], encryptionKey)
        decrypted_username = decrypt(entry[2], encryptionKey)
        decrypted_password = decrypt(entry[3], encryptionKey)

        lbl_website = Label(frame, text=decrypted_website, font=("Arial", 12), bg="black", fg="#29AF40")
        lbl_website.grid(row=i + 3, column=0, padx=20, pady=5, sticky="ew")

        lbl_username = Label(frame, text=decrypted_username, font=("Arial", 12), bg="black", fg="#29AF40")
        lbl_username.grid(row=i + 3, column=1, padx=20, pady=5, sticky="ew")

        lbl_password = Label(frame, text=decrypted_password, font=("Arial", 12), bg="black", fg="#29AF40")
        lbl_password.grid(row=i + 3, column=2, padx=20, pady=5, sticky="ew")

        btn_remove = Button(frame, text="Remove", font=("Arial", 10, "bold"),
                            bg="black", fg="#29AF40", activebackground="#146914", activeforeground="#29AF40",
                            relief="flat", highlightthickness=1, highlightbackground="#29AF40", highlightcolor="#29AF40",
                            command=partial(removeEntry, entry[0]))
        btn_remove.grid(row=i + 3, column=3, padx=20, pady=5, sticky="ew")

    # Make columns expand evenly
    for col_index in range(4):
        frame.grid_columnconfigure(col_index, weight=1)


cursor.execute("SELECT * FROM masterpassword")
if cursor.fetchall():
    loginScreen()
else:
    firstScreen()

window.mainloop()

