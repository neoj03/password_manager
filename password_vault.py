import sqlite3, hashlib
from tkinter import *
from tkinter import simpledialog
from functools import partial

#Database Code 
with sqlite3.connect('password_vault.db') as db:
    cursor = db.cursor()

cursor.execute("""
CREATE TABLE IF NOT EXISTS masterpassword(
id INTEGER PRIMARY KEY,
password TEXT NOT NULL); 
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

def hashPassword(input):
    hash = hashlib.md5(input)
    hash = hash.hexdigest()

    return hash

def firstScreen():
    window.geometry("350x200")

    label = Label(window, text="Create Master Password")
    label.config(anchor='center')
    label.pack()

    txt = Entry(window, width=20)
    txt.pack()
    txt.focus()

    label1 = Label(window, text="Re-enter Master Password")
    label1.pack() 

    txt1 = Entry(window, width=20)
    txt1.pack()
    txt1.focus()

    label2 = Label(window)
    label2.pack() 


    def savePassword():
        if txt.get() == txt1.get():
            hashedPassword = hashPassword(txt.get().encode('utf-8'))
            
            insert_password = """ INSERT INTO masterpassword(password) 
            VALUES(?) """
            cursor.execute(insert_password, [(hashedPassword)])
            db.commit()

            passwordVault()

        else:
            label2.config(text="Passwords do not match, try again")

    btn = Button(window, text="Save", command=savePassword)
    btn.pack(pady=10)


def loginScreen():
    window.geometry("1000x500")

    label = Label(window, text="Enter Master Password")
    label.config(anchor='center')
    label.pack()

    txt = Entry(window, width=20, show="*")
    txt.pack()
    txt.focus()

    label = Label(window)
    label.pack() 

    def getMasterPassword():
        checkHashedPassword = hashPassword(txt.get().encode('utf-8'))
        cursor.execute("SELECT * FROM masterpassword WHERE id = 1 AND password = ?", [(checkHashedPassword)])
        print(checkHashedPassword)
        return cursor.fetchall()
    

    def checkPassword():
        match = getMasterPassword()

        if match:
            passwordVault()
        else:
            txt.delete(0, 'end')
            label.config(text="Incorrect Password, try again")

    btn = Button(window, text="Submit", command=checkPassword)
    btn.pack(pady=10)



def passwordVault():
    for widget in window.winfo_children():
        widget.destroy()

    def addEntry():
        text1 = "Website"
        text2 = "Username"
        text3 = "Password"

        wesbite = popUp(text1)
        username = popUp(text2)
        password = popUp(text3)

        insert_fields = """ INSERT INTO vault(website, username, password)
        VALUES(?,?,?) """

        cursor.execute(insert_fields, (wesbite, username, password))
        db.commit()

        passwordVault()
        
    def removeEntry(input):
        cursor.execute("DELETE FROM vault WHERE id = ?", (input,))
        db.commit()
        passwordVault()
    
    window.geometry("700x350")

    label = Label(window, text="Password Vault")
    label.grid(column=1)

    button = Button(window, text="Add", command=addEntry)
    button.grid(column=1, pady=10)

    label = Label(window, text="Website")
    label.grid(row=2, column=0, padx=80)
    label = Label(window, text="Username")
    label.grid(row=2, column=1, padx=80)
    label = Label(window, text="Password")
    label.grid(row=2, column=2, padx=80)

    cursor.execute("SELECT * FROM vault")
    if(cursor.fetchall() != None):
        i = 0 
        while True:
            cursor.execute("SELECT * FROM vault")
            array = cursor.fetchall()

            label1 = Label(window, text=array[i][1], font=("Arial", 12))
            label1.grid(row=i+3, column=0)
            label2 = Label(window, text=array[i][2], font=("Arial", 12))
            label2.grid(row=i+3, column=1)
            label3 = Label(window, text=array[i][3], font=("Arial", 12))
            label3.grid(row=i+3, column=2)

            button = Button(window, text="Remove", command=partial(removeEntry, array[i][0]))
            button.grid(row=i+3, column=3, pady=10)

            i += 1 

            cursor.execute("SELECT * FROM vault")
            if len(cursor.fetchall()) <= i:
                break

cursor.execute("SELECT * FROM masterpassword")
if cursor.fetchall():
    loginScreen()
else:
    firstScreen()

window.mainloop()

