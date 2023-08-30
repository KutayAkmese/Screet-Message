from tkinter import *
from PIL import Image, ImageTk
from tkinter import messagebox
import base64
window=Tk()
window.title("Secret Quiz")
window.minsize(width=300,height=300)
def encode(key, clear):
    enc = []
    for i in range(len(clear)):
        key_c = key[i % len(key)]
        enc_c = chr((ord(clear[i]) + ord(key_c)) % 256)
        enc.append(enc_c)
    return base64.urlsafe_b64encode("".join(enc).encode()).decode()

def decode(key, enc):
    dec = []
    enc = base64.urlsafe_b64decode(enc).decode()
    for i in range(len(enc)):
        key_c = key[i % len(key)]
        dec_c = chr((256 + ord(enc[i]) - ord(key_c)) % 256)
        dec.append(dec_c)
    return "".join(dec)
def save_clicked():
    title = entry.get()
    message = entry2.get("1.0",END)
    master_secret = entry3.get()

    if len(title) == 0 or len(message) == 0 or len(master_secret) == 0:
            messagebox.showinfo(title="Error!", message="Please enter all information.")
    else:
        message_encrypted = encode(master_secret, message)

        try:
            with open("mysecret.txt", "a") as data_file:
                data_file.write(f'\n{title}\n{message_encrypted}')
        except FileNotFoundError:
            with open("mysecret.txt", "w") as data_file:
                data_file.write(f'\n{title}\n{message_encrypted}')
        finally:
            entry.delete(0, END)
            entry3.delete(0, END)
            entry2.delete("1.0",END)

def decrypt_clicked():
    message_encrypted = entry2.get("1.0", END)
    master_secret = entry3.get()

    if len(message_encrypted) == 0 or len(master_secret) == 0:
        messagebox.showinfo(title="Error!", message="Please enter all information.")
    else:
        try:
            decrypted_message = decode(master_secret,message_encrypted)
            entry2.delete("1.0", END)
            entry2.insert("1.0", decrypted_message)
        except:
            messagebox.showinfo(title="Error!", message="Please make sure of encrypted info.")


imageFile = "Unknown.png"

img = ImageTk.PhotoImage(Image.open(imageFile))
panel =Label(window, image = img)
panel.pack(side = "bottom", fill = "both", expand = "yes")
label=Label(text="Enter your title")
label.config(fg="black")
label.pack()

entry=Entry(width=20)
entry.pack()

label2=Label(text="Enter your secret")
label2.config(fg="black")
label2.pack()

entry2=Text(width=20,height=10)
entry2.pack()

label3=Label(text="Enter master key")
label3.config(fg="black")
label3.pack()

entry3=Entry(width=20)
entry3.pack()

save=Button(text="Save &Encrypt",command=save_clicked)
save.pack()

decrypt=Button(text="Decrypt",command=decrypt_clicked)
decrypt.pack()

window.mainloop()



