import customtkinter as ctk
import tkinter as tk
from tkinter import font
from pwmanager.ui import App

def main():
    # UI theme
    ctk.set_appearance_mode("dark")
    root = ctk.CTk()
    root.wm_title("The only PW mngr u need")

    # size/position
    screen_width = root.winfo_screenwidth()
    screen_height = root.winfo_screenheight()
    width = int(screen_width * 0.54)
    height = int(screen_height * 0.505)
    x, y = 50, 50
    root.geometry(f"{width}x{height}+{x}+{y}")
    root.resizable(False, False)

    # font for listbox
    myfont = font.Font(family="Helvetica", size=11)

    # prompt for master key 
    dlg = ctk.CTkInputDialog(text="Enter a master key", title="Master Key (REMEMBER THIS)")
    master_key = dlg.get_input()
    while master_key == "":
        dlg = ctk.CTkInputDialog(text="Nice try, enter a master key", title="Nice try :)")
        master_key = dlg.get_input()

    # Hand over to App. The App will derive the Fernet key AFTER a DB is chosen/created,
    # using Argon2id+salt when available (new) or PBKDF2 (legacy DB).
    app = App(
        root=root,
        myfont=myfont,
        master_key=master_key,
        width=width,
        height=height
    )
    app.run()

if __name__ == "__main__":
    main()
