# This file is part of PW_Manager5.1.
#
# PW_Manager5.1 is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# PW_Manager5.1 is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with PW_Manager5.1.  If not, see <https://www.gnu.org/licenses/>.


import os
import sys
import base64
import hashlib
import secrets
import sqlite3
import requests
import pygame
import random
import time
import numpy as np

from PIL import Image
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

import tkinter as tk
from tkinter import (
    Toplevel,
    filedialog,
    messagebox,
    font,
)

import customtkinter as ctk
import tkinter as tk

def game():

    icon = pygame.image.load(r"C:\Users\...\PW_Mngr 4\PW_MNGR.png") #REPLACE THIS WITH YOUR DESTINATION
    pygame.display.set_icon(icon)
    
    start_time = time.time()

    # Initialize Pygame
    pygame.init()
    pygame.mouse.set_visible(False)

    # Set up the screen
    screen_info = pygame.display.Info()
    screen_width = int(screen_info.current_w * 0.15)
    screen_height = int(screen_info.current_h * 0.4)
    screen = pygame.display.set_mode((screen_width, screen_height))
    pygame.display.set_caption("Collect as many balls as you can!")

    # Set up the clock
    clock = pygame.time.Clock()

    # Set up the colors
    white = (int(255 * 0.25), int(255 * 0.25), int(255 * 0.25))
    black = (0, 0, 0)

    # Set up the font
    font = pygame.font.SysFont(None, 30)

    # Set up the ball class
    class Ball(pygame.sprite.Sprite):
        def __init__(self):
            super().__init__()
            self.radius = 10
            self.image = pygame.Surface((self.radius * 2, self.radius * 2), pygame.SRCALPHA)
            self.rect = self.image.get_rect()
            self.rect.x = random.randrange(screen_width - self.rect.width)
            self.rect.y = -self.rect.height
            self.speed = random.randint(2, 8)
            
            # Set the color of the ball
            color_probs = {'green': 0.5, 'white': 0.45, 'red': 0.05}
            color_choice = np.random.choice(list(color_probs.keys()), p=list(color_probs.values()))
            if color_choice == 'green':
                pygame.draw.circle(self.image, (0, 128, 0), (self.radius, self.radius), 14)
                self.is_green = True
                self.is_red = False
                self.speed = random.randint(1, 7)
            elif color_choice == 'white':
                self.radius = random.choice([8, 10])
                pygame.draw.circle(self.image, white, (self.radius, self.radius), self.radius)
                self.is_green = False
                self.is_red = False
            else:
                pygame.draw.circle(self.image, (255, 0, 0), (self.radius/1.5, self.radius/1.5), self.radius/1.5)
                self.is_green = False
                self.is_red = True
                self.speed = random.randint(5, 10)
        def update(self):
            self.rect.y += self.speed

    # Set up the player class
    class Player(pygame.sprite.Sprite):
        def __init__(self):
            super().__init__()
            self.image = pygame.Surface((48, 48))
            self.image.fill(white)
            self.rect = self.image.get_rect()
            self.rect.x = (screen_width - self.rect.width) // 2
            self.rect.y = screen_height - self.rect.height
            self.speed = 10

        def update(self):
            self.rect.x = pygame.mouse.get_pos()[0] - self.rect.width // 2

    # Set up the sprite groups
    all_sprites = pygame.sprite.Group()
    balls = pygame.sprite.Group()

    # Set up the player
    player = Player()
    all_sprites.add(player)

    # Set up the game loop
    game_over = False
    score = 0
    while not game_over:
        # Process events
        for event in pygame.event.get():
            if event.type == pygame.QUIT:
                game_over = True
                print("loser")

        # Update sprites
        all_sprites.update()

        # Add a new ball every 20 frames
        if pygame.time.get_ticks() % 20 == 0:
            ball = Ball()
            all_sprites.add(ball)
            balls.add(ball)

        # Check for collisions
        collisions = pygame.sprite.spritecollide(player, balls, True)
        for collided_ball in collisions:
            if collided_ball.is_green:
                messagebox.showinfo(
                    "Game over.",
                    str(score) + " points collected in " + str(time_elapsed) + " seconds \n\n---------------\n How it works: \n---------------\n Red balls = 15 pts \n Ball = 1pt \n Big ball = 2pts \n Green square = die",
                )
                print("Score: ", score)
                print("Seconds: ", time_elapsed)
                pygame.quit()
                break
            elif collided_ball.is_red:
                score += 9
            else:
                score += 1
                if collided_ball.radius == 10:
                    score += 1

        # Delete balls that hit the bottom
        for ball in balls:
            if ball.rect.y >= screen_height:
                ball.kill()

        # Draw the screen
        screen.fill(black)
        all_sprites.draw(screen)

        # Draw the timer
        time_elapsed = int(time.time() - start_time)
        milliseconds = int((time.time() - start_time) * 100 % 100)
        text = "Time: {:02d}.{:02d}".format(time_elapsed, milliseconds)
        text_surface = font.render(text, True, white)
        text_rect = text_surface.get_rect()
        text_rect.topleft = (10, 10)
        screen.blit(text_surface, text_rect)

        # Draw the Score
        score_elapsed = score
        score_text_surface = font.render("Score: " + str(score_elapsed), True, white)
        score_text_rect = score_text_surface.get_rect()
        score_text_rect.topleft = (10, 30)
        screen.blit(score_text_surface, score_text_rect)

        # Update the display
        pygame.display.flip()

        # Limit the frame rate
        clock.tick(60)

        time_elapsed = int(time.time() - start_time)

    # Quit Pygame
    pygame.quit()


# root window
root = ctk.CTk()
ctk.set_appearance_mode("dark")
root.wm_title("The only PW mngr u need")

# font for listbox
myfont = font.Font(family="Helvetica", size=11)
root.configure(font=myfont)

# calculate size as a percentage of the screen size
screen_width = root.winfo_screenwidth()
screen_height = root.winfo_screenheight()
width_percent = 0.3
height_percent = 0.420
width = int(screen_width * width_percent)
height = int(screen_height * height_percent)

# set the window size and position
x = 50
y = 50
root.geometry(f"{width}x{height}+{x}+{y}")
root.resizable(False, False)

# filepath var for user selection
global filepath
filepath = ""

# user enters a key to get into the program. this entry is encrypted and won't allow the user to retrieve p/w's if it doesn't match the .DB file
master_key = ctk.CTkInputDialog(
    text="Enter a master key", 
    title="Master Key (REMEMBER THIS)", 
    button_fg_color='#8bc34a', 
    button_text_color='black',
    button_hover_color='#689f38',
    entry_border_color='#8bc34a',
    entry_text_color='gray21',
    )
master_key = master_key.get_input()
while master_key == "":
    master_key = ctk.CTkInputDialog(
        text="Nice try, enter a master key", title="Nice try :)"
    )
    master_key = master_key.get_input()

# a password-based key derivation function
bmaster_key = bytes(master_key, "utf-8")
password = bmaster_key + b".M7XRxa2QNnE>/7KXDfcFxp?k("
salt = b"B+G66/pl?wOlYLP7wxCCjCfLL>/Xn74:ABix4!" 
kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256,
    length=32,
    salt=salt,
    iterations=100000,
    backend=default_backend(),
)
key = base64.urlsafe_b64encode(kdf.derive(password))

# Encryption func
def encrypt(password):
    ciphertext = f.encrypt(password.encode())
    return ciphertext

# Decryption func
def decrypt(encrypted_password):
    plaintext = f.decrypt(encrypted_password)
    return plaintext.decode()


# Encryption func for email
def encryptdata(data):
    ciphertext = f.encrypt(data.encode()) 
    return ciphertext

# Decryption func for email
def decryptdata(encrypted_data):
    plaintext = f.decrypt(encrypted_data)
    return plaintext.decode() 

# Create Fernet object using the key
f = Fernet(key)

# Encrypt the key
key_enc = f.encrypt(key) 

#special drawing function
def draw(event):
    x, y = event.x, event.y
    alpha = 1.0  # initial alpha value
    oval_id = canvas.create_oval(x-4, y-4, x+4, y+4, fill=f'#{int(alpha*255):02x}0000', outline='')

    # define a function to gradually decrease the alpha value
    def fade():
        nonlocal alpha, oval_id
        alpha -= 0.1  # decrease the alpha value by 0.1
        if alpha <= 0:
            # if the alpha value is less than or equal to 0, delete the oval and stop fading
            canvas.delete(oval_id)
        else:
            # otherwise, set the fill color of the oval to the new alpha value and schedule the next fade
            canvas.itemconfigure(oval_id, fill=f'#{int(alpha*255):02x}{int((1-alpha)*255):02x}{0x23:02x}')
            canvas.after(80, fade)

    # schedule the first fade after 100ms
    canvas.after(80, fade)

canvas = tk.Canvas(root, width=width, height=height, bg='gray14', highlightthickness=0)
canvas.place(relx=0.5, rely=0.5, anchor="center")
prev_x, prev_y = None, None
canvas.bind('<B2-Motion>', draw)

def on_middle_button_double_click(event):
    game()
canvas.bind('<Double-Button-2>', on_middle_button_double_click)


def main(): 

    def animate():
        canvwidth = int(canvas.winfo_width())
        canv2width = int(canvas2.winfo_width())

        colors1 = ('#007f00', '#007f00', '#007f00', '#007f00', '#007f00', '#007f00', '#007f00', '#007f00', '#007f00', '#007f00')
        colors2 = ('#333333', '#4d4d4d', '#808080', '#a6a6a6', '#cccccc', '#e6e6e6', '#cccccc', '#a6a6a6', '#808080', '#4d4d4d')


        flag = True  # Initialize a flag variable to alternate between the two color sets

        while True:
            if flag:
                colors = colors1
            else:
                colors = colors2

            for i in range(canvwidth):
                color_index = int(i / (width/1.5) * len(colors))
                color = colors[color_index]
                canvas.create_rectangle(i, 0, i+1, 3, fill=color, outline='')
                root.update()
                root.after(8)

            for i in range(canv2width-1, -1, -1):
                color_index = int((width-1 - i) / (width/1.5) * len(colors) + len(colors)/2) % len(colors)
                color = colors[color_index]
                canvas2.create_rectangle(i, 0, i+1, 3, fill=color, outline='')
                root.update()
                root.after(8)

            flag = not flag  # Flip the flag variable to switch to the other color set
            root.update()


    Addwebsite_Txtbox = ctk.CTkEntry(master=root)
    Addemail_Txtbox = ctk.CTkEntry(master=root)
    Addpass_Txtbox = ctk.CTkEntry(master=root)

    def clear_fields():
        Addwebsite_Txtbox.delete(0, "end")
        Addpass_Txtbox.delete(0, "end")
        Addemail_Txtbox.delete(0, "end")

    # Create table & chks if tables already exist
    def createTable():
        # Create/connect to Database
        with sqlite3.connect(filepath) as conn:
            cursor = conn.cursor()

            # Check if table "passwords" already exists
            cursor.execute(
                """SELECT name FROM sqlite_master WHERE type='table' AND name='passwords'"""
            )
            if cursor.fetchone():
                # If table already exists, add "email" column if it doesn't already exist
                cursor.execute("""SELECT * FROM passwords""")
                columns = [description[0] for description in cursor.description]
                if "email" not in columns:
                    cursor.execute("""ALTER TABLE passwords ADD COLUMN email TEXT""")
                    print("Column 'email' has been added to table 'passwords'.")
                else:
                    print("Column 'email' already exists in table 'passwords'.")
            else:
                # Create table with columns for "website", "email", and "password"
                cursor.execute(
                    """CREATE TABLE passwords (website TEXT, email TEXT, password BLOB)"""
                )
                print("Table 'passwords' has been created.")
            conn.commit()

    # Define resource_path function to get absolute path to bundled file
    def resource_path(relative_path):
        if hasattr(sys, "_MEIPASS"):
            # PyInstaller creates a temp folder and stores path in _MEIPASS
            return os.path.join(sys._MEIPASS, relative_path)
        return os.path.join(os.path.abspath("."), relative_path)

    # Load the image using the resource_path function if running in bundled application
    if getattr(sys, "frozen", False):
        LogoImg = tk.PhotoImage(file=resource_path("PW_MNGR.png"))
    else:
        LogoImg = tk.PhotoImage(file=r"C:\Users\...\PW_Mngr 4\PW_MNGR.png") #REPLACE THIS WITH YOUR DESTINATION

    root.iconphoto(False, LogoImg)

    if getattr(sys, "frozen", False):
        l_light_image_path = resource_path("PW_MNGR.png")
        l_light_image = Image.open(l_light_image_path)
        l_dark_image_path = resource_path("PW_MNGR.png")
        l_dark_image = Image.open(l_dark_image_path)
    else:
        l_light_image_path = r"C:\Users\...\PW_Mngr 4\PW_MNGR.png" #REPLACE THIS WITH YOUR DESTINATION
        l_light_image = Image.open(l_light_image_path)
        l_dark_image_path = r"C:\Users\...\PW_Mngr 4\PW_MNGR.png" #REPLACE THIS WITH YOUR DESTINATION
        l_dark_image = Image.open(l_dark_image_path)

    logo_image = ctk.CTkImage(
        light_image=l_light_image, dark_image=l_dark_image, size=(65, 65)
    )

    Submit_Btn = ctk.CTkButton(master=root)

    RetrievePass_Txtbox = tk.Entry()
    RetrieveEmail_Txtbox = tk.Entry()

    RetrievePass_Txtbox.configure(
        bg="gray10", fg="#8bc34a", width=40, highlightthickness=2, highlightbackground='#8bc34a', highlightcolor='#8bc34a', selectbackground="#8bc34a", selectforeground="black"
    )
    RetrieveEmail_Txtbox.configure(
        bg="gray10", fg="#8bc34a", width=40, highlightthickness=2, highlightbackground='#8bc34a', highlightcolor='#8bc34a', selectbackground="#8bc34a", selectforeground="black"
    )
    Addwebsite_Txtbox.configure(
        border_width=1,
        border_color='#8bc34a',
        text_color='#8bc34a',
        corner_radius=5,
        fg_color='gray23',
        height=25,
    )
    Addemail_Txtbox.configure(
        border_width=1,
        border_color='#8bc34a',
        text_color='#8bc34a',
        corner_radius=5,
        height=25,
    )
    Addpass_Txtbox.configure(
        border_width=1,
        border_color='#8bc34a',
        text_color='#8bc34a',
        corner_radius=5,
        width=200,
        height=25,
    )

    # creates the table for the relevant key
    def createKeyTable(key):
        global filepath
        print(f"filepath: {filepath}")
        with sqlite3.connect(filepath) as conn:
            cursor = conn.cursor()
            # Check if table "keys" already exists
            cursor.execute(
                """SELECT name FROM sqlite_master WHERE type='table' AND name='keys'"""
            )
            if cursor.fetchone():
                print("Table 'keys' already exists.")
            else:
                cursor.execute("""CREATE TABLE keys (key TEXT)""")
                print("Table 'keys' has been created.")
            # Check if the keys table has any entries
            cursor.execute("SELECT COUNT(*) FROM keys")
            if cursor.fetchone()[0] == 0:
                cursor.execute("INSERT INTO keys (key) VALUES (?)", (key,))
                conn.commit()
                print(f"Inserted key: {key}")
            else:
                cursor.execute("SELECT key FROM keys")
                saved_key = cursor.fetchone()[0]
                if saved_key == key:
                    print(f"Key {key} matches database.")
                else:
                    messagebox.showerror("Error", "Invalid key.")
                    print(f"Invalid key: {key}")
                    Submit_Btn.configure(state="disabled")
                    Nuke_Btn.configure(state='disabled')
                    Websites_Listbox.configure(state="disabled")

    def on_submit_button_enter_pressed(event):
        submit()

    Addpass_Txtbox.bind("<Return>", on_submit_button_enter_pressed) 

    # Delete all
    def delete_all():
        if filepath != "":
            with sqlite3.connect(filepath) as conn:
                cursor = conn.cursor()
            confirm = messagebox.askyesno(
                "Confirm", "Are you sure you want to delete everything?"
            )
            if confirm:
                cursor.execute("DELETE FROM passwords")
                conn.commit()
                messagebox.showinfo(
                    "Success",
                    "All websites, emails and associated passwords have been deleted.",
                )
                refresh_listbox()
        else:
            messagebox.showinfo("Error", "Please select a .DB file first")

    def password_complexity(password):
        # Password length
        length = len(password)

        # Character complexity
        uppercase = any(c.isupper() for c in password)
        lowercase = any(c.islower() for c in password)
        digits = any(c.isdigit() for c in password)
        special = any(not c.isalnum() for c in password)

        # Complexity score
        score = 0
        if length >= 8:
            score += 1
        if uppercase and lowercase:
            score += 1
        if digits:
            score += 1
        if special:
            score += 1

        return score

    # submit button
    def submit():
        global filepath

        if not filepath:
            messagebox.showerror("Error", "No DB file selected dude")
            return

        website = Addwebsite_Txtbox.get().strip()
        password = Addpass_Txtbox.get().strip()
        email = Addemail_Txtbox.get().strip()

        if not website or not password:
            messagebox.showerror("Error", "Please enter a website and password")
            return

        if password_complexity(password) < 3:
            # If the password is not considered secure enough, prompt the user to confirm submission
            result = messagebox.askyesno("Confirm", "It's recommended that you choose a stronger password. Are you sure you want to submit this password?")
            if not result:
                # If the user chooses not to submit the password, return without doing anything
                return

        try:
            with sqlite3.connect(filepath) as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT website FROM passwords WHERE website=?", (website,))
                result = cursor.fetchone()

                if result:
                    messagebox.showerror("Error", "Website already exists")
                    return

                encrypted_password = encrypt(password)
                if email:
                    encrypted_email = encryptdata(email)
                    cursor.execute("INSERT INTO passwords (website, password, email) VALUES (?, ?, ?)", (website, sqlite3.Binary(encrypted_password), sqlite3.Binary(encrypted_email)))
                else:
                    cursor.execute("INSERT INTO passwords (website, password) VALUES (?, ?)", (website, sqlite3.Binary(encrypted_password)))

                conn.commit()
                messagebox.showinfo("Success", "Website added to list")
                clear_fields()
                refresh_listbox()

        except sqlite3.Error as e:
            messagebox.showerror("Error", e)


    Submit_Btn.configure(
        cursor="hand2",
        text="Submit",
        command=submit,
        fg_color="gray10",
        text_color="#8bc34a",
        hover_color="#36454F",
        height=23,
        border_color="white",
        border_width=1,
    )

    # Refresh LB
    def refresh_listbox():
        print(filepath)
        with sqlite3.connect(filepath) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT website FROM passwords")
            websites = cursor.fetchall()
            Websites_Listbox.delete(0, "end")
            for website in websites:
                Websites_Listbox.insert("end", website[0])

    sframe = tk.Frame(root)
    sframe.place(rely=0.32, relx=0.05, anchor="nw")
    sframe.config(bg="#8bc34a", cursor="hand2", padx=3, pady=3, height=15)

    KeyLbl = ctk.CTkLabel(master=root, text="Log in key: *******", font=(myfont, 10))
    KeyLbl.configure(cursor="hand2")
    KeyLbl.place(rely=0.96, relx=0.05, anchor="w")

    Websites_Listbox = tk.Listbox(sframe)
    # log in key - single click
    global Kylbl_hide_flag
    Kylbl_hide_flag = False

    def sort_listbox_az():
        items = list(Websites_Listbox.get(0, 'end'))
        if items == sorted(items, key=lambda x: x.lower()):
            items.sort(key=lambda x: x.lower(), reverse=True)
        else:
            items.sort(key=lambda x: x.lower())
        Websites_Listbox.delete(0, 'end')
        for item in items:
            Websites_Listbox.insert('end', item)

    def on_label_clicked(event):
        global Kylbl_hide_flag
        if Kylbl_hide_flag:
            KeyLbl.configure(text="Log in key: *******")
            Kylbl_hide_flag = False
        else:
            KeyLbl.configure(text="Log in key: " + master_key)
            Kylbl_hide_flag = True

    # log in key - dbl click
    def on_label_double_clicked(event):
        DecodedKey = key.decode()
        KeyLbl.configure(text="enc key: " + DecodedKey)

    KeyLbl.bind("<Button-1>", on_label_clicked)
    KeyLbl.bind("<Double-Button-1>", on_label_double_clicked)

    # Add New Website & PW
    AddNewWeb_Lbl = ctk.CTkLabel(master=root, text="Add New Website", text_color='lightgray')
    AddNewWeb_Lbl.place(rely=0.01, relx=0.01, anchor="nw")

    AddNewEmail_Lbl = ctk.CTkLabel(master=root, text="Add New Email", text_color='lightgray')
    AddNewEmail_Lbl.place(rely=0.01, relx=0.3, anchor="nw")

    AddNewPW_Lbl = ctk.CTkLabel(master=root, text="Add New Password", text_color='lightgray')
    AddNewPW_Lbl.place(rely=0.01, relx=0.585, anchor="nw")

    Addwebsite_Txtbox.place(rely=0.073, relx=0.01, anchor="nw")
    Addemail_Txtbox.place(rely=0.073, relx=0.3, anchor="nw")
    Addpass_Txtbox.place(rely=0.073, relx=0.585, anchor="nw")

    Submit_Btn.place(rely=0.18, relx=0.93, anchor="e")


    # line
    canvas = tk.Canvas(master=root, width=width/1.5, height=3)
    canvas.place(rely=0.18, anchor="nw")
    canvas.configure(bg="gray25", highlightthickness=0)

    # line3
    canvas3 = ctk.CTkCanvas(master=root, width=323, height=3)
    # canvas3.grid(row=20, column=0, columnspan=10, sticky="EW", pady=2)
    canvas3.configure(bg="gray", highlightthickness=0)

    # Random PW Generator lbl and entry
    PWGen_Lbl = ctk.CTkLabel(master=root, text="Random password generator", text_color='lightgray')
    PWGen_Lbl.place(rely=0.285, relx=0.88, anchor="e")
    PWGen_Txtbox = ctk.CTkEntry(
        master=root,
        border_width=1,
        border_color='#8bc34a',
        text_color='#8bc34a',
        corner_radius=5,
        width=200,
        height=25,
    )
    PWGen_Txtbox.place(rely=0.34, relx=0.93, anchor="e")

    # No of pw characters scroller
    PWGen_Scroller_Lbl = ctk.CTkLabel(master=root, text="#", text_color="#8bc34a")
    PWGen_Scroller_Lbl.place(rely=0.39, relx=0.98, anchor="e")

    def get_slider_value():
        return int(slider.get())

    def slider_event(value):
        PWGen_Scroller_Lbl.configure(text=value)

    slider = ctk.CTkSlider(
        master=root,
        from_=8,
        to=32,
        command=slider_event,
        number_of_steps=24,
        button_color="#8bc34a",
        button_hover_color="#7cb342",
    )
    slider.place(rely=0.4, relx=0.93, anchor="e")

    # copy text from p/w gen textbox
    def copyPWGen_Txtbox_text():
        Copy_PassGen_Btn.place_forget()
        text = PWGen_Txtbox.get()
        root.clipboard_clear()
        root.clipboard_append(text)
        messagebox.showinfo("Success", "Password copied to clipboard")
        PWGen_Txtbox.delete(0, "end")

    Copy_PassGen_Btn = ctk.CTkButton(master=root, text="Copy")
    Copy_PassGen_Btn.configure(
        command=copyPWGen_Txtbox_text, 
        text="Copy pw", 
        cursor="hand2", 
        fg_color="#8bc34a", 
        text_color="black", 
        hover_color="white",
        height=10,
        border_color="white",
        width=20)
    

    # Generate random password
    def generate_password():
        Copy_PassGen_Btn.place(rely=0.459, relx=0.65, anchor="e")

        characters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!#$%&*+-=?@^_[]}{?><:;#$%"
        password = "".join(
            secrets.choice(characters) for i in range(get_slider_value())
        )

        pw = tk.StringVar()
        pw.set(password)
        PWGen_Txtbox.configure(textvariable=pw)

        return password

    pwGen_Btn = ctk.CTkButton(
        master=root,
        text="Generate",
        command=generate_password,
        fg_color="gray10",
        text_color="#8bc34a",
        hover_color="#36454F",
        height=23,
        border_color="white",
        border_width=1,
    )
    pwGen_Btn.configure(cursor="hand2")
    pwGen_Btn.place(rely=0.459, relx=0.93, anchor="e")

    # line2
    canvas2 = ctk.CTkCanvas(master=root, width=width, height=3)
    canvas2.place(relx=1.0, relwidth=0.6, rely=0.51, anchor="ne")
    canvas2.configure(bg="gray25", highlightthickness=0) 

    # Saved websites label

    SavedWebsites_Lbl = ctk.CTkLabel(master=root, text="Saved Websites")
    SavedWebsites_Lbl.place(rely=0.29, relx=0.05, anchor="w")

    # List saved websites

    scrollbar = ctk.CTkScrollbar(
        master=root,
        orientation="vertical",
        command=Websites_Listbox.yview,
        button_color="lightgray",
        button_hover_color="black",
    )
    scrollbar.place(rely=0.33, relx=0.01, anchor="nw")
    scrollbar.configure(cursor="hand1")

    Websites_Listbox.config(
        height=14,
        yscrollcommand=scrollbar.set,
        bg="gray10",
        fg="#8bc34a",
        width=25,
        selectforeground="#3B3B3B",
        selectbackground="#8bc34a",
        highlightthickness=0,
    )
    Websites_Listbox.pack(side="left", fill="both", expand=True) 

    def SelectDBfile():
        global filepath
        # Prompt the user to select a directory to save the .db file
        filepath = filedialog.askopenfilename(defaultextension=".db")
        # Connect to or create the .db file at the selected filepath
        with sqlite3.connect(filepath) as conn:
            cursor = conn.cursor()
        # only attempts to create table if filepath has been chosen
        if filepath != "":
            createTable()
            createKeyTable(key)
            refresh_listbox()
            messagebox.showinfo("Hey", ".DB file is loaded", icon="info")
            Startdialog.title("Logged In")
            root.deiconify()
            Startdialog.geometry("300x125+420+15")
            Startdialog.SaveFile_Btn.configure(state="disabled")
            Startdialog.SelectFile_Btn.configure(text="Change DB File")
            Startdialog.SaveFile_Btn.configure(text="restart to re-enter master key")
        print(filepath)
        animate()

    def SaveDBfile():
        global filepath
        filepath = filedialog.asksaveasfilename(defaultextension=".db")
        with sqlite3.connect(filepath) as conn:
            cursor = conn.cursor()
        if filepath != "":
            createTable()
            createKeyTable(key)
            messagebox.showinfo(
                "Hey",
                "Your .DB file is saved & loaded. Remember that you can save/relocate this .db file, such as on an external storage device. As long as you remember where it is! (and remember your master key)",
            )
            Startdialog.title("Logged In")
            root.deiconify()
            Startdialog.geometry("300x125+420+15")
            Startdialog.SaveFile_Btn.configure(state="disabled")
            Startdialog.SelectFile_Btn.configure(text="Change DB File")
            Startdialog.SaveFile_Btn.configure(text="restart to re-enter master key")
        print(filepath)

    def copy_text():
        text = RetrievePass_Txtbox.get()
        root.clipboard_clear()
        root.clipboard_append(text)
        messagebox.showinfo("Success", "Password copied to clipboard")
        Copy_Pass_Btn.place_forget()
        Compromised_Btn.place(rely=0.9, relx=0.49, anchor="w")
        RetrievePass_Txtbox.delete(0, "end")

    def on_right_click(event):
        Copy_Pass_Btn.place_forget()
        Copy_PassGen_Btn.place_forget()
        Compromised_Btn.place(rely=0.9, relx=0.49, anchor="w")

    Copy_PassGen_Btn.bind("<Button-3>", on_right_click)

    Copy_Pass_Btn = ctk.CTkButton(
        master=root,
        text="Copy pw",
        command=copy_text,
        fg_color="#8bc34a",
        text_color="black",
        hover_color="white",
        height=10,
        border_color="white",
        width=20
    )
    Copy_Pass_Btn.configure(cursor="hand2")

    Copy_Pass_Btn.bind("<Button-3>", on_right_click)

    # Copy Btn
    def callCopy_Pass_Btn():
        Copy_Pass_Btn.place(rely=0.9, relx=0.5, anchor="w")

    def retrieve(event): 
        if filepath != "":
            callCopy_Pass_Btn()
            selected_website = Websites_Listbox.curselection()
            if not selected_website:
                messagebox.showerror("Error", "No website chosen from list")
                return
            selected_website = Websites_Listbox.get(selected_website)
            with sqlite3.connect(filepath) as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "SELECT password, email FROM passwords WHERE website=?",
                    (selected_website,),
                )
                result = cursor.fetchone()
                if result:
                    try:
                        Compromised_Btn.place(rely=0.9, relx=0.63, anchor="w")
                        decrypted_password = decrypt(result[0])
                        decrypted_email = ""
                        if result[1]:
                            decrypted_email = decrypt(result[1])
                        else:
                            decrypted_email = "{n/a}"
                        RetrievePass_Txtbox.delete(0, "end")
                        RetrievePass_Txtbox.insert(0, decrypted_password)
                        RetrieveEmail_Txtbox.delete(0, "end")
                        RetrieveEmail_Txtbox.insert(0, decrypted_email)
                    except InvalidToken:
                        messagebox.showinfo(
                            "Error",
                            "Invalid Token for the database chosen, please check your encryption/login key",
                        )
                else:
                    messagebox.showinfo("Sorry", "Website not found")
        else:
            messagebox.showinfo("Error", "Please select a .DB file first")

    # Create a new top-level window (i.e. a new dialog)
    Startdialog = Toplevel()
    Startdialog.geometry("420x200+15+15")
    Startdialog.title("Log In")
    Startdialog.resizable(False, False)
    Startdialog.iconphoto(False, LogoImg)
    Startdialog.configure(background="#8bc34a")
    # Create a button to display the image
    Startdialog.SelectFile_Btn = ctk.CTkButton(
        master=Startdialog,
        text="Select DB File",
        command=SelectDBfile,
        border_width=1,
        fg_color="black",
        text_color="#8bc34a",
        hover_color="#36454F",
        height=10,
        border_color="#8bc34a",
    )
    Startdialog.SelectFile_Btn.configure(cursor="hand2")
    Startdialog.SelectFile_Btn.grid(row=0, column=0, sticky="nswe")
    Startdialog.SaveFile_Btn = ctk.CTkButton(
        master=Startdialog,
        text="Save new DB file (select if it's first time here)",
        command=SaveDBfile,
        border_width=1,
        fg_color="black",
        text_color="#8bc34a",
        hover_color="#36454F",
        height=10,
        border_color="#8bc34a",
    )
    Startdialog.SaveFile_Btn.configure(cursor="hand2")
    Startdialog.SaveFile_Btn.grid(row=1, column=0, sticky="nswe")
    # expand buttons to fill up the avail space
    Startdialog.columnconfigure(0, weight=1)
    Startdialog.rowconfigure(0, weight=1)
    Startdialog.rowconfigure(1, weight=1)
    root.withdraw()

    # Retrieve password
    event = tk.Event()
    event.keysym = "r"
    RetrievePass_Btn = ctk.CTkButton(
        master=root,
        text="Retrieve (r)",
        command=lambda: retrieve(event),
        fg_color="#8bc34a",
        text_color="gray10",
        hover_color="#689f38",
        height=10,
        border_color="#8bc34a",
        border_width=1,
        width=30
    )
    RetrievePass_Btn.configure(cursor="hand2")
    RetrievePass_Btn.place(rely=0.74, relx=0.33, anchor="w")
    Websites_Listbox.bind("<Key-r>", retrieve)

    

    def highlight_first_entry(event):
        if event.keysym == 'Right':
            Websites_Listbox.focus_set()
            Websites_Listbox.activate(0)
            Websites_Listbox.selection_clear(0, 'end')
            Websites_Listbox.selection_set(0)
            Websites_Listbox.yview_moveto(0)

    def move_selection(event):
        current_index = Websites_Listbox.curselection()
        if not current_index:
            return
        elif event.keysym == 'Left':
            root.focus_set()
            Websites_Listbox.selection_clear(0, 'end')
            Websites_Listbox.activate(0)
            Websites_Listbox.selection_set(0)
            RetrievePass_Txtbox.delete(0, "end")
            RetrieveEmail_Txtbox.delete(0, "end")
        try:
            Websites_Listbox.selection_clear(0, 'end')
        except UnboundLocalError:
            pass

    root.bind("<Right>", highlight_first_entry)
    root.bind("<Left>", move_selection)
    
    # email retrieve TB
    RetrieveEmail_Txtbox.place(rely=0.855, relx=0.05, anchor="w")
    # pw retrieve TB
    RetrievePass_Txtbox.place(rely=0.9, relx=0.05, anchor="w")

    def delete(event):
        selected_website = Websites_Listbox.curselection()
        if not selected_website:
            messagebox.showinfo("Error", "Please select a website to delete")
            return

        with sqlite3.connect(filepath) as conn:
            cursor = conn.cursor()
            website = Websites_Listbox.get(selected_website)
            confirm = messagebox.askyesno(
                "Confirm Deletion", "Are you sure you want to delete " + website + "?"
            )
            if confirm:
                cursor.execute("DELETE FROM passwords WHERE website=?", (website,))
                conn.commit()
                refresh_listbox()
            else:
                print("Deletion canceled.")

    # Delete PW
    event1 = tk.Event()
    event1.keysym = "d"
    DeletePass_Btn = ctk.CTkButton(
        master=root,
        text="Delete   (d)",
        command=lambda: delete(event1),
        fg_color="#8bc34a",
        text_color="gray10",
        hover_color="#689f38",
        height=10,
        border_color="#8bc34a",
        border_width=1,
        width=30
    )
    DeletePass_Btn.configure(cursor="hand2")
    DeletePass_Btn.place(rely=0.79, relx=0.33, anchor="w")
    Websites_Listbox.bind("<Key-d>", delete)

    # logo
    logo_Btn = ctk.CTkButton(
        master=root,
        text="",
        image=logo_image,
        fg_color="transparent",
        bg_color="transparent",
        hover_color='gray14',
        width=40,
        command= sort_listbox_az
    )
    logo_Btn.place(rely=0.62, relx=0.98, anchor="e")
    logo_Btn.configure(cursor="hand2")

    # Self destruct account
    Nuke_Btn = ctk.CTkButton(
        master=root,
        text="Nuke",
        command=delete_all,
        fg_color="black",
        text_color="#8bc34a",
        hover_color="white",
        height=10,
        border_color="#8bc34a",
        border_width=1,
    )
    Nuke_Btn.configure(cursor="spider", width=5)
    Nuke_Btn.place(rely=0.98, relx=1, anchor="e")

    # Chk compromised P/w
    def get_password_leak_count(hashes, hash_to_check):
        # Split the response text into lines and split each line into a tuple of (hash, count)
        hashes = (line.split(":") for line in hashes.text.splitlines())
        # Iterate through the tuples and check if the hash matches
        for h, count in hashes:
            if h == hash_to_check:
                return count
        return 0

    def pwned_api_check(password):
        # Hash the password using sha1 and convert it to uppercase
        sha1password = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
        # Split the hash into the first 5 characters and the rest of the hash
        first5_char, tail = sha1password[:5], sha1password[5:]
        # Send a request to the HaveIBeenPwned API using the first 5 characters
        response = requests.get(f"https://api.pwnedpasswords.com/range/{first5_char}")
        # If the API returns an error status code, raise an exception
        if response.status_code != 200:
            raise RuntimeError(
                f"Error fetching: {response.status_code}, check the API and try again"
            )
        # Compare the rest of the hash to the response from the API
        return get_password_leak_count(response, tail)

    def check_password():
        password = RetrievePass_Txtbox.get()
        if password != "":
            count = pwned_api_check(password)
            # Print a message based on the result
            if count:
                messagebox.showerror(
                    "Error",
                    f"{password} was found {count} times... you should probably change your password!",
                )
            else:
                messagebox.showinfo(
                    "Info", f"{password} was NOT found in any password leaks. Carry on!"
                )
        else:
            messagebox.showerror(
                "Error",
                f"No password found, please ensure that there is a password in the textbox to the left of this button - You may type your own password in this box, OR get it via. the Retrieve button",
            )

    Compromised_Btn = ctk.CTkButton(
        master=root,
        text="Compromised?",
        command=check_password,
        fg_color="gray10",
        text_color="#8bc34a",
        hover_color="#36454F",
        height=15,
        border_color="lightgray",
        border_width=1,
    )
    Compromised_Btn.place(rely=0.9, relx=0.49, anchor="w")
    Compromised_Btn.configure(cursor="hand2")

main()

root.mainloop()

#coded by @jamessao