# Saos_Password_Manager
Encrypted password manager programmed in Python 3.11 - using PBKDF2-HMAC with AES (Advanced Encryption Standard) SHA256 hashing algorithm

-----------
Welcome 
-----------
To the only PW Manager you need :) 
-------------------------------------------------
(screenshot files attached in main folder)
-------------------
MAIN FEATURES:
--------------------
 - Emails & Passwords are encrypted & stored onto a .DB file that can be securely stored anywhere, such as on a USB.
 - Random password generator (choose between 8 & 32 characters)
 - 'Compromised' button checks HIBP API if the password retrieved has been leaked (credits below)
 - 'Nuke' button to quickly destory all of the passwords in your .DB file
 - Easily access passwords with arrow keys, as well as 'R' for retrieve and 'D' for delete (macros below)
 - Mini-game embedded that's sort of broken (working on this). Double click the mouse button on the background of the program to run it.  
 -------------------
 
Credit:
-----------
This project was programmed in Python 3.11 by James Saoumi, but this program couldn't have been put together without:
 - HIBP API (https://github.com/HaveIBeenPwned) 
 - CustomTkinter UI library (https://github.com/TomSchimansky/CustomTkinter/wiki/)
 - Pygame (https://github.com/pygame/)
 - Pillow (https://github.com/python-pillow/Pillow)
 - Cryptography (https://github.com/pyca/cryptography) 
-------------------------------------------------

BEFORE RUNNING:

----------------
1) Search for #REPLACE THIS WITH YOUR DESTINATION tag and replace (r"C:\Users\...\PW_MNGR.png") with the relevant destination. 

2) You must have the following libraries installed to run the code:
Tkinter
CustomTkinter 
Pygame
Pillow
Cryptography
The other libraries in use (os, sys, base64, hashlib, secrets, sqlite3, requests, random, time, numpy) are all included in the standard py library.

3) Run it :) 

------------------------

Compression instructions: 

-------------------------------

To compress this with PyInstaller, see:
https://github.com/TomSchimansky/CustomTkinter/wiki/Packaging

In case it helps, this is the command I used in PyInstaller to get it working for me:
py -m PyInstaller --onedir --windowed --icon="C:/Users/.../PW_MNGR.ico" --add-data "C:/Users/.../AppData/Local/Programs/Python/Python311/Lib/site-packages/customtkinter;customtkinter/" --add-data "C:/Users/.../PW_MNGR.png;." "C:/Users/.../.../PW_Mngr 5.1/PW_Manager5.1.py"

----------------------------------------------------

How to use:

------------
1) GENERATE A MASTER KEY. The program will ask you to generate a key when you first open it. This will be stored (and encrypted) into the .DB file which you will create in the next step, so make sure you remember it as it CANNOT be retrieved. 

2) SELECT or CREATE a new database (.DB) file. 
Although the contents in this file will be strongly encrypted, it's recommended that you store this file somewhere safe such as on a secure USB/hard drive to reduce the likelihood of the file getting into the wrong hands. NO INFORMATION will be stored within the actual program though. The program is just a portal to your database file. As long as your database file is safe, so are you.

3) ADD WEBSITES & PASSWORDS 
Once your DB file is loaded, you can add a website/email/pass which will be directly stored into your encrypted .DB file. 
It is recommended that you use the random password generator to generate your passwords. Use the slider to adjust the amount of characters generated, in the case that the website you're creating a password for has a character limit. Otherwise, why not use 32? 

4) RETRIEVE/DELETE PASSWORDS
To retrieve/delete a password, simply select the website from the listbox, and then click the retrieve/delete button or 'r'/'d' on your keyboard (BINDS BELOW). When you retrieve a password, a copy button will appear which you can use as a shortcut to copying your p/w. 

5) COMPROMISED BUTTON
The compromised button can be used directly after retrieving a password, OR if you just want to check if your a past password has been leaked, you can just type it into the password retrieve textbox, and then select 'compromised?'. 
This button was programmed with the Pwned Passwords API provided by Troy Hunt's 'Have I Been Pwned' (HIBP) project. The Pwned Passwords API provides a secure way to check if a password has been exposed without transmitting the password in plaintext over the internet. 

6) NUKE BUTTON
This button will delete all of the data in your database. Use this button with caution as you won't be able to retrieve your passwords after using it.

7) LOG IN KEY
This is your master key. Single click to view your log in key, double click to view how this key is encrypted/stored in the database file. 

-----------------------------------------------------------------------------------------------

Binds: 

------------

Listbox Binds: 
- Right Arrow = Select first option in listbox
- Down Arrow = Select next option in listbox
- Up Arrow = Select previous selection in listbox
- Left Arrow = Remove listbox highlight selection (NOT website) & clear pw/email retrieve textboxes
- 'R' = Retrieve Button
- 'D' = Delete Button

Other:
 - Click the green cube to sort the list from A>Z. Click again to sort from Z>A. 
 - Enter on "Add Password" textbox = Submit Button
 - Right click 'Copy' to get rid of the button without copying text to your clipboard
 - One click of the key label = show key
   - Two clicks of the key label = show encrypted key (stored key) 
 - Double click with middle mouse for minigame
 - Middle mouse drag on the background to draw an effect

---------------------------------------------------------

Security information: 

-----------------------------

This password manager uses industry-standard encryption methods to securely store passwords. 
When a master key is generated, it is passed through a key derivation function (KDF) using the PBKDF2-HMAC algorithm with AES (Advanced Encryption Standard) SHA256 hashing algorithm, 100,000 iterations, and a 32-byte output length. 
The resulting key is then used to encrypt and decrypt your passwords, ensuring that they are stored in an unreadable format in the database file. Additionally, this program uses the Pwned Passwords API provided by Troy Hunt's 'Have I Been Pwned' (HIBP) project to check if a password has been exposed without transmitting the password in plaintext over the internet.
When a password is stored in your .DB file, it is encrypted. The only way to retrieve it is back through the program, using the masterkey attached the database file (which is also encrypted, so REMEMBER IT).

As an extra layer of security, it is recommended that you store your database file somewhere safe such as on a secure USB/hard drive to reduce the likelihood of the file getting into the wrong hands. Remember to never share your master key with anyone and make sure to keep it safe as it cannot be retrieved.

-----------------------------------------------------
Feedback
----------------
PLEASE give feedback / open an issue if there's anything I can do to help if you're having trouble running this or have any suggestions for me!
