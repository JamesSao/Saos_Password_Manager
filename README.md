# Saos_Password_Manager

WELCOME
(Screenshots in the repo)

-------------------------------

MAIN FEATURES:

• Emails & Passwords are encrypted and stored in an SQLCipher-encrypted .db file (with per-vault salt sidecar). Store the file safely anywhere (USB, external drive, cloud).
• Random password generator (choose between 8 & 32 characters).
• "Compromised?" button checks passwords against the HaveIBeenPwned API (HIBP) without sending the password in plaintext.
• "Nuke" button quickly destroys all saved entries in a vault.
• Fast keyboard access: arrow keys for navigation, R to retrieve, D to delete.
• Clipboard safety: retrieved passwords clear from clipboard automatically after 30 seconds.
• Idle lock: vault auto-locks after inactivity (limits exposure).
• CustomTkinter UI with curved entries, modern theming, hover effects, and smooth animations.

Fun extras:
• Middle-mouse drag draws a fading trail animation.
• Click the logo cube to sort entries A→Z or Z→A.

-------------------------------

SECURITY INFORMATION:

• Key derivation: Argon2id (memory-hard), per-vault random salt (stored in .db.salt).
• Parameters tuned for ~0.5–2s per derive. Legacy PBKDF2-SHA256 vaults still supported.
• Database encryption: SQLCipher (AES-256, page-level) with Argon2id-derived key.
• Field-level encryption: passwords/emails further encrypted with Fernet (AES + HMAC).
• Verifier: stores only a secure HMAC check, never the raw derived key.
• Clipboard: auto-clears after 30 seconds.
• UI safety: no key reveals, idle auto-lock, no debug leaks.

Notes:
If an attacker gets your .db and .salt file, they can attempt offline guesses. Argon2id makes this expensive, but you must use a strong, unique master passphrase (12–20+ characters). If your computer has malware (keylogger, RAM scraper), no local manager can protect you.

-------------------------------

• CREDITS:
This project was programmed in Python 3.11 by James Saoumi.

Thanks to:

• HIBP API (Troy Hunt)
• CustomTkinter
• Pillow
• cryptography
• argon2-cffi
• pysqlcipher3

----------------------

BEFORE RUNNING:

• Install dependencies:

- customtkinter
- Pillow
- cryptography
- argon2-cffi
- pysqlcipher3
- requests
- pyperclip

Run it:
python run.py

-------------------------------

First launch:

Create a master key (your passphrase).

Select or create a .db vault. New vaults use SQLCipher + Argon2id.

-------------------------------

HOW TO USE:

1) Generate a master key when first opening. Do not forget it.

2) Select or create a DB file (.db and .db.salt must stay together).

3) Add credentials (website/email/password).

• Retrieve or delete credentials (via buttons, R/D hotkeys). Retrieve shows a copy button.
• Use the "Compromised?" button to check passwords against HIBP.
• Nuke button deletes all entries in the vault.
• Vault auto-locks after inactivity.

------------------------------

BINDS & SHORTCUTS:

• Right Arrow = Select first entry in listbox
• Left Arrow = Clear selection and clear retrieved fields
• Up/Down Arrow = Navigate listbox
• R = Retrieve
• D = Delete
• Enter (in Add Password box) = Submit
• Logo cube = toggle A→Z/Z→A sorting
• Middle-mouse drag = draw trail

-------------------------------

PACKAGING WITH PYINSTALLER:
See CustomTkinter packaging guide. Example:

pyinstaller --onedir --windowed --icon="PW_MNGR.ico" --add-data "pwmanager:pwmanager/" run.py

FEEDBACK:
Please open an issue if you hit bugs, have suggestions, or want features improved. Security feedback is especially welcome.
