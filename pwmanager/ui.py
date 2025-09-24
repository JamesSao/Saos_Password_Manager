import os
import tkinter as tk
import customtkinter as ctk
from tkinter import filedialog, messagebox

from cryptography.fernet import InvalidToken
from .crypto_utils import (
    encrypt_str, decrypt_str,
    derive_fernet_pbkdf2, derive_fernet_argon2id
)
from .db_utils import (
    connect_plain,
    open_sqlcipher_with_master,
    ensure_passwords_table,
    ensure_meta_table,
    get_or_create_salt,
    set_or_check_verifier,
    has_legacy_keys_table,
    legacy_key_matches,
    list_websites,
    insert_password,
    get_credentials,
    delete_website,
    delete_all_rows,
    sidecar_salt_path,
)
from .pwned import pwned_api_check
from .resources import load_logo_images, load_tk_icon


# ---------- styling helpers (CustomTkinter-focused) ----------

GREEN = "#8bc34a"
GREEN_DIM = "#7cb342"
TEXT_LIGHT = "#c5e1a5"
BG_DARK = "black"
HL_NEUTRAL = "grey25"


def style_entry_add(e: ctk.CTkEntry):
    """
    Style for the Add fields (website/email/password).
    Grey ring idle, green-ish on focus (via attach_focus_glow).
    """
    e.configure(
        fg_color=BG_DARK,
        text_color=TEXT_LIGHT,
        border_color=HL_NEUTRAL,   # idle
        border_width=2,
        corner_radius=10,
        width=220,
        height=28,
    )


def style_entry_retrieve(e: ctk.CTkEntry):
    """
    Style for the Retrieve fields (email/password).
    Always green accent like the original.
    """
    e.configure(
        fg_color=BG_DARK,
        text_color=GREEN,
        border_color=GREEN,
        border_width=2,
        corner_radius=10,
        width=320,
        height=28,
    )


def style_entry_generator(e: ctk.CTkEntry):
    """
    Style for the password generator textbox.
    """
    e.configure(
        fg_color=BG_DARK,
        text_color=GREEN,
        border_color="lightgray",
        border_width=2,
        corner_radius=10,
        width=320,
        height=28,
    )


def attach_focus_glow(e: ctk.CTkEntry, idle_color=HL_NEUTRAL, focus_color=TEXT_LIGHT):
    """
    Change border color on focus in/out to simulate the glow.
    """
    def on_focus_in(_):  e.configure(border_color=focus_color)
    def on_focus_out(_): e.configure(border_color=idle_color)
    e.bind("<FocusIn>", on_focus_in)
    e.bind("<FocusOut>", on_focus_out)


class App:
    def __init__(self, root, myfont, master_key, width, height):
        self.root = root
        self.myfont = myfont
        self.master_key = master_key
        self.width = width
        self.height = height

        # runtime state
        self.filepath: str | None = None
        self.f = None           # Fernet instance (Argon2/Scrypt or legacy PBKDF2)
        self.key_b64 = None     # base64 key bytes (for Fernet)
        self.mode = None        # "sqlcipher" | "legacy" | "argon2"

        # build backdrop canvas + draw trail
        self._build_canvas()
        self._bind_draw_trail()

        # hold strong refs for Tk images (macOS stability)
        self.logo_icon = load_tk_icon()
        self.logo_light, self.logo_dark = load_logo_images()
        self.logo_ctk_image = ctk.CTkImage(
            light_image=self.logo_light,
            dark_image=self.logo_dark,
            size=(65, 65)
        )

    def run(self):
        self._logged_in_ui()
        self.root.mainloop()

    # ---- backdrop canvas + draw effect ----
    def _build_canvas(self):
        # keep as tk.Canvas (CustomTkinter doesn't replicate all Canvas APIs)
        self.canvas = tk.Canvas(self.root, width=self.width, height=self.height, bg="gray14", highlightthickness=0)
        self.canvas.place(relx=0.5, rely=0.5, anchor="center")
        # keep it behind all interactive widgets so it never steals first click
        try:
            tk.Misc.lower(self.canvas)  # correct widget z-order lower
        except Exception:
            self.canvas.tk.call('lower', self.canvas._w)

    def _bind_draw_trail(self):
        def draw(event):
            x, y = event.x, event.y
            alpha = 1.0
            oid = self.canvas.create_oval(x-4, y-4, x+4, y+4, fill=f"#{int(alpha*255):02x}0000", outline="")
            def fade():
                nonlocal alpha, oid
                alpha -= 0.1
                if alpha <= 0:
                    self.canvas.delete(oid)
                else:
                    self.canvas.itemconfigure(oid, fill=f"#{int(alpha*255):02x}{int((1-alpha)*255):02x}{0x23:02x}")
                    self.canvas.after(80, fade)
            self.canvas.after(80, fade)
        self.canvas.bind("<B2-Motion>", draw)

    # ---- full UI ----
    def _logged_in_ui(self):
        root = self.root
        width, height = self.width, self.height

        # window & icon
        if self.logo_icon:
            root.iconphoto(False, self.logo_icon)

        # inputs (convert to CTkEntry)
        self.Addwebsite_Txtbox    = ctk.CTkEntry(root, corner_radius=10)
        self.Addemail_Txtbox      = ctk.CTkEntry(root, corner_radius=10)
        self.Addpass_Txtbox       = ctk.CTkEntry(root, corner_radius=10)
        self.RetrievePass_Txtbox  = ctk.CTkEntry(root, corner_radius=10)
        self.RetrieveEmail_Txtbox = ctk.CTkEntry(root, corner_radius=10)

        # styles (restore original look using CTk)
        style_entry_retrieve(self.RetrievePass_Txtbox)
        style_entry_retrieve(self.RetrieveEmail_Txtbox)

        style_entry_add(self.Addwebsite_Txtbox)
        style_entry_add(self.Addemail_Txtbox)
        style_entry_add(self.Addpass_Txtbox)
        # width tweak to mimic previous feel for password add box
        self.Addpass_Txtbox.configure(width=240)

        # focus glow for add fields (grey → green-ish on focus)
        attach_focus_glow(self.Addwebsite_Txtbox, idle_color=HL_NEUTRAL, focus_color=TEXT_LIGHT)
        attach_focus_glow(self.Addemail_Txtbox, idle_color=HL_NEUTRAL, focus_color=TEXT_LIGHT)
        attach_focus_glow(self.Addpass_Txtbox, idle_color=HL_NEUTRAL, focus_color=TEXT_LIGHT)

        # labels/placements (CTkLabel)
        ctk.CTkLabel(master=root, text="Add New Website", text_color="lightgray").place(rely=0.01, relx=0.01, anchor="nw")
        ctk.CTkLabel(master=root, text="Add New Email", text_color="lightgray").place(rely=0.01, relx=0.3, anchor="nw")
        ctk.CTkLabel(master=root, text="Add New Password", text_color="lightgray").place(rely=0.01, relx=0.585, anchor="nw")
        self.Addwebsite_Txtbox.place(rely=0.073, relx=0.01, anchor="nw")
        self.Addemail_Txtbox.place(rely=0.073, relx=0.3, anchor="nw")
        self.Addpass_Txtbox.place(rely=0.073, relx=0.585, anchor="nw")

        # submit logic
        def submit():
            if not self.filepath or not self.f:
                messagebox.showerror("Error", "No DB file selected dude")
                return
            website = self.Addwebsite_Txtbox.get().strip()
            password = self.Addpass_Txtbox.get().strip()
            email = self.Addemail_Txtbox.get().strip()
            if not website or not password:
                messagebox.showerror("Error", "Please enter a website and password")
                return
            enc_pw = encrypt_str(self.f, password)
            enc_email = encrypt_str(self.f, email) if email else None
            try:
                with self._open_conn() as conn:
                    insert_password(conn, website, enc_pw, enc_email)
                messagebox.showinfo("Success", "Website added to list")
                self.Addwebsite_Txtbox.delete(0, "end")
                self.Addpass_Txtbox.delete(0, "end")
                self.Addemail_Txtbox.delete(0, "end")
                refresh_listbox()
            except ValueError as e:
                messagebox.showerror("Error", str(e))
            except Exception as e:
                messagebox.showerror("Error", str(e))

        Submit_Btn = ctk.CTkButton(
            master=root, text="Submit", command=submit,
            fg_color="black", text_color=GREEN, hover_color="white",
            height=28, border_color="white", border_width=1
        )
        Submit_Btn.configure(cursor="hand2")
        Submit_Btn.place(rely=0.18, relx=0.96, anchor="e")
        self.Addpass_Txtbox.bind("<Return>", lambda e: submit())

        # separators (keep as tk.Canvas for 1px crisp lines)
        line1 = tk.Canvas(master=root, width=width, height=3, bg="gray16", highlightthickness=0)
        line1.place(rely=0.18, anchor="nw", relwidth=0.66)

        # password generator
        ctk.CTkLabel(master=root, text="Random password generator", text_color="lightgray").place(rely=0.25, relx=0.81, anchor="e")
        PWGen_Txtbox = ctk.CTkEntry(root, corner_radius=10)
        style_entry_generator(PWGen_Txtbox)
        PWGen_Txtbox.place(rely=0.32, relx=0.96, anchor="e")

        lbl_len = ctk.CTkLabel(master=root, text="#", text_color=GREEN)
        lbl_len.place(rely=0.39, relx=0.975, anchor="e")

        def slider_event(v): lbl_len.configure(text=int(float(v)))
        slider = ctk.CTkSlider(master=root, from_=8, to=32, command=slider_event,
                               number_of_steps=24, button_color=GREEN, button_hover_color=GREEN_DIM)
        slider.place(rely=0.39, relx=0.93, anchor="e")

        import secrets
        def generate_password():
            n = int(slider.get())
            chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!#$%&*+-=?@^_[]}{?><:;#$%"
            pw = "".join(secrets.choice(chars) for _ in range(n))
            PWGen_Txtbox.delete(0, "end")
            PWGen_Txtbox.insert(0, pw)
            return pw

        ctk.CTkButton(master=root, text="Generate", command=generate_password,
                      fg_color="black", text_color=GREEN, hover_color="white",
                      height=28, border_color="lightgray", border_width=1).place(rely=0.455, relx=0.96, anchor="e")

        # second separator
        line2 = tk.Canvas(master=root, width=width, height=3, bg="gray16", highlightthickness=0)
        line2.place(relx=1.0, relwidth=0.6, rely=0.51, anchor="ne")

        # saved websites list
        ctk.CTkLabel(master=root, text="Saved Websites").place(rely=0.29, relx=0.05, anchor="w")

        # container around listbox (CTkFrame)
        sframe = ctk.CTkFrame(root, fg_color=GREEN, corner_radius=6)
        sframe.place(rely=0.32, relx=0.05, anchor="nw")
        sframe.configure(width=10, height=10)  # just to ensure it draws; listbox expands

        Websites_Listbox = tk.Listbox(sframe)
        scrollbar = ctk.CTkScrollbar(master=root, orientation="vertical", command=Websites_Listbox.yview,
                                     button_color="lightgray", button_hover_color="black")
        scrollbar.place(rely=0.33, relx=0.01, anchor="nw")
        Websites_Listbox.config(height=14, yscrollcommand=scrollbar.set, bg=BG_DARK, fg=GREEN, width=25,
                                selectforeground="black", selectbackground=GREEN, highlightthickness=0)
        Websites_Listbox.pack(side="left", fill="both", expand=True)

        # sort toggle via logo
        self.logo_btn = ctk.CTkButton(master=root, text="", image=self.logo_ctk_image,
                                      fg_color="transparent", bg_color="transparent",
                                      hover_color="gray14", width=40,
                                      command=lambda: sort_listbox_az())
        self.logo_btn.place(rely=0.62, relx=0.98, anchor="e")
        self.logo_btn.configure(cursor="hand2")

        def sort_listbox_az():
            items = list(Websites_Listbox.get(0, "end"))
            items = sorted(items) if items != sorted(items) else sorted(items, reverse=True)
            Websites_Listbox.delete(0, "end")
            for it in items:
                Websites_Listbox.insert("end", it)

        # login/start dialog (use CTkToplevel)
        Startdialog = ctk.CTkToplevel(root)
        Startdialog.geometry("500x300+15+15")
        Startdialog.title("Log In")
        Startdialog.resizable(False, False)
        if self.logo_icon:
            Startdialog.iconphoto(False, self.logo_icon)
            Startdialog._icon_ref = self.logo_icon
        Startdialog.configure(fg_color=GREEN)

        def refresh_listbox():
            if not self.filepath:
                return
            with self._open_conn() as conn:
                sites = list_websites(conn)
            Websites_Listbox.delete(0, "end")
            for s in sites:
                Websites_Listbox.insert("end", s)

        # crypto init after DB is chosen/created
        def init_crypto_for_opened_conn(conn) -> bool:
            """
            After a connection is open (plain or SQLCipher), derive the Fernet key
            for field-level encryption using Argon2id/Scrypt with per-vault salt in meta.
            Legacy fallback: if keys table exists, use PBKDF2 & legacy verifier.
            """
            # Try modern meta (salt + HMAC verifier)
            ensure_meta_table(conn)
            try:
                salt = get_or_create_salt(conn)
                f, key_b64 = derive_fernet_argon2id(self.master_key, salt)
                if not set_or_check_verifier(conn, key_b64):
                    return False
                self.f = f
                self.key_b64 = key_b64
                self.mode = "sqlcipher" if self._has_sidecar() else "argon2"
                return True
            except Exception:
                pass

            # Legacy fallback
            if has_legacy_keys_table(conn):
                f, key_b64 = derive_fernet_pbkdf2(self.master_key)
                if legacy_key_matches(conn, key_b64.decode()):
                    self.f = f
                    self.key_b64 = key_b64
                    self.mode = "legacy"
                    return True
            return False

        def _post_login_config():
            # bring up main window
            self.root.deiconify()
            # fully remove login dialog so it can't steal focus
            try:
                Startdialog.destroy()
            except Exception:
                pass
            refresh_listbox()
            animate_headers()
            # force focus so first click isn't lost on macOS
            self.root.after(50, self.root.focus_force)
            messagebox.showinfo("Hey", ".DB file is loaded")

        def _open_sqlcipher_new(db_path: str):
            """Create a brand new SQLCipher DB and initialize tables + meta."""
            try:
                conn, raw_key, salt_sidecar = open_sqlcipher_with_master(self.master_key, db_path)
            except Exception as e:
                messagebox.showerror("Error", f"Failed to create SQLCipher DB: {e}")
                return None

            try:
                ensure_passwords_table(conn)
                ok = init_crypto_for_opened_conn(conn)
                if not ok:
                    raise RuntimeError("Failed to initialize encryption meta.")
                return conn
            except Exception as e:
                try:
                    conn.close()
                except Exception:
                    pass
                messagebox.showerror("Error", f"Failed to initialize DB: {e}")
                return None

        def SelectDBfile():
            self.filepath = filedialog.askopenfilename(defaultextension=".db")
            if not self.filepath:
                return

            if self._has_sidecar():
                # Open as SQLCipher
                try:
                    conn, raw_key, salt_sidecar = open_sqlcipher_with_master(self.master_key, self.filepath)
                except Exception as e:
                    messagebox.showerror("Error", f"Failed to open encrypted DB: {e}")
                    return
                try:
                    ensure_passwords_table(conn)
                    ok = init_crypto_for_opened_conn(conn)
                finally:
                    conn.close()
                if not ok:
                    messagebox.showerror("Error", "Invalid key for this encrypted database.")
                    return
                _post_login_config()
                return

            # Otherwise try plain SQLite (legacy or modern without SQLCipher)
            try:
                with connect_plain(self.filepath) as conn:
                    ensure_passwords_table(conn)
                    ok = init_crypto_for_opened_conn(conn)
            except Exception as e:
                messagebox.showerror("Error", f"Failed to open DB: {e}")
                return
            if not ok:
                messagebox.showerror("Error", "Invalid key for this database.")
                return
            _post_login_config()

        def SaveDBfile():
            # Always create NEW vaults as SQLCipher-encrypted
            self.filepath = filedialog.asksaveasfilename(defaultextension=".db")
            if not self.filepath:
                return
            conn = _open_sqlcipher_new(self.filepath)
            if not conn:
                return
            conn.close()

            messagebox.showinfo(
                "Hey",
                "Your encrypted .DB file is saved & loaded. A '.salt' sidecar contains the KDF salt for SQLCipher.\n"
                "Keep both files together if you move the vault."
            )
            _post_login_config()

        # Start dialog buttons (CTkButton)
        sel_btn = ctk.CTkButton(
            master=Startdialog, text="Select DB File", command=SelectDBfile,
            border_width=1, fg_color="black", text_color=GREEN,
            hover_color="white", height=36, border_color=GREEN
        )
        new_btn = ctk.CTkButton(
            master=Startdialog, text="Save new DB file (encrypted with SQLCipher)", command=SaveDBfile,
            border_width=1, fg_color="black", text_color=GREEN,
            hover_color="white", height=36, border_color=GREEN
        )
        # simple grid
        sel_btn.grid(row=0, column=0, sticky="nswe", padx=20, pady=(20, 10))
        new_btn.grid(row=1, column=0, sticky="nswe", padx=20, pady=(10, 20))
        Startdialog.columnconfigure(0, weight=1)
        Startdialog.rowconfigure(0, weight=1)
        Startdialog.rowconfigure(1, weight=1)
        root.withdraw()

        # credentials retrieval
        def show_copy_button():
            Copy_Pass_Btn.place(rely=0.85, relx=0.5, anchor="w")

        def retrieve(_):
            if not self.filepath or not self.f:
                messagebox.showinfo("Error", "Please select a .DB file first")
                return
            sel = Websites_Listbox.curselection()
            if not sel:
                messagebox.showerror("Error", "No website chosen from list")
                return
            website = Websites_Listbox.get(sel)
            with self._open_conn() as conn:
                row = get_credentials(conn, website)
            if row:
                try:
                    Compromised_Btn.place(rely=0.94, relx=0.48, anchor="w")
                    dec_pw = decrypt_str(self.f, row[0])
                    dec_email = decrypt_str(self.f, row[1]) if row[1] else "{n/a}"
                    self.RetrievePass_Txtbox.delete(0, "end")
                    self.RetrievePass_Txtbox.insert(0, dec_pw)
                    self.RetrieveEmail_Txtbox.delete(0, "end")
                    self.RetrieveEmail_Txtbox.insert(0, dec_email)
                    show_copy_button()
                except InvalidToken:
                    messagebox.showinfo(
                        "Error",
                        "Invalid Token for the database chosen, please check your encryption/login key",
                    )
            else:
                messagebox.showinfo("Sorry", "Website not found")

        event = tk.Event(); event.keysym = "r"
        RetrievePass_Btn = ctk.CTkButton(
            master=root, text="(r)", command=lambda: retrieve(event),
            fg_color="black", text_color=GREEN, hover_color="white",
            height=28, border_color=GREEN, border_width=1, width=45
        )
        RetrievePass_Btn.configure(cursor="hand2")
        RetrievePass_Btn.place(rely=0.70, relx=0.35, anchor="w")
        Websites_Listbox.bind("<Key-r>", retrieve)

        # selection navigation
        def highlight_first_entry(ev):
            if ev.keysym == "Right":
                Websites_Listbox.focus_set()
                Websites_Listbox.activate(0)
                Websites_Listbox.selection_clear(0, "end")
                Websites_Listbox.selection_set(0)
                Websites_Listbox.yview_moveto(0)
        def move_selection(ev):
            if ev.keysym == "Left":
                root.focus_set()
                Websites_Listbox.selection_clear(0, "end")
                Websites_Listbox.activate(0)
                Websites_Listbox.selection_set(0)
                self.RetrievePass_Txtbox.delete(0, "end")
                self.RetrieveEmail_Txtbox.delete(0, "end")
        root.bind("<Right>", highlight_first_entry)
        root.bind("<Left>", move_selection)

        # place retrieve fields (CTkEntry positions)
        self.RetrieveEmail_Txtbox.place(rely=0.855, relx=0.05, anchor="w")
        self.RetrievePass_Txtbox.place(rely=0.93, relx=0.05, anchor="w")

        # delete selected site
        def delete_selected(_):
            sel = Websites_Listbox.curselection()
            if not sel:
                messagebox.showinfo("Error", "Please select a website to delete")
                return
            website = Websites_Listbox.get(sel)
            if messagebox.askyesno("Confirm Deletion", f"Are you sure you want to delete {website}?"):
                with self._open_conn() as conn:
                    delete_website(conn, website)
                refresh_listbox()

        event_d = tk.Event(); event_d.keysym = "d"
        DeletePass_Btn = ctk.CTkButton(
            master=root, text="(d)", command=lambda: delete_selected(event_d),
            fg_color="black", text_color=GREEN, hover_color="white",
            height=28, border_color=GREEN, border_width=1, width=45
        )
        DeletePass_Btn.configure(cursor="hand2")
        DeletePass_Btn.place(rely=0.77, relx=0.35, anchor="w")
        Websites_Listbox.bind("<Key-d>", delete_selected)

        # copy pw button + clipboard auto-clear
        def copy_text():
            text = self.RetrievePass_Txtbox.get()
            if not text:
                return
            root.clipboard_clear()
            root.clipboard_append(text)
            messagebox.showinfo("Success", "Password copied to clipboard (auto-clears in 30s)")
            Copy_Pass_Btn.place_forget()
            Compromised_Btn.place(rely=0.94, relx=0.48, anchor="w")
            self.RetrievePass_Txtbox.delete(0, "end")

            # Auto-clear clipboard after 30s if unchanged
            def clear_clip_if_unchanged(prev=text):
                try:
                    current = root.clipboard_get()
                except Exception:
                    return
                if current == prev:
                    root.clipboard_clear()
            root.after(30_000, clear_clip_if_unchanged)

        Copy_Pass_Btn = ctk.CTkButton(master=root, text="Copy pw", command=copy_text,
                                      fg_color=GREEN, text_color="black", hover_color="white",
                                      height=28, border_color="white", width=70)
        Copy_Pass_Btn.configure(cursor="hand2")
        Copy_Pass_Btn.bind("<Button-3>", lambda e: (Copy_Pass_Btn.place_forget(),
                                                    Compromised_Btn.place(rely=0.8, relx=0.48, anchor="w")))

        # nuke all
        def delete_all():
            if not self.filepath:
                messagebox.showinfo("Error", "Please select a .DB file first")
                return
            if messagebox.askyesno("Confirm", "Are you sure you want to delete everything?"):
                with self._open_conn() as conn:
                    delete_all_rows(conn)
                messagebox.showinfo("Success", "All websites, emails and associated passwords have been deleted.")
                refresh_listbox()

        Nuke_Btn = ctk.CTkButton(master=root, text="Nuke", command=delete_all,
                                 fg_color="black", text_color=GREEN, hover_color="white",
                                 height=28, border_color=GREEN, border_width=1, width=60)
        Nuke_Btn.configure(cursor="spider")
        Nuke_Btn.place(rely=0.95, relx=1, anchor="e")

        # compromised check
        def check_password():
            pw = self.RetrievePass_Txtbox.get()
            if not pw:
                messagebox.showerror(
                    "Error",
                    "No password found. Type a password into the left textbox or use Retrieve first."
                )
                return
            count = pwned_api_check(pw)
            if count:
                messagebox.showerror("Error", f"{pw} was found {count} times... change it!")
            else:
                messagebox.showinfo("Info", f"{pw} was NOT found in known leaks. Carry on!")

        Compromised_Btn = ctk.CTkButton(master=root, text="Compromised?", command=check_password,
                                        fg_color="black", text_color=GREEN, hover_color="white",
                                        height=28, border_color="lightgray", border_width=1, width=120)
        Compromised_Btn.place(rely=0.94, relx=0.48, anchor="w")
        Compromised_Btn.configure(cursor="hand2")

        # --- Smooth, slowed animation with progressive overwrite (top L->R, bottom R->L) ---

        def animate_headers():
            # keep as tk.Canvas for the progressive stripe overwrite effect
            self.canv1 = tk.Canvas(master=root, width=width, height=3, bg="gray16", highlightthickness=0)
            self.canv1.place(rely=0.18, anchor="nw", relwidth=0.66)
            self.canv2 = tk.Canvas(master=root, width=width, height=3, bg="gray16", highlightthickness=0)
            self.canv2.place(relx=1.0, relwidth=0.6, rely=0.51, anchor="ne")

            colors_green = ("#003300","#005000","#007f00","#00b300","#00e600",
                            "#00eb00","#00e600","#00b300","#007f00","#005000")
            colors_gray  = ("#333333","#4d4d4d","#808080","#a6a6a6","#cccccc",
                            "#e6e6e6","#cccccc","#a6a6a6","#808080","#4d4d4d")

            step_px  = 4     # stripe width
            delay_ms = 50   # delay per stripe

            use_green = True
            phase = "top"
            idx_top = 0
            idx_bot = None

            def init_stripes(canvas, forward=True):
                w = int(canvas.winfo_width())
                if w <= 0:
                    return [], 0
                stripes = []
                if forward:
                    for x in range(0, w, step_px):
                        rid = canvas.create_rectangle(x, 0, min(x + step_px, w), 3, fill="", outline="")
                        stripes.append(rid)
                else:
                    for x in range(w - 1, -1, -step_px):
                        rid = canvas.create_rectangle(max(x - step_px + 1, 0), 0, x + 1, 3, fill="", outline="")
                        stripes.append(rid)
                return stripes, w

            self.canv1.update_idletasks()
            self.canv2.update_idletasks()
            top_stripes, _ = init_stripes(self.canv1, forward=True)
            bot_stripes, _ = init_stripes(self.canv2, forward=False)

            def color_top(palette, x):
                return palette[int(x / (width / 1.5) * len(palette)) % len(palette)]

            def color_bot(palette, i):
                base = (width - 1 - i) / (width / 1.5) * len(palette) + len(palette) / 2
                return palette[int(base) % len(palette)]

            def step():
                nonlocal use_green, phase, idx_top, idx_bot

                if not root.winfo_exists() or not self.canv1.winfo_exists() or not self.canv2.winfo_exists():
                    return

                palette = colors_green if use_green else colors_gray

                if phase == "top":
                    if idx_top < len(top_stripes):
                        x_left = idx_top * step_px
                        try:
                            self.canv1.itemconfigure(top_stripes[idx_top], fill=color_top(palette, x_left))
                        except tk.TclError:
                            return
                        idx_top += 1
                        root.after(delay_ms, step)
                        return
                    else:
                        phase = "bot"
                        idx_bot = 0
                        root.after(delay_ms, step)
                        return

                if phase == "bot":
                    w2 = int(self.canv2.winfo_width())
                    if idx_bot < len(bot_stripes):
                        i = w2 - 1 - (idx_bot * step_px)  # right -> left
                        try:
                            self.canv2.itemconfigure(bot_stripes[idx_bot], fill=color_bot(palette, i))
                        except tk.TclError:
                            return
                        idx_bot += 1
                        root.after(delay_ms, step)
                        return
                    else:
                        use_green = not use_green
                        phase = "top"
                        idx_top = 0
                        root.after(delay_ms, step)
                        return

            root.after(200, step)

        # ensure the main window has focus after layout
        self.root.after(0, self.root.focus_force)

    # ----- helpers -----

    def _has_sidecar(self) -> bool:
        return bool(self.filepath) and os.path.exists(sidecar_salt_path(self.filepath))

    def _open_conn(self):
        """
        Connection opener, picking SQLCipher or plain based on sidecar presence.
        """
        if self._has_sidecar():
            from .db_utils import open_sqlcipher_with_master
            conn, _, _ = open_sqlcipher_with_master(self.master_key, self.filepath)
            return conn
        return connect_plain(self.filepath)
