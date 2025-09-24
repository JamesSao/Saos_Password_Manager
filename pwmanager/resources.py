import os, sys
from tkinter import PhotoImage
from PIL import Image

def resource_path(relative_path: str) -> str:
    if hasattr(sys, "_MEIPASS"):
        return os.path.join(sys._MEIPASS, relative_path)
    return os.path.join(os.path.abspath("."), relative_path)

def load_logo_images():
    # Supports both frozen and normal runs; fallback to PW_MNGR.png in cwd
    path = resource_path("PW_MNGR.png")
    try:
        light = Image.open(path)
        dark = Image.open(path)
    except Exception:
        # if missing, create a 65x65 placeholder
        light = Image.new("RGBA", (65, 65), (139, 195, 74, 255))
        dark = light.copy()
    return light, dark

def load_tk_icon():
    try:
        return PhotoImage(file=resource_path("PW_MNGR.png"))
    except Exception:
        return None
