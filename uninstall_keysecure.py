import os
import shutil
import sys

if os.name == "nt":
    APP_DIR = os.path.join(os.environ["APPDATA"], "KeySecureApp")
    SHORTCUT_NAME = "KeySecureApp.lnk"
    try:
        import winshell
        startup = winshell.startup()
        shortcut = os.path.join(startup, SHORTCUT_NAME)
        if os.path.exists(shortcut):
            os.remove(shortcut)
    except Exception:
        pass
else:
    APP_DIR = os.path.expanduser("~/.keysecureapp")

# Remove app directory and all contents
try:
    if os.path.exists(APP_DIR):
        shutil.rmtree(APP_DIR)
        print(f"Removed {APP_DIR}")
except Exception as e:
    print(f"Error removing app directory: {e}")

print("KeySecure app uninstalled.")
