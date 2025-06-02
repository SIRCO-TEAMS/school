# Python Monitoring & Security App – Full Documentation & GUI Design

## Table of Contents
1. [Introduction](#introduction)
2. [Creating the EXE Installer](#creating-the-exe-installer)
3. [Core App Functionality](#core-app-functionality)
4. [GUI Design & Owner Panel](#gui-design--owner-panel)
5. [Detailed Scenarios](#detailed-scenarios)
6. [Server-Side Setup & Secure Communication](#server-side-setup--secure-communication)
7. [Checksum Verification](#checksum-verification)
8. [Security, Encryption, and Authentication](#security-encryption-and-authentication)
9. [Installation & Secure Connection Workflow](#installation--secure-connection-workflow)
10. [User Guide](#user-guide)
11. [Final Summary](#final-summary)

---

## 1. Introduction
This documentation outlines a comprehensive Python-based monitoring and security app intended for managed environments (schools, corporations, etc.) with full user consent and transparency. The app:

- Monitors and logs system events.
- Triggers real-time notifications on critical activities.
- Uninstalls with secure backup deletion.
- Uses AES-256 encryption and SHA-256 hashing for data security.
- Verifies file integrity with checksum verification.
- Communicates securely with a remote Node.js server.
- Provides an intuitive, centrally designed GUI with an advanced Owner Panel.

---

## 2. Creating the EXE Installer

### Step 1: Install PyInstaller
```bash
pip install pyinstaller
```

### Step 2: Build the EXE
```bash
pyinstaller --onefile app.py
```
The executable will be located in the `dist` folder as `app.exe`.

### Installer Behavior
- **User Consent:** Prompts for consent before installation.
- **Admin Privileges:** Requests administrator rights (UAC prompt) to perform tasks (e.g., Windows Defender exclusions, startup registration).
- **Startup Registration:** Automatically adds the app to Windows startup.
- **Removal Protection:** Full removal only via uninstallation.

*Ensure these installer behaviors are built into the Python app before packaging.*

---

## 3. Core App Functionality

### Key Features
- **Background Monitoring:** Runs in the background, logging system events (e.g., app usage, logins).
- **Uninstallation Requests:** Detects uninstallation attempts and, upon request, deletes local backups while logging the event.
- **Password Protection:** Sensitive actions require admin credentials secured via hashing (SHA-256) or AES-256 encryption.
- **Server Communication:** Logs and alerts are sent in real time to a secure remote server.
- **Backup Management:** Local backups are automatically deleted upon an uninstall attempt—but the logs remain.

#### Example Python Code – Core Functions
```python
import os
import logging
import hashlib
import requests

# Configure logging; all entries go to activity.log
logging.basicConfig(filename="activity.log", level=logging.INFO)

def monitor_system():
    """Start logging system events."""
    logging.info("Monitoring active.")

def send_notification(event):
    """Sends critical alerts to the secure logging server."""
    server_url = "https://secure-server.com/notify"
    data = {"event": event, "user": os.getlogin()}
    requests.post(server_url, json=data)

def encrypt_password(password):
    """Secures the password via SHA-256."""
    return hashlib.sha256(password.encode()).hexdigest()

monitor_system()
```

---

## 4. GUI Design & Owner Panel

### Visual Design Overview
The app’s graphical user interface is designed to be clean, intuitive, and centered. The main window is divided into three sections:
- **Header:** Displays the application title.
- **Content:** Centrally laid out buttons that provide quick access to key functions.
- **Footer:** Shows the current status (e.g., "Monitoring Active").

#### Main Window Layout
- **Header:** A colored bar at the top with the title "Monitoring Control Panel".
- **Content Area:** Centrally placed buttons arranged in a grid:
  - **Pause Monitoring**
  - **View Logs**
  - **Adjust Sensitivity**
  - **Force Backup Deletion**
  - **Owner Panel** (opens additional administrative controls)
- **Footer:** Displays status messages in a flat, consistent color.

#### Owner Panel Design
The Owner Panel is a separate window (pop-up) that opens upon clicking the "Owner Panel" button. It includes:
- A title and header identifying it as "Owner Panel — Administrator Access".
- A log viewer (using a listbox) that displays all logs.
- Buttons to refresh or filter logs.
- Additional controls (if needed) for advanced administrative tasks.

### Example GUI Implementation in Tkinter
Below is an example Python code snippet using Tkinter which implements the described layout. You can adjust styles (colors, fonts, dimensions) as needed.

```python
import tkinter as tk

class MonitoringGUI:
    def __init__(self, master):
        self.master = master
        self.master.title("Monitoring Control Panel")
        self.master.geometry("800x600")  # Set window size

        # Header Frame
        self.header_frame = tk.Frame(master, height=50, bg="#2E86C1")
        self.header_frame.pack(fill="x")
        self.title_label = tk.Label(self.header_frame, text="Monitoring Control Panel", 
                                    fg="white", bg="#2E86C1", font=("Arial", 18))
        self.title_label.pack(pady=10)

        # Content Frame for central buttons
        self.content_frame = tk.Frame(master, bg="#F8F9F9")
        self.content_frame.pack(expand=True, fill="both")

        # Grid layout for buttons
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

        # Footer Frame
        self.footer_frame = tk.Frame(master, height=30, bg="#2E86C1")
        self.footer_frame.pack(fill="x")
        self.status_label = tk.Label(self.footer_frame, text="Status: Active", fg="white", bg="#2E86C1", font=("Arial", 10))
        self.status_label.pack(pady=5)

    def pause_monitoring(self):
        self.status_label.config(text="Status: Monitoring Paused")

    def view_logs(self):
        # Placeholder method for viewing logs
        self.status_label.config(text="Status: Viewing Logs")

    def adjust_sensitivity(self):
        # Placeholder method for adjusting sensitivity
        self.status_label.config(text="Status: Adjusting Sensitivity")

    def force_delete_backups(self):
        # Placeholder method for forcing backup deletion
        self.status_label.config(text="Status: Backups Deleted")

    def show_owner_panel(self):
        owner_panel = tk.Toplevel(self.master)
        owner_panel.title("Owner Panel")
        owner_panel.geometry("600x400")
        
        header = tk.Label(owner_panel, text="Owner Panel — Administrator Access", font=("Arial", 16), fg="white", bg="#2C3E50")
        header.pack(fill="x", pady=10)
        
        # Log viewer section
        log_label = tk.Label(owner_panel, text="System Logs:", font=("Arial", 12))
        log_label.pack(pady=(10, 0))
        self.log_listbox = tk.Listbox(owner_panel, width=70, height=15)
        self.log_listbox.pack(padx=20, pady=10)
        
        # Button to refresh logs
        refresh_button = tk.Button(owner_panel, text="Refresh Logs", command=self.refresh_logs)
        refresh_button.pack(pady=5)

    def refresh_logs(self):
        # Placeholder method to refresh logs in the owner panel
        self.status_label.config(text="Status: Logs Refreshed")

if __name__ == "__main__":
    root = tk.Tk()
    app = MonitoringGUI(root)
    root.mainloop()
```

### GUI Design Breakdown
- **Header:** A consistent blue header (`#2E86C1`) with white text for clear identification.
- **Central Content:**
  - Uses a grid layout to center buttons.
  - Buttons are spaciously arranged with clear labels such as "Pause Monitoring" and "Owner Panel."
- **Footer:** Displays a live status message to keep administrators aware of the current state.
- **Owner Panel:** This additional window (opened as a `Toplevel` instance) includes a header, a Listbox for log viewing, and a refresh button. This panel is reserved for advanced administrative tasks and provides deeper system insight.

---

## 5. Detailed Scenarios

### Scenario 1: Student Uninstallation Attempt
- **Action:** Jamie requests the uninstallation password.
- **System Response:** Local backups are deleted immediately; the request is logged and an alert is sent.
- **Outcome:** IT reviews logs and takes disciplinary action.

### Scenario 2: Teacher Bypass Attempt
- **Action:** Mr. Lee attempts to uninstall the app.
- **System Response:** Backups are deleted, and his action is logged. The system flags him for increased monitoring.
- **Outcome:** IT responds with heightened scrutiny and potential consequences.

### Scenario 3: External Backup Strategy
- **Action:** Regular external backups are maintained (e.g., on a hard drive).
- **System Response:** Local backups are deleted on uninstall while external backups remain for cross-referencing.
- **Outcome:** IT leverages external backups for integrity verification and log recovery if needed.

---

## 6. Server-Side Setup & Secure Communication

### Node.js Server Setup
Deploy a remote logging server using Node.js to handle notifications:
```javascript
const express = require('express');
const app = express();
app.use(express.json());

app.post('/notify', (req, res) => {
    console.log("Alert received: ", req.body);
    res.sendStatus(200);
});

app.listen(3000, () => console.log("Server running on port 3000"));
```

### Secure Communication
1. Deploy the Node.js server with HTTPS enabled.
2. Generate a secure key file for client authentication.
3. Allow only clients with the correct key file to connect.
4. Gate administrative access with an owner panel that requires authenticated login.

---

## 7. Checksum Verification

### Generating a SHA-256 Checksum
Use this code to verify that the `app.exe` file is unaltered:
```python
import hashlib

def generate_checksum(filename):
    with open(filename, 'rb') as file:
        data = file.read()
    return hashlib.sha256(data).hexdigest()

print(generate_checksum("app.exe"))
```
Verify the generated checksum against a known good value to ensure file integrity.

---

## 8. Security, Encryption, and Authentication

### AES-256 Encryption for Secure Logs & Data
```python
from Crypto.Cipher import AES
import base64

def encrypt_data(data, key):
    # Pad the data to 32 bytes if necessary
    cipher = AES.new(key.encode(), AES.MODE_ECB)
    padded_data = data.ljust(32)
    return base64.b64encode(cipher.encrypt(padded_data.encode()))

key = "your256bitkeygoeshere"  # Must be 16, 24, or 32 characters
encrypted_log = encrypt_data("System Alert: Uninstall Request", key)
print(encrypted_log)
```

### Authentication & Secure Communication
- **Password Protection:** Sensitive actions require secure admin credentials.
- **HTTPS Communication:** All interactions with the server are secured.
- **Key-Based Access:** Only systems with the correct key file can communicate with the server.
- **Owner Panel Access:** All advanced controls require verified admin login.

---

## 9. Installation & Secure Connection Workflow

1. **Prompt for Server Address:** Ask for the Node server IP and port (e.g., `https://IP:3000`).
2. **Server Verification:** The app verifies that the server is active and uses key-based authentication.
3. **Key File Upload:** Users supply the secure key file to enable authenticated connections.
4. **Settings Storage:** Save server details and key file location securely to maintain future communications.

---

## 10. User Guide

### Getting Started
- **Installation:** Run the EXE installer with admin privileges.
- **Login:** Enter your credentials to access the dashboard.
- **Dashboard:** Monitor logs, view alerts, and adjust settings using the centralized GUI.

### Uninstallation Process
- **Initiation:** An uninstall request causes local backups to be deleted while retaining logs.
- **Logging:** All actions (initiated or canceled) are recorded and notified to IT.
- **Approval:** Full removal requires administrative clearance through the Owner Panel.

---

## 11. Final Summary

- **Advanced Monitoring & Logging:** Constant background tracking of system events.
- **Real-Time Alerts:** Immediate notifications for security events (uninstalls, errors, etc.).
- **Intuitive Admin GUI:** Centrally designed interface with clear, evenly spaced buttons for key functions.
- **Owner Panel:** Provides in-depth log viewing, administrative controls, and advanced settings.
- **Robust Encryption & Authentication:** AES-256 encryption, HTTPS secure communications, and key-based access.
- **Checksum Verification:** Ensures the integrity of the executable file.
- **Installation Workflow:** Guides secure server connection and key management throughout the setup.

---

This document now includes every aspect of the project—from detailed GUI layout (with sample Tkinter code for central buttons and the owner panel) to server setup and security measures. This all-in-one guide should give any developer or AI a complete understanding for implementation. Enjoy building your secure, monitored, and user-friendly application!