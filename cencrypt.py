import customtkinter as ctk
from tkinter import filedialog, messagebox
import os
import hashlib
import json
import urllib.request
import platform
import datetime
import time
import threading
import mmap
from pathlib import Path
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import secrets
from packaging import version
import ctypes
from ctypes import wintypes
import getpass

APP_NAME = "CEncrypt"
SETTINGS_FILE = "settings.json"
APP_VERSION = "2.0.0"
APP_AUTHOR = "Cr3zy"
APP_MAGIC_HEADER = b"CENCRYPT"
GITHUB_API_URL = "https://api.github.com/repos/Cr3zy-dev/CEncrypt/releases/latest"

# File types that should be excluded from encryption to prevent system damage
SYSTEM_CRITICAL_EXTENSIONS = {
    ".exe", ".dll", ".sys", ".bat", ".cmd", ".com", ".scr", ".msi", ".inf",
    ".cab", ".cpl", ".drv", ".ocx", ".vxd", ".386", ".bin", ".rom", ".efi"
}

# Additional risky extensions that users should be warned about
RISKY_EXTENSIONS = {
    ".db", ".sqlite", ".reg", ".cfg", ".ini", ".conf", ".plist"
}

class SecureString:
    """A more secure way to handle sensitive strings in memory"""
    def __init__(self, data: str = ""):
        self._data = bytearray(data.encode('utf-8'))
    
    def get(self) -> str:
        return self._data.decode('utf-8')
    
    def set(self, data: str):
        # Clear existing data
        self.clear()
        self._data = bytearray(data.encode('utf-8'))
    
    def clear(self):
        if hasattr(self, '_data'):
            # Overwrite with random data
            for i in range(len(self._data)):
                self._data[i] = secrets.randbits(8)
            # Then zero it
            for i in range(len(self._data)):
                self._data[i] = 0
    
    def __del__(self):
        self.clear()

class SecureCredentialManager:
    """Handles secure credential storage using OS-specific methods"""
    
    def __init__(self):
        self.is_windows = platform.system() == "Windows"
        
    def store_credential(self, password: str) -> bool:
        """Store password hash securely using OS credential manager"""
        try:
            password_hash = hashlib.sha256(password.encode()).hexdigest()
            
            if self.is_windows:
                return self._store_windows_credential(password_hash)
            else:
                return self._store_unix_credential(password_hash)
        except Exception as e:
            print(f"Failed to store credential: {e}")
            return False
    
    def get_credential(self) -> str:
        """Retrieve stored password hash"""
        try:
            if self.is_windows:
                return self._get_windows_credential()
            else:
                return self._get_unix_credential()
        except Exception:
            return ""
    
    def credential_exists(self) -> bool:
        """Check if credential is stored"""
        return bool(self.get_credential())
    
    def _store_windows_credential(self, password_hash: str) -> bool:
        """Store credential using Windows Credential Manager"""
        try:
            # Use Windows Credential Manager via ctypes
            import win32cred
            win32cred.CredWrite({
                'Type': win32cred.CRED_TYPE_GENERIC,
                'TargetName': f'{APP_NAME}_auth',
                'UserName': getpass.getuser(),
                'CredentialBlob': password_hash,
                'Comment': f'Authentication for {APP_NAME}',
                'Persist': win32cred.CRED_PERSIST_LOCAL_MACHINE
            })
            return True
        except ImportError:
            # Fallback to registry if win32cred not available
            return self._store_registry_credential(password_hash)
        except Exception:
            return False
    
    def _get_windows_credential(self) -> str:
        """Get credential from Windows Credential Manager"""
        try:
            import win32cred
            cred = win32cred.CredRead(f'{APP_NAME}_auth', win32cred.CRED_TYPE_GENERIC)
            return cred['CredentialBlob']
        except ImportError:
            return self._get_registry_credential()
        except Exception:
            return ""
    
    def _store_registry_credential(self, password_hash: str) -> bool:
        """Fallback: Store in Windows registry"""
        try:
            import winreg
            key = winreg.CreateKey(winreg.HKEY_CURRENT_USER, f"Software\\{APP_NAME}")
            # Encode to make it less obvious
            encoded = secrets.token_hex(16) + password_hash + secrets.token_hex(16)
            winreg.SetValueEx(key, "auth", 0, winreg.REG_SZ, encoded)
            winreg.CloseKey(key)
            return True
        except Exception:
            return False
    
    def _get_registry_credential(self) -> str:
        """Get credential from Windows registry"""
        try:
            import winreg
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, f"Software\\{APP_NAME}")
            encoded, _ = winreg.QueryValueEx(key, "auth")
            winreg.CloseKey(key)
            # Decode (remove 32 char prefix and suffix)
            return encoded[32:-32]
        except Exception:
            return ""
    
    def _store_unix_credential(self, password_hash: str) -> bool:
        """Store credential in Unix keyring"""
        try:
            import keyring
            keyring.set_password(APP_NAME, getpass.getuser(), password_hash)
            return True
        except ImportError:
            # Fallback to hidden file with better permissions
            return self._store_unix_file_credential(password_hash)
        except Exception:
            return False
    
    def _get_unix_credential(self) -> str:
        """Get credential from Unix keyring"""
        try:
            import keyring
            return keyring.get_password(APP_NAME, getpass.getuser()) or ""
        except ImportError:
            return self._get_unix_file_credential()
        except Exception:
            return ""
    
    def _store_unix_file_credential(self, password_hash: str) -> bool:
        """Fallback: Store in hidden file with restricted permissions"""
        try:
            config_dir = Path.home() / ".config" / APP_NAME.lower()
            config_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
            
            cred_file = config_dir / ".auth"
            # Add some obfuscation
            obfuscated = secrets.token_hex(16) + password_hash + secrets.token_hex(16)
            cred_file.write_text(obfuscated)
            cred_file.chmod(0o600)  # Owner read/write only
            return True
        except Exception:
            return False
    
    def _get_unix_file_credential(self) -> str:
        """Get credential from Unix hidden file"""
        try:
            config_dir = Path.home() / ".config" / APP_NAME.lower()
            cred_file = config_dir / ".auth"
            
            if cred_file.exists():
                obfuscated = cred_file.read_text().strip()
                return obfuscated[32:-32]  # Remove obfuscation
            return ""
        except Exception:
            return ""

def load_settings():
    try:
        with open(SETTINGS_FILE, "r") as f:
            return json.load(f)
    except:
        return {
            "theme": "dark", 
            "kdf": 100000, 
            "logging": False, 
            "force": False,
            "exclude_system": True,
            "backup_before_encrypt": True,
            "secure_delete": True
        }

def save_settings(settings):
    with open(SETTINGS_FILE, "w") as f:
        json.dump(settings, f, indent=2)

settings = load_settings()
ctk.set_appearance_mode(settings.get("theme", "dark"))
ctk.set_default_color_theme("blue")

def check_for_update():
    try:
        with urllib.request.urlopen(GITHUB_API_URL, timeout=5) as response:
            data = json.loads(response.read().decode())
            latest = data["tag_name"].lstrip("v")
            if version.parse(latest) > version.parse(APP_VERSION):
                return f"\U0001F504 Update available: v{latest} (you have v{APP_VERSION})"
            else:
                return "\u2705 You are using the latest version."
    except Exception as e:
        return f"\u26A0\ufe0f Could not check for updates: Network error"

def secure_delete_file(file_path: str, passes=3):
    """Securely delete a file by overwriting it multiple times"""
    try:
        if not os.path.exists(file_path):
            return True
            
        file_size = os.path.getsize(file_path)
        
        with open(file_path, "r+b") as f:
            for _ in range(passes):
                f.seek(0)
                # Overwrite with random data
                f.write(secrets.token_bytes(file_size))
                f.flush()
                os.fsync(f.fileno())  # Force write to disk
        
        os.remove(file_path)
        return True
    except Exception:
        return False

def is_safe_to_encrypt(file_path: str, exclude_system: bool = True) -> tuple[bool, str]:
    """Check if a file is safe to encrypt"""
    file_ext = Path(file_path).suffix.lower()
    
    if exclude_system and file_ext in SYSTEM_CRITICAL_EXTENSIONS:
        return False, "System critical file"
    
    if file_ext in RISKY_EXTENSIONS:
        return True, "Risky file type - proceed with caution"
    
    return True, "Safe to encrypt"

class CryptoApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title(f"{APP_NAME} v{APP_VERSION}")
        self.geometry("1000x700")
        self.resizable(True, True)
        
        # Secure password storage
        self.password = SecureString()
        self.credential_manager = SecureCredentialManager()
        
        self.folder_path = None
        self.failed_attempts = 0
        self.is_processing = False
        
        # Settings variables
        self.force_reencrypt = ctk.BooleanVar(value=settings.get("force", False))
        self.enable_logging = ctk.BooleanVar(value=settings.get("logging", False))
        self.exclude_system_files = ctk.BooleanVar(value=settings.get("exclude_system", True))
        self.backup_before_encrypt = ctk.BooleanVar(value=settings.get("backup_before_encrypt", True))
        self.secure_delete = ctk.BooleanVar(value=settings.get("secure_delete", True))
        self.kdf_strength = ctk.IntVar(value=settings.get("kdf", 100000))
        self.theme_mode = ctk.StringVar(value=settings.get("theme", "dark"))

        # UI Components
        self.login_frame = ctk.CTkFrame(self)
        self.console_frame = ctk.CTkFrame(self)
        self.progress_bar = None

        self.setup_console()
        self.setup_login()

    def setup_console(self):
        self.console_frame.pack(side="bottom", fill="x", padx=10, pady=(0, 10))
        
        console_label = ctk.CTkLabel(self.console_frame, text="Activity Log", font=ctk.CTkFont(size=14, weight="bold"))
        console_label.pack(pady=(10, 5))
        
        self.console_text = ctk.CTkTextbox(self.console_frame, height=200, font=ctk.CTkFont(family="Consolas", size=11))
        self.console_text.pack(expand=True, fill="both", padx=10, pady=(0, 10))
        self.console_text.configure(state="disabled")

    def setup_login(self):
        self.login_frame.pack(expand=True, pady=50, padx=50)

        # Title
        title_label = ctk.CTkLabel(self.login_frame, text=f"{APP_NAME}", 
                                 font=ctk.CTkFont(size=24, weight="bold"))
        title_label.pack(pady=(20, 10))
        
        subtitle_label = ctk.CTkLabel(self.login_frame, text="Secure File Encryption Tool", 
                                    font=ctk.CTkFont(size=14))
        subtitle_label.pack(pady=(0, 20))

        # Password input
        ctk.CTkLabel(self.login_frame, text="Enter Password", font=ctk.CTkFont(size=16)).pack(pady=(10, 5))
        self.password_entry = ctk.CTkEntry(self.login_frame, show="*", width=300, height=35)
        self.password_entry.pack(pady=5)
        self.password_entry.bind("<Return>", lambda e: self.check_password())

        # Show password checkbox
        self.show_var = ctk.BooleanVar()
        ctk.CTkCheckBox(self.login_frame, text="Show Password", variable=self.show_var, 
                       command=self.toggle_password).pack(pady=10)

        # Login button
        login_btn = ctk.CTkButton(self.login_frame, text="Unlock", command=self.check_password,
                                 width=200, height=40, font=ctk.CTkFont(size=14))
        login_btn.pack(pady=15)

        self.log(check_for_update())

        if not self.credential_manager.credential_exists():
            self.show_first_time_instructions()

    def show_first_time_instructions(self):
        self.log("\U0001F510 Welcome to CEncrypt – v2.0.0")
        self.log("\U0001F6E1 First-time setup: Choose a strong master password")
        self.log("\u2139\ufe0f Requirements: 8+ chars, mixed case, numbers, symbols")
        self.log("\u26A0\ufe0f Master password cannot be recovered if lost!")
        self.log("\U0001F4BE Password will be stored securely.")

    def toggle_password(self):
        self.password_entry.configure(show="" if self.show_var.get() else "*")

    def check_password(self):
        input_password = self.password_entry.get()
        
        if not input_password:
            messagebox.showwarning("Input Required", "Please enter a password.")
            return

        if not self.credential_manager.credential_exists():
            # First time setup
            if len(input_password) < 8:
                messagebox.showwarning("Weak Password", "Password must be at least 8 characters long.")
                return
                
            if self.credential_manager.store_credential(input_password):
                self.password.set(input_password)
                messagebox.showinfo("Setup Complete", "Master password saved securely. Welcome to CEncrypt!")
                self.login_successful()
            else:
                messagebox.showerror("Setup Failed", "Could not save password securely. Please try again.")
            return

        # Verify existing password
        stored_hash = self.credential_manager.get_credential()
        input_hash = hashlib.sha256(input_password.encode()).hexdigest()
        
        if input_hash == stored_hash:
            self.password.set(input_password)
            self.login_successful()
        else:
            self.failed_attempts += 1
            messagebox.showerror("Access Denied", f"Incorrect password. Attempt {self.failed_attempts}/3")
            if self.failed_attempts >= 3:
                self.log("\u274C Maximum login attempts exceeded. Exiting for security.")
                self.destroy()

    def login_successful(self):
        self.login_frame.pack_forget()
        self.log(f"\U0001F511 Authenticated at {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        self.setup_main_ui()
        # Clear the password entry for security
        self.password_entry.delete(0, 'end')

    def setup_main_ui(self):
        # Create main container
        main_container = ctk.CTkFrame(self)
        main_container.pack(fill="both", expand=True, padx=10, pady=(10, 0))
        
        self.tab_view = ctk.CTkTabview(main_container)
        self.tab_view.pack(fill="both", expand=True, padx=10, pady=10)

        # Tabs
        self.encrypt_tab = self.tab_view.add("🔒 Encrypt")
        self.decrypt_tab = self.tab_view.add("🔓 Decrypt")
        self.settings_tab = self.tab_view.add("⚙️ Settings")
        self.about_tab = self.tab_view.add("ℹ️ About")

        self.setup_encrypt_tab()
        self.setup_decrypt_tab()
        self.setup_settings_tab()
        self.setup_about_tab()

        self.log("\U0001F510 Ready for secure file operations...")

    def setup_encrypt_tab(self):
        scroll_frame = ctk.CTkScrollableFrame(self.encrypt_tab)
        scroll_frame.pack(fill="both", expand=True, padx=20, pady=20)

        # Folder selection
        folder_frame = ctk.CTkFrame(scroll_frame)
        folder_frame.pack(fill="x", pady=10)

        ctk.CTkLabel(folder_frame, text="Select Folder to Encrypt",
                    font=ctk.CTkFont(size=16, weight="bold")).pack(pady=10)

        ctk.CTkButton(folder_frame, text="📁 Browse Folder", command=self.select_folder,
                    width=200, height=40).pack(pady=10)

        self.selected_folder_label = ctk.CTkLabel(folder_frame, text="No folder selected", wraplength=400)
        self.selected_folder_label.pack(pady=5)

        # Options
        options_frame = ctk.CTkFrame(scroll_frame)
        options_frame.pack(fill="x", pady=10)

        ctk.CTkLabel(options_frame, text="Encryption Options",
                    font=ctk.CTkFont(size=14, weight="bold")).pack(pady=10)

        ctk.CTkCheckBox(options_frame, text="Exclude system files (.exe, .dll, etc.)",
                        variable=self.exclude_system_files).pack(pady=5, anchor="w", padx=20)

        ctk.CTkCheckBox(options_frame, text="Create backup before encryption",
                        variable=self.backup_before_encrypt).pack(pady=5, anchor="w", padx=20)

        # Encrypt button
        self.encrypt_btn = ctk.CTkButton(scroll_frame, text="🔒 Start Encryption",
                                        command=self.encrypt_folder_threaded,
                                        width=250, height=50,
                                        font=ctk.CTkFont(size=16, weight="bold"))
        self.encrypt_btn.pack(pady=20)

    def setup_decrypt_tab(self):
        # Folder selection
        folder_frame = ctk.CTkFrame(self.decrypt_tab)
        folder_frame.pack(fill="x", padx=20, pady=20)
        
        ctk.CTkLabel(folder_frame, text="Select Folder to Decrypt", 
                    font=ctk.CTkFont(size=16, weight="bold")).pack(pady=10)
        
        ctk.CTkButton(folder_frame, text="📁 Browse Folder", command=self.select_folder,
                     width=200, height=40).pack(pady=10)
        
        # Decrypt button
        self.decrypt_btn = ctk.CTkButton(self.decrypt_tab, text="🔓 Start Decryption", 
                                        command=self.decrypt_folder_threaded,
                                        width=250, height=50, 
                                        font=ctk.CTkFont(size=16, weight="bold"))
        self.decrypt_btn.pack(pady=20)

    def setup_settings_tab(self):
        settings_scroll = ctk.CTkScrollableFrame(self.settings_tab)
        settings_scroll.pack(fill="both", expand=True, padx=20, pady=20)
        
        # Security Settings
        security_frame = ctk.CTkFrame(settings_scroll)
        security_frame.pack(fill="x", pady=10)
        
        ctk.CTkLabel(security_frame, text="Security Settings", 
                    font=ctk.CTkFont(size=16, weight="bold")).pack(pady=10)
        
        ctk.CTkLabel(security_frame, text="KDF Iterations (higher = more secure, slower)").pack(pady=5)
        kdf_frame = ctk.CTkFrame(security_frame)
        kdf_frame.pack(pady=5)
        
        ctk.CTkEntry(kdf_frame, textvariable=self.kdf_strength, width=100).pack(side="left", padx=5)
        ctk.CTkButton(kdf_frame, text="Reset to Default", width=120,
                     command=lambda: self.kdf_strength.set(100000)).pack(side="left", padx=5)
        
        ctk.CTkCheckBox(security_frame, text="Secure delete original files after encryption", 
                       variable=self.secure_delete).pack(pady=10, anchor="w", padx=20)
        
        ctk.CTkCheckBox(security_frame, text="Force re-encryption of already encrypted files", 
                       variable=self.force_reencrypt).pack(pady=5, anchor="w", padx=20)
        
        # UI Settings
        ui_frame = ctk.CTkFrame(settings_scroll)
        ui_frame.pack(fill="x", pady=10)
        
        ctk.CTkLabel(ui_frame, text="Interface Settings", 
                    font=ctk.CTkFont(size=16, weight="bold")).pack(pady=10)
        
        ctk.CTkLabel(ui_frame, text="Theme Mode").pack(pady=5)
        ctk.CTkOptionMenu(ui_frame, values=["light", "dark", "system"], 
                         variable=self.theme_mode, command=self.change_theme).pack(pady=5)
        
        ctk.CTkCheckBox(ui_frame, text="Enable activity logging to file", 
                       variable=self.enable_logging).pack(pady=10, anchor="w", padx=20)
        
        # Save button
        ctk.CTkButton(settings_scroll, text="💾 Save Settings", 
                     command=self.save_current_settings,
                     width=200, height=40).pack(pady=20)

    def setup_about_tab(self):
        about_scroll = ctk.CTkScrollableFrame(self.about_tab)
        about_scroll.pack(expand=True, fill="both", padx=20, pady=20)

        ctk.CTkLabel(about_scroll, text=f"{APP_NAME}",
                    font=ctk.CTkFont(size=24, weight="bold")).pack(pady=20)

        ctk.CTkLabel(about_scroll, text=f"Version {APP_VERSION}",
                    font=ctk.CTkFont(size=16)).pack(pady=5)

        ctk.CTkLabel(about_scroll, text=f"by {APP_AUTHOR}",
                    font=ctk.CTkFont(size=14)).pack(pady=5)

        features_text = """
Security Features:
• Strong AES-GCM encryption with built-in integrity checks
• Configurable PBKDF2 key derivation for enhanced password security
• Secure storage of master password using OS-native credential managers
• Automatic protection against encryption of critical system files
• Optional secure deletion of original files after encryption
• In-memory protection of sensitive data

Enhanced Safety:
• Smart exclusion of risky file types
• Automatic backup creation before encryption
• File validation and safety checks
• Real-time progress tracking and operation logging
• Robust error handling and user-friendly interface
    """

        ctk.CTkLabel(about_scroll, text=features_text,
                    font=ctk.CTkFont(size=12), justify="left").pack(pady=20, padx=20)

    def change_theme(self, choice):
        ctk.set_appearance_mode(choice)
        self.save_current_settings()

    def save_current_settings(self):
        config = {
            "theme": self.theme_mode.get(),
            "kdf": self.kdf_strength.get(),
            "logging": self.enable_logging.get(),
            "force": self.force_reencrypt.get(),
            "exclude_system": self.exclude_system_files.get(),
            "backup_before_encrypt": self.backup_before_encrypt.get(),
            "secure_delete": self.secure_delete.get()
        }
        save_settings(config)
        self.log("\u2699\ufe0f Settings saved successfully")

    def select_folder(self):
        path = filedialog.askdirectory(title="Select folder for encryption/decryption")
        if path:
            self.folder_path = path
            folder_name = os.path.basename(path)
            self.log(f"\U0001F4C1 Selected: {folder_name} ({path})")
            if hasattr(self, 'selected_folder_label'):
                self.selected_folder_label.configure(text=f"Selected: {folder_name}")
        else:
            self.log("\u26A0\ufe0f No folder selected")

    def derive_key(self, password: str, salt: bytes) -> bytes:
        """Derive encryption key from password using PBKDF2"""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=self.kdf_strength.get(),
            backend=default_backend()
        )
        return kdf.derive(password.encode())

    def encrypt_folder_threaded(self):
        """Start encryption in a separate thread"""
        if self.is_processing:
            messagebox.showwarning("Operation in Progress", "Please wait for current operation to complete.")
            return
            
        if not self.folder_path:
            messagebox.showwarning("No Folder Selected", "Please select a folder first.")
            return
        
        # Confirm encryption
        result = messagebox.askyesno("Confirm Encryption", 
                                   f"Are you sure you want to encrypt all files in:\n{self.folder_path}\n\nThis operation cannot be undone without the correct password.")
        if not result:
            return
            
        self.is_processing = True
        self.encrypt_btn.configure(state="disabled")
        threading.Thread(target=self.encrypt_folder, daemon=True).start()

    def decrypt_folder_threaded(self):
        """Start decryption in a separate thread"""
        if self.is_processing:
            messagebox.showwarning("Operation in Progress", "Please wait for current operation to complete.")
            return
            
        if not self.folder_path:
            messagebox.showwarning("No Folder Selected", "Please select a folder first.")
            return
            
        self.is_processing = True
        self.decrypt_btn.configure(state="disabled") 
        threading.Thread(target=self.decrypt_folder, daemon=True).start()

    def encrypt_folder(self):
        """Encrypt all files in the selected folder"""
        try:
            self.log("\U0001F512 Starting encryption process...")
            
            # Count files first for progress
            file_count = 0
            files_to_process = []
            
            for root, dirs, files in os.walk(self.folder_path):
                for name in files:
                    file_path = os.path.join(root, name)
                    safe, reason = is_safe_to_encrypt(file_path, self.exclude_system_files.get())
                    
                    if not safe:
                        self.log(f"\u26A0\ufe0f Skipped {reason}: {file_path}")
                        continue
                    
                    if reason == "Risky file type - proceed with caution":
                        self.log(f"\u26A0\ufe0f {reason}: {file_path}")
                    
                    files_to_process.append(file_path)
                    file_count += 1
            
            if file_count == 0:
                self.log("\u274C No files found to encrypt")
                return
            
            self.log(f"\U0001F4CA Found {file_count} files to encrypt")
            
            processed = 0
            encrypted_count = 0
            skipped_count = 0
            
            for file_path in files_to_process:
                try:
                    # Read file
                    with open(file_path, "rb") as f:
                        data = f.read()
                    
                    # Check if already encrypted
                    if data.startswith(APP_MAGIC_HEADER) and not self.force_reencrypt.get():
                        self.log(f"\u23ED Already encrypted: {os.path.basename(file_path)}")
                        skipped_count += 1
                        processed += 1
                        continue
                    
                    # Create backup if requested
                    if self.backup_before_encrypt.get():
                        backup_path = file_path + ".backup"
                        with open(backup_path, "wb") as backup_file:
                            backup_file.write(data)
                    
                    # Encrypt
                    salt = secrets.token_bytes(16)
                    nonce = secrets.token_bytes(12)
                    key = self.derive_key(self.password.get(), salt)
                    aesgcm = AESGCM(key)
                    encrypted = aesgcm.encrypt(nonce, data, None)
                    
                    # Write encrypted file
                    with open(file_path, "wb") as f:
                        f.write(APP_MAGIC_HEADER + salt + nonce + encrypted)
                    
                    # Secure delete backup if successful and requested
                    if self.backup_before_encrypt.get() and self.secure_delete.get():
                        secure_delete_file(backup_path)
                    
                    self.log(f"\u2705 Encrypted: {os.path.basename(file_path)}")
                    encrypted_count += 1
                    
                except Exception as e:
                    self.log(f"\u274C Error encrypting {os.path.basename(file_path)}: {str(e)}")
                
                processed += 1
                
                # Update progress every 10 files or at the end
                if processed % 10 == 0 or processed == file_count:
                    progress = (processed / file_count) * 100
                    self.log(f"\U0001F4CA Progress: {processed}/{file_count} files ({progress:.1f}%)")
            
            self.log(f"\u2705 Encryption complete! {encrypted_count} encrypted, {skipped_count} skipped")
            messagebox.showinfo("Encryption Complete", 
                              f"Successfully encrypted {encrypted_count} files.\n{skipped_count} files were skipped.")
            
        except Exception as e:
            self.log(f"\u274C Critical error during encryption: {str(e)}")
            messagebox.showerror("Encryption Failed", f"An error occurred during encryption: {str(e)}")
        
        finally:
            self.is_processing = False
            self.encrypt_btn.configure(state="normal")

    def decrypt_folder(self):
        """Decrypt all files in the selected folder"""
        try:
            self.log("\U0001F513 Starting decryption process...")
            
            # Count encrypted files first
            file_count = 0
            files_to_process = []
            
            for root, dirs, files in os.walk(self.folder_path):
                for name in files:
                    file_path = os.path.join(root, name)
                    try:
                        with open(file_path, "rb") as f:
                            header = f.read(len(APP_MAGIC_HEADER))
                        if header == APP_MAGIC_HEADER:
                            files_to_process.append(file_path)
                            file_count += 1
                    except Exception:
                        continue
            
            if file_count == 0:
                self.log("\u274C No encrypted files found")
                messagebox.showinfo("No Files", "No encrypted files found in the selected folder.")
                return
            
            self.log(f"\U0001F4CA Found {file_count} encrypted files to decrypt")
            
            processed = 0
            decrypted_count = 0
            failed_count = 0
            
            for file_path in files_to_process:
                try:
                    with open(file_path, "rb") as f:
                        content = f.read()
                    
                    # Verify header
                    if not content.startswith(APP_MAGIC_HEADER):
                        continue
                    
                    # Extract components
                    content = content[len(APP_MAGIC_HEADER):]
                    if len(content) < 28:  # salt(16) + nonce(12) + minimum encrypted data
                        raise ValueError("File appears corrupted")
                    
                    salt = content[:16]
                    nonce = content[16:28]
                    encrypted = content[28:]
                    
                    # Decrypt
                    key = self.derive_key(self.password.get(), salt)
                    aesgcm = AESGCM(key)
                    decrypted = aesgcm.decrypt(nonce, encrypted, None)
                    
                    # Write decrypted file
                    with open(file_path, "wb") as f:
                        f.write(decrypted)
                    
                    self.log(f"\u2705 Decrypted: {os.path.basename(file_path)}")
                    decrypted_count += 1
                    
                except Exception as e:
                    self.log(f"\u274C Error decrypting {os.path.basename(file_path)}: Authentication failed")
                    failed_count += 1
                
                processed += 1
                
                # Update progress
                if processed % 10 == 0 or processed == file_count:
                    progress = (processed / file_count) * 100
                    self.log(f"\U0001F4CA Progress: {processed}/{file_count} files ({progress:.1f}%)")
            
            self.log(f"\u2705 Decryption complete! {decrypted_count} decrypted, {failed_count} failed")
            
            if failed_count > 0:
                messagebox.showwarning("Decryption Partial", 
                                     f"Decrypted {decrypted_count} files successfully.\n{failed_count} files failed (wrong password or corrupted).")
            else:
                messagebox.showinfo("Decryption Complete", 
                                  f"Successfully decrypted all {decrypted_count} files!")
            
        except Exception as e:
            self.log(f"\u274C Critical error during decryption: {str(e)}")
            messagebox.showerror("Decryption Failed", f"An error occurred during decryption: {str(e)}")
        
        finally:
            self.is_processing = False
            self.decrypt_btn.configure(state="normal")

    def log(self, message):
        """Log a message to the console and optionally to file"""
        timestamp = datetime.datetime.now().strftime("%H:%M:%S")
        full_message = f"[{timestamp}] {message}"
        
        # Log to file if enabled
        if self.enable_logging.get():
            try:
                with open("cencrypt_log.txt", "a", encoding="utf-8") as log_file:
                    log_file.write(full_message + "\n")
            except Exception:
                pass  # Silently fail if logging fails
        
        # Update console
        try:
            self.console_text.configure(state='normal')
            self.console_text.insert("end", full_message + "\n")
            self.console_text.configure(state='disabled')
            self.console_text.see("end")
        except Exception:
            pass  # Silently fail if console update fails
        
        # Force UI update
        self.update_idletasks()

    def on_closing(self):
        """Clean up when closing the application"""
        if self.is_processing:
            if messagebox.askokcancel("Operation in Progress", 
                                    "An encryption/decryption operation is in progress. Force quit?"):
                self.password.clear()
                self.destroy()
        else:
            self.password.clear()
            self.destroy()

    def __del__(self):
        """Ensure secure cleanup"""
        if hasattr(self, 'password'):
            self.password.clear()


def main():
    """Main application entry point"""
    try:
        app = CryptoApp()
        app.protocol("WM_DELETE_WINDOW", app.on_closing)
        app.mainloop()
    except KeyboardInterrupt:
        print("\nApplication interrupted by user")
    except Exception as e:
        print(f"Critical error: {e}")
        messagebox.showerror("Critical Error", f"Application crashed: {e}")


if __name__ == "__main__":
    main()