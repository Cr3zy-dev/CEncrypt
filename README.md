# CEncrypt

**CEncrypt** is a secure, open source, modern GUI tool for encrypting and decrypting folders using AES-GCM encryption.

🔐 Built for privacy. Designed for simplicity.

[![Download](https://img.shields.io/badge/Download-.exe-blue?style=for-the-badge&logo=windows)](https://github.com/Cr3zy-dev/CEncrypt/releases/latest/download/cencrypt.exe)

---

## 🚀 Features

- 🔐 AES-256 encryption (AES-GCM) with random salt & nonce
- 🔑 One-time master password (securely stored using OS-native credential managers)
- 🧠 PBKDF2-HMAC key derivation with configurable iteration count
- 🧱 Modern GUI built with `customtkinter`
- 🌗 Light, Dark & System theme support
- 🧼 Secure deletion of original files after encryption (optional)
- 🧩 Automatic exclusion of system-critical file types
- 🧠 Memory-safe password handling
- 📁 Backup creation before encryption (optional)
- 📜 Scrollable interface for small screens
- 🛠 Portable `.exe` – no installation required

---

## ⚠️ Security Notes

- 🔒 Password is **never stored in plaintext**
- 🔐 Encrypted files are **only** decryptable via this app
- 🔁 Password **cannot be changed or recovered**
- 🔄 File encryption depends on:
  - Master password
  - KDF strength (iteration count)
- ⚠️ Decryption fails with incorrect password or KDF mismatch

---

## 💾 Data Storage

- 🔐 Password hash stored securely via OS credential manager or fallback method
- ⚙️ App settings stored in `settings.json`
- 📝 Optional log output saved to `cencrypt_log.txt`

---

## 📦 Download

👉 Get the latest release from the [releases page](https://github.com/Cr3zy-dev/CEncrypt/releases) (Windows only).  
📌 Python is **not** required.

---

## 🛡 License

This project is licensed under the  
**Creative Commons Attribution-NonCommercial-NoDerivatives 4.0 International (CC BY-NC-ND 4.0)**.

© 2025 Cr3zy. All rights reserved.  
You may view and share the source code for **personal and educational use only**.  
**Commercial use, redistribution, or modification is strictly prohibited.**  
See [LICENSE](LICENSE) for full legal terms.

---

## 👤 Author

Developed by **Cr3zy**  
© 2025 All rights reserved
