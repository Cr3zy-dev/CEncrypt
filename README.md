# CEncrypt

**CEncrypt** is a secure, minimalistic GUI tool for encrypting and decrypting folders using modern AES-GCM encryption.

🔐 Built for privacy. Designed for simplicity.

---

## 🚀 Features

- 🔐 AES-256 encryption (AES-GCM) with random salt + nonce
- 🔑 One-time master password (stored as SHA-256 hash)
- 🧠 Secure key derivation (PBKDF2-HMAC with custom iterations)
- 🧱 Modern GUI powered by `customtkinter`
- 🌗 Light & Dark mode support
- 📂 Drag & Drop ready (planned)
- 🛠 No installation required – portable `.exe`

---

## ⚠️ Security Notes

- 💬 Password is **never stored in plaintext**
- 🧠 Encrypted files are **only** decryptable via this app
- 🔁 Password **cannot be changed or reset**
- 🔄 File encryption depends on:
  - Password
  - KDF strength (iteration count)
- ⚠️ Decryption fails with wrong KDF settings

---

## 💾 Data

- 🔐 Password hash stored in `.password` file (SHA-256)
- ⚙️ App settings stored in `settings.json`
- 📝 Log output saved to `cencrypt_log.txt` (if enabled)

---

## 📦 Download

👉 Get the latest release from the [Releases page](https://github.com/Cr3zy-dev/CEncrypt/releases)

📁 Only `.exe` is required to run the app (Windows only).  
📌 You do **not** need Python installed.

---

## 🛑 Legal

This software is **proprietary and closed-source**.  
Redistribution, reverse engineering, or modification is **strictly prohibited**.  
See `LICENSE` for full legal terms.

---

## 👤 Author

Developed by **Cr3zy**  
© 2025 All rights reserved
