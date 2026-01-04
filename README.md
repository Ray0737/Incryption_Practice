# Advanced Encryption Exercise
Side Project 

## Project Details:

This code is dedicated to my senior (p'View). I created this code as way to prank my senior buddy in return and to practicing in decrypting and encrypting data for Capture The Flag competition.

---

## Project Status:

| Detail | Value |
| :--- | :--- |
| **Primary Library** | [PyCA Cryptography](https://cryptography.io/) |
| **Password Engine** | Argon2id (Memory-Hard Hashing) |
| **Security Tier** | Production-Grade (Hybrid Encryption) |
| **Latest Edit** | January 2, 2026 |
---

## 🛠️ Cryptographic Architecture



| Module | Algorithm | Reversible | Strength | Role |
| :--- | :--- | :--- | :--- | :--- |
| **KDF** | **Argon2id** | No | v | Secure user password hashing |
| **Asymmetric** | **RSA-3072** | Yes | iv | Encrypts/Decrypts the AES Session Keys |
| **Symmetric** | **AES-256 GCM** | Yes | v | Encrypts the actual secret data (Authenticated) |
| **Persistence** | **PKCS8 PEM** | Yes | iii | RSA Private Key stored with Master Password |

---

## 🧠 Deep Dive: The Logic

### 1. RSA (Asymmetric Encryption)
RSA is the "Gatekeeper." It uses two keys: a **Public Key** (to lock) and a **Private Key** (to unlock).
* **The Trapdoor:** It relies on the difficulty of factoring the product of two massive prime numbers.
* **The Hybrid Approach:** RSA is slow. In this project, we don't encrypt the message with RSA. We encrypt a random **AES Key** with RSA, then use that AES key for the message. This is known as a **Key Encapsulation Mechanism (KEM)**.



### 2. AES-256 GCM (Symmetric Encryption)
This is the "Workhorse." AES-256 is the industry standard for bulk data.
* **GCM Mode:** Unlike older modes (like CBC), **Galois/Counter Mode** provides **AEAD** (Authenticated Encryption with Associated Data). 
* **The Tag:** It generates a "MAC tag." If an attacker changes even one bit of the encrypted file, the tag check fails, and the code refuses to decrypt. This prevents "Bit-Flipping" attacks often seen in CTFs.



### 3. Hashlib & Argon2id (Hashing)
Hashing is a one-way street. You can turn a password into a hash, but you can't turn a hash back into a password.
* **Argon2id:** This is the winner of the Password Hashing Competition. It is designed to be "Memory-Hard," meaning attackers can't use expensive GPUs to crack your password quickly.
* **The Salt:** A "Salt" is a random string added to the password before hashing. Even if two users have the same password, their hashes will look completely different. This kills "Rainbow Table" attacks.

---

## 🔐 The "Double-Lock" Flow

1.  **The Master Lock:** The `private_key.pem` is encrypted on disk. You need a **Master Password** to even load the key into memory.
2.  **The User Lock:** Individual user accounts are protected via **Argon2id**, preventing brute-force attacks.
3.  **The Data Lock:** Each secret is encrypted with a unique **AES-GCM** key. Even if one secret is somehow compromised, the others remain safe because they don't share a key.

---

## 💡 Pro-Tips & Advanced Notes

### 📦 Useful Modules for Security
* **`secrets` (Standard Library):** Always use `secrets` instead of `random` for generating tokens or nonces. `random` is predictable; `secrets` is cryptographically secure.
* **`getpass`:** Prevents "shoulder surfing" by hiding characters as you type passwords in the terminal.
* **`python-dotenv`:** Store sensitive configurations (like file paths) in a `.env` file instead of hardcoding them.

### 📜 Encoding vs. Encryption
Common mistake in CTFs: Confusing **Base64** with encryption. 
* **Base64 is NOT security.** It is a transport format.
* **Encoding Tip:** When storing encrypted bytes in a JSON file, always use `base64.urlsafe_b64encode()`. It removes characters like `+` and `/` which can sometimes break URL strings or certain file parsers.

### 🛡️ Best Practices for "Max Security"
* **Memory Zeroing:** In high-security C-based apps, we wipe the RAM after using a password. In Python, this is hard, but you can minimize risk by not storing passwords in global variables.
* **Salt Uniqueness:** Never reuse a salt. Fortunately, Argon2 handles this for you by generating a new salt for every `ph.hash()` call.
* **Nonce Integrity:** For AES-GCM, the `nonce` (number used once) must **never** be repeated with the same key. If you repeat a nonce, an attacker can recover the key.

---

## 📥 Installation & Usage

### 1. Install Dependencies
```bash
pip install cryptography argon2-cffi
pip install python-pkcs11
```
---

## ⚠️ Deployment Note:

* **Key Loss:** If the `private_key.pem` is deleted or the Master Password is forgotten, **all data in `log.json` is permanently lost.** There is no "backdoor" or "recovery" feature by design.
* **Tamper Protection:** Because this uses AES-GCM (Authenticated Encryption), if an attacker modifies even a single byte of the encrypted data, the decryption will fail with an error rather than returning corrupted text.


