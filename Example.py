import os
import json
import base64
import getpass # Used to hide password typing in terminal
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

# Configuration
DATA_FILE = "log.json"
KEY_FILE = "private_key.pem"
ph = PasswordHasher()

# -----------------------------------------------------
# RSA Key Management with Master Password Protection
# -----------------------------------------------------

def get_rsa_keys():
    """Load the RSA key using a Master Password or generate a new one."""
    if os.path.exists(KEY_FILE):
        print("\n--- SECURE KEY STORAGE DETECTED ---")
        while True:
            master_pw = getpass.getpass("Enter Master Password to unlock Private Key: ")
            try:
                with open(KEY_FILE, "rb") as key_file:
                    private_key = serialization.load_pem_private_key(
                        key_file.read(),
                        password=master_pw.encode(),
                    )
                return private_key, private_key.public_key()
            except Exception:
                print("Invalid Master Password. Access Denied.")
    else:
        print("\n--- INITIAL SETUP: GENERATING NEW KEYS ---")
        master_pw = getpass.getpass("Create a Master Password to protect your key file: ")
        confirm_pw = getpass.getpass("Confirm Master Password: ")
        
        if master_pw != confirm_pw:
            print("Passwords do not match. Restarting...")
            exit()

        private_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
        
        # Encrypt the private key before saving to disk
        encryption_algo = serialization.BestAvailableEncryption(master_pw.encode())
        pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=encryption_algo
        )
        
        with open(KEY_FILE, "wb") as f:
            f.write(pem)
            
        print(f"Success! Private key encrypted and saved to {KEY_FILE}.")
        return private_key, private_key.public_key()

# -----------------------------------------------------
# Hybrid Encryption (RSA + AES-GCM)
# -----------------------------------------------------

def encrypt_secret(message_text, public_key):
    session_key = AESGCM.generate_key(bit_length=256)
    nonce = os.urandom(12) 
    
    aesgcm = AESGCM(session_key)
    ciphertext = aesgcm.encrypt(nonce, message_text.encode(), None)
    
    enc_session_key = public_key.encrypt(
        session_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    return {
        "key": base64.b64encode(enc_session_key).decode('utf-8'),
        "nonce": base64.b64encode(nonce).decode('utf-8'),
        "ciphertext": base64.b64encode(ciphertext).decode('utf-8')
    }

def decrypt_secret(package, private_key):
    enc_session_key = base64.b64decode(package["key"])
    nonce = base64.b64decode(package["nonce"])
    ciphertext = base64.b64decode(package["ciphertext"])
    
    session_key = private_key.decrypt(
        enc_session_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    aesgcm = AESGCM(session_key)
    return aesgcm.decrypt(nonce, ciphertext, None).decode()

# -----------------------------------------------------
# Database Helpers
# -----------------------------------------------------

def load_db():
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, 'r') as f:
            return json.load(f)
    return {}

def save_db(data):
    with open(DATA_FILE, 'w') as f:
        json.dump(data, f, indent=4)

# -----------------------------------------------------
# Main Execution Flow
# -----------------------------------------------------

def run_app():
    # 1. Unlock the "Safe" (The RSA Key)
    try:
        priv_key, pub_key = get_rsa_keys()
    except KeyboardInterrupt:
        print("\nExiting...")
        return

    db = load_db()
    
    # 2. User Authentication
    username = input("\nEnter Username: ")
    if username not in db:
        choice = input("User not found. Register? (y/n): ")
        if choice.lower() == 'y':
            password = getpass.getpass("Create User Password: ")
            db[username] = {"hash": ph.hash(password), "vault": []}
            save_db(db)
            print("User registered.")
        else: return

    # 3. Verify Login
    password = getpass.getpass(f"Enter password for {username}: ")
    try:
        ph.verify(db[username]["hash"], password)
        print("Login Successful!")
        
        # 4. Perform Secure Operations
        msg = input("\nEnter a secret to encrypt: ")
        package = encrypt_secret(msg, pub_key)
        db[username]["vault"].append(package)
        save_db(db)
        
        print("\n--- VAULT UPDATED ---")
        # Decrypt the last entry just to prove it works
        decrypted = decrypt_secret(db[username]["vault"][-1], priv_key)
        print(f"Decrypted value: {decrypted}")

    except VerifyMismatchError:
        print("Login failed: Incorrect password.")

if __name__ == "__main__":
    run_app()