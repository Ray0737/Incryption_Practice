import os
import json
import base64
import hashlib
import getpass 
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

DATA_FILE = "log.json"
STATIC_SALT = "a_secure_static_salt_for_this_demo"
KEY_FILE = "key.pem"

private_key = None
public_key = None
encrypted_session_key = None
iv = None
encrypted_message = None

#-----------------------------------------------------File System Set up-----------------------------------------------------#

def load_db():
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, 'r') as f:
            try:
                return json.load(f)
            except json.JSONDecodeError:
                return {}
    return {}

def save_db(data):
    with open(DATA_FILE, 'w') as f:
        json.dump(data, f, indent=4)

def clear_console():
    os.system('cls' if os.name == 'nt' else 'clear')

db = load_db()

#-----------------------------------------------------Encoder & Decoder-----------------------------------------------------#

#--------------------------------------RSA Key Management with Master Password Protection--------------------------------------# 

def get_rsa_keys():
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

#--------------------------------------Base 64--------------------------------------# 

def encode_b64(text):
    text_bytes = text.encode("utf-8")
    b64_bytes = base64.b64encode(text_bytes)
    return b64_bytes.decode("utf-8")

def decode_b64(b64_text):
    b64_bytes = b64_text.encode("utf-8")
    text_bytes = base64.b64decode(b64_bytes)
    return text_bytes.decode("utf-8")

#--------------------------------------Hash | Hash Salt--------------------------------------# 

def hash_sha256(password: str) -> str:
    salted_password = STATIC_SALT + password
    return hashlib.sha256(salted_password.encode('utf-8')).hexdigest()

def hash_new_password(password):
    salt = os.urandom(16)
    hash_object = hashlib.sha256(salt + password.encode())
    return salt.hex(), hash_object.hexdigest()

def verify_password(stored_salt_hex, stored_hash, input_password):
    salt = bytes.fromhex(stored_salt_hex)
    hash_object = hashlib.sha256(salt + input_password.encode())
    return hash_object.hexdigest() == stored_hash

#--------------------------------------Argon 2--------------------------------------# 

ph = PasswordHasher()

def hash_new_password(password: str) -> str:
    return ph.hash(password)

def verify_user_password(stored_hash: str, provided_password: str) -> bool:
    try:
        ph.verify(stored_hash, provided_password)
        if ph.check_needs_rehash(stored_hash):
            print("Notice: Password hash needs updating to newer security standards.")
            
        return True
    except VerifyMismatchError:
        return False
    except Exception as e:
        print(f"Verification error: {e}")
        return False

#--------------------------------------Hybrid Encryption (RSA + AES-GCM)--------------------------------------# 

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

#-----------------------------------------------------Code Executer-----------------------------------------------------#

def run_app():
    priv_key, pub_key = get_rsa_keys()
    
    username = input("\nEnter Username: ")
    if username not in db:
        choice = input("User not found. Register? (y/n): ")
        if choice.lower() == 'y':
            password = getpass.getpass("Create User Password: ")
            db[username] = {"hash": ph.hash(password), "vault": []}
            save_db(db)
            print("User registered.")
            clear_console()
        else: return
    clear_console()
    password = getpass.getpass(f"Enter password for {username}: ")
    try:
        ph.verify(db[username]["hash"], password)
        print("Login Successful!")
        clear_console()
        
        msg = input("\nEnter a secret to encrypt: ")
        package = encrypt_secret(msg, pub_key)
        db[username]["vault"].append(package)
        save_db(db)
        
        print("\n--- VAULT UPDATED ---")
        decrypted = decrypt_secret(db[username]["vault"][-1], priv_key)
        print(f"Decrypted value: {decrypted}")    
    except VerifyMismatchError:
        print("Login failed: Incorrect password.")
        
if __name__ == "__main__":
    run_app()    
    
