import os
import base64
import hashlib
import json
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

DATA_FILE = "log.json"
STATIC_SALT = "a_secure_static_salt_for_this_demo"

private_key = None
public_key = None
encrypted_session_key = None
iv = None
encrypted_message = None

def load_users():
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, 'r') as f:
            try:
                return json.load(f)
            except json.JSONDecodeError:
                return {}
    return {}

def save_users(data):
    with open(DATA_FILE, 'w') as f:
        json.dump(data, f, indent=4)

users = load_users()

def hash_sha256(password: str) -> str:
    salted_password = STATIC_SALT + password
    return hashlib.sha256(salted_password.encode('utf-8')).hexdigest()

def incrypting_RSA(message_text):
    global private_key, public_key, encrypted_session_key, iv, encrypted_message
    
    # 1. Generate RSA Keys
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    
    # 2. Setup AES Session Key
    session_key = os.urandom(32) 
    iv = os.urandom(16) 
    
    # 3. AES Encryption
    cipher = Cipher(algorithms.AES(session_key), modes.CFB(iv))
    encryptor = cipher.encryptor()
    encrypted_message = encryptor.update(message_text.encode()) + encryptor.finalize()
    
    # 4. RSA Encrypt the Session Key
    encrypted_session_key = public_key.encrypt(
        session_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted_message.hex()

def decrpting_RSA():
    # 1. RSA Decrypt the Session Key
    decrypted_session_key = private_key.decrypt(
        encrypted_session_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    # 2. AES Decrypt the Message
    decryptor = Cipher(algorithms.AES(decrypted_session_key), modes.CFB(iv)).decryptor() 
    original_message = decryptor.update(encrypted_message) + decryptor.finalize()
    
    return original_message.decode()

def encode_b64(text):
    text_bytes = text.encode("utf-8")
    b64_bytes = base64.b64encode(text_bytes)
    return b64_bytes.decode("utf-8")

def decode_b64(b64_text):
    b64_bytes = b64_text.encode("utf-8")
    text_bytes = base64.b64decode(b64_bytes)
    return text_bytes.decode("utf-8")

def register():
    username = input("Enter a new username: ")
    user_key = hash_sha256(username)
    
    if user_key in users:
        print("Username already exists.")
        return False
    
    password = input("Enter a password: ")
    users[user_key] = {
        "password": hash_sha256(password),
        "secret": [] 
    }
    save_users(users)
    print(f"User '{username}' registered successfully!")
    return True

def login():
    while True:
        username = input("Enter your username: ")
        user_key = hash_sha256(username)
        
        if user_key in users:
            password = input("Enter your password: ")
            if users[user_key]["password"] == hash_sha256(password):
                print(f"\nWelcome, {username}!")
                
                msg1 = input("Enter secret: ")
                msg2 = incrypting_RSA(msg1)
                msg3 = encode_b64(msg2)
                
                msg4 = decode_b64(msg3)
                msg5 = decrpting_RSA()

                users[user_key]["secret"].append(msg3)
                save_users(users)
                print(f"Sent: {msg3}")
                print(f"Decrypted: {msg5}")
                break
            else:
                print("\033[31mIncorrect Password\033[0m\n")
        else:
            print(f"User '{username}' not found.")
            if register():
                break


if __name__ == '__main__':
    running = input("Start program? (y/n): ").strip().lower()
    if running == 'y':
        login()
