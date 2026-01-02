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

#-----------------------------------------------------JSON Set up-----------------------------------------------------#

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

#-----------------------------------------------------Encoder & Decoder & Sender -----------------------------------------------------#

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

#--------------------------------------RSA AES--------------------------------------# 

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

#-----------------------------------------------------Code Executer-----------------------------------------------------#

def register():
    users = load_users()
    username = input("Enter a new username: ")
    username_h = hash_sha256(username)
    
    if username_h in users:
        print("Username already exists.")
        return False
    
    password = input("Enter a password: ")
    salt, password_h = hash_new_password(password)
    
    users[username_h] = {
        "01": salt,
        "02": password_h,
        "03": [] 
    }
    save_users(users)
    print(f"User '{username}' registered successfully!")
    return True

def login():
    users = load_users() 
    while True:
        username = input("Enter your username: ")
        username_h = hash_sha256(username)
        
        if username_h in users:
            password = input("Enter your password: ")
            user_data = users[username_h]
            
            if verify_password(user_data["01"], user_data["02"], password):
                print(f"\nWelcome, {username}!")
                
                msg1 = input("Enter secret: ")
                msg2 = incrypting_RSA(msg1)
                msg3 = encode_b64(msg2)
                
                msg4 = decode_b64(msg3)
                msg5 = decrpting_RSA()
                
                users[username_h]["03"].append(msg3)
                save_users(users)
                
                print(f"Stored (Hex): {msg3}")
                break
            else:
                print("\033[31mIncorrect Password\033[0m\n")
        else:
            print(f"User '{username}' not found.")
            if register():
                # Re-load users so the login loop finds the new person
                users = load_users()
                continue 

if __name__ == '__main__':
    running = input("Start program? (y/n): ").strip().lower()
    if running == 'y':

        login()
