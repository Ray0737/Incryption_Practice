import hashlib
import os
import json

DATA_FILE = "log2.json"

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

def hash_new_password(password):
    salt = os.urandom(16)
    hash_object = hashlib.sha256(salt + password.encode())
    return salt.hex(), hash_object.hexdigest()

def verify_password(stored_salt_hex, stored_hash, input_password):
    salt = bytes.fromhex(stored_salt_hex)
    hash_object = hashlib.sha256(salt + input_password.encode())
    return hash_object.hexdigest() == stored_hash

def register():
    users = load_users()
    username = input("Enter a new username: ")
    
    if username in users:
        print("Username already exists.")
        return False
    
    password = input("Enter a password: ")
    salt, hashed_pw = hash_new_password(password)
    
    users[username] = {
        "salt": salt,
        "password": hashed_pw,
        "secret": [] 
    }
    save_users(users)
    print(f"User '{username}' registered successfully!")
    return True

def login():
    users = load_users() # Refresh data
    while True:
        username = input("Enter your username: ")
        
        if username in users:
            password = input("Enter your password: ")
            user_data = users[username]
            
            # Use the verification function with the stored salt
            if verify_password(user_data["salt"], user_data["password"], password):
                print(f"\nWelcome, {username}!")
                
                secret = input("Enter secret to store: ")
                # Simple hex encoding as a placeholder for RSA
                hex_msg = secret.encode().hex() 
                
                users[username]["secret"].append(hex_msg)
                save_users(users)
                
                print(f"Stored (Hex): {hex_msg}")
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