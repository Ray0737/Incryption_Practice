import os
import json
import base64
import getpass
import pkcs11
from pkcs11 import Attribute, ObjectClass, KeyType
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from argon2 import PasswordHasher
from argon2 import exceptions as argon_exceptions

# Configuration
DATA_FILE = "main_log.json"
PKCS11_LIB = os.getenv('PKCS11_MODULE', '/usr/local/lib/softhsm/libsofthsm2.so') # Path to your HSM driver
TOKEN_LABEL = 'MySecurityToken'
KEY_LABEL = 'VaultMasterKey'

ph = PasswordHasher()

#-----------------------------------------------------HSM Logic-----------------------------------------------------#

def get_hsm_session(user_pin):
    try:
        lib = pkcs11.lib(PKCS11_LIB)
        token = lib.get_token(token_label=TOKEN_LABEL)
        return token.open(user_pin=user_pin, rw=True)
    except Exception as e:
        print(f"HSM Connection Error: {e}")
        return None

def get_keys_from_hsm(session):
    keys = list(session.get_objects({
        Attribute.CLASS: ObjectClass.PRIVATE_KEY,
        Attribute.LABEL: KEY_LABEL,
    }))

    if keys:
        print("--- HSM SECURE KEY DETECTED ---")
        priv_key = keys[0]
        pub_key_obj = list(session.get_objects({
            Attribute.CLASS: ObjectClass.PUBLIC_KEY,
            Attribute.LABEL: KEY_LABEL,
        }))[0]
        return priv_key, pub_key_obj
    else:
        print("--- GENERATING NEW KEY PAIR INSIDE HSM ---")
        pub, priv = session.generate_keypair(KeyType.RSA, 3072, label=KEY_LABEL)
        return priv, pub

#-----------------------------------------------------Encryption Logic-----------------------------------------------------#

def encrypt_secret_hsm(message_text, public_key_handle):

    session_key = AESGCM.generate_key(bit_length=256)
    nonce = os.urandom(12)
    aesgcm = AESGCM(session_key)
    ciphertext = aesgcm.encrypt(nonce, message_text.encode(), None)

    enc_session_key = public_key_handle.encrypt(
        session_key,
        mechanism=pkcs11.Mechanism.RSA_PKCS_OAEP,
        mechanism_param=(pkcs11.Mechanism.SHA256, pkcs11.MGF1.SHA256, None)
    )

    return {
        "key": base64.b64encode(enc_session_key).decode('utf-8'),
        "nonce": base64.b64encode(nonce).decode('utf-8'),
        "ciphertext": base64.b64encode(ciphertext).decode('utf-8')
    }

def decrypt_secret_hsm(package, private_key_handle):

    enc_session_key = base64.b64decode(package["key"])
    nonce = base64.b64decode(package["nonce"])
    ciphertext = base64.b64decode(package["ciphertext"])

    session_key = private_key_handle.decrypt(
        enc_session_key,
        mechanism=pkcs11.Mechanism.RSA_PKCS_OAEP,
        mechanism_param=(pkcs11.Mechanism.SHA256, pkcs11.MGF1.SHA256, None)
    )

    aesgcm = AESGCM(session_key)
    return aesgcm.decrypt(nonce, ciphertext, None).decode()

#-----------------------------------------------------Database & Flow-----------------------------------------------------#

def load_db():
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, 'r') as f:
            try: return json.load(f)
            except: return {}
    return {}

def save_db(data):
    with open(DATA_FILE, 'w') as f:
        json.dump(data, f, indent=4)

def run_app():
    db = load_db()
    hsm_pin = getpass.getpass("Enter HSM User PIN: ")
    
    with get_hsm_session(hsm_pin) as session:
        if not session: return
        
        priv_key_handle, pub_key_handle = get_keys_from_hsm(session)
        
        username = input("\nEnter Username: ")
        if username not in db:
            password = getpass.getpass("Create User Password: ")
            db[username] = {"hash": ph.hash(password), "vault": []}
            save_db(db)
        
        user_pw = getpass.getpass(f"Enter password for {username}: ")
        try:
            ph.verify(db[username]["hash"], user_pw)
            print("Login Successful!")
            
            msg = input("\nEnter secret: ")
            package = encrypt_secret_hsm(msg, pub_key_handle)
            db[username]["vault"].append(package)
            save_db(db)
            
            print("\n--- VAULT UPDATED (Hardware Secured) ---")
            decrypted = decrypt_secret_hsm(db[username]["vault"][-1], priv_key_handle)
            print(f"Decrypted: {decrypted}")
            
        except argon_exceptions.VerifyMismatchError:
            print("Access Denied.")

if __name__ == "__main__":
    run_app()