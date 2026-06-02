"""
auth.py — SecureVault User Authentication
==========================================
PBKDF2-HMAC-SHA256 key derivation + user account management.
Users stored in data/users.json
"""

import os, json, base64, hmac
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from crypto import (generate_rsa_keypair, serialize_private_key,
                    serialize_public_key, encrypt_file, decrypt_file)

USERS_FILE = "data/users.json"
ITERATIONS = 100_000
KEY_LENGTH = 32
SALT_SIZE  = 32


def _load_users() -> dict:
    if not os.path.exists(USERS_FILE):
        return {}
    with open(USERS_FILE, "r") as f:
        return json.load(f)

def _save_users(users: dict):
    os.makedirs("data", exist_ok=True)
    with open(USERS_FILE, "w") as f:
        json.dump(users, f, indent=2)

def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(), length=KEY_LENGTH,
        salt=salt, iterations=ITERATIONS
    )
    return kdf.derive(password.encode())

def _hash_password(password: str, salt: bytes) -> str:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(), length=KEY_LENGTH,
        salt=salt + b"_auth", iterations=ITERATIONS
    )
    return base64.b64encode(kdf.derive(password.encode())).decode()

def register(username: str, password: str) -> tuple:
    """
    Register a new user.
    Returns (True, aes_key) on success, (False, error_msg) on failure.
    """
    users = _load_users()
    if username in users:
        return False, "Username already exists."
    if len(password) < 8:
        return False, "Password must be at least 8 characters."

    salt    = os.urandom(SALT_SIZE)
    aes_key = derive_key(password, salt)
    pw_hash = _hash_password(password, salt)

    # Generate RSA keypair — private key encrypted with AES
    priv, pub = generate_rsa_keypair()
    priv_pem  = serialize_private_key(priv)
    pub_pem   = serialize_public_key(pub)
    enc_priv  = encrypt_file(priv_pem, aes_key)

    users[username] = {
        "salt"       : base64.b64encode(salt).decode(),
        "pw_hash"    : pw_hash,
        "public_key" : pub_pem.decode(),
        "private_key": base64.b64encode(enc_priv).decode()
    }
    _save_users(users)
    return True, aes_key

def login(username: str, password: str) -> tuple:
    """
    Authenticate user.
    Returns (True, aes_key) on success, (False, error_msg) on failure.
    """
    users = _load_users()
    if username not in users:
        return False, "User not found."

    user = users[username]
    salt = base64.b64decode(user["salt"])

    attempt = _hash_password(password, salt)
    if not hmac.compare_digest(attempt, user["pw_hash"]):
        return False, "Incorrect password."

    aes_key = derive_key(password, salt)
    return True, aes_key

def get_user(username: str) -> dict:
    return _load_users().get(username, {})

def get_private_key(username: str, aes_key: bytes):
    """Decrypt and return user's RSA private key."""
    from crypto import load_private_key
    user     = get_user(username)
    enc_priv = base64.b64decode(user["private_key"])
    priv_pem = decrypt_file(enc_priv, aes_key)
    return load_private_key(priv_pem)

def get_public_key(username: str):
    """Return user's RSA public key object."""
    from crypto import load_public_key
    user = get_user(username)
    return load_public_key(user["public_key"].encode())

def user_exists(username: str) -> bool:
    return username in _load_users()

def all_users() -> list:
    return list(_load_users().keys())
