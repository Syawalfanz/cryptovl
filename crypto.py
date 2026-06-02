"""
crypto.py — SecureVault Cryptography Core
==========================================
Provides AES-256-GCM file encryption, SHA-256 hashing,
and RSA-2048 digital signatures.

Security services:
  Confidentiality → AES-256-GCM encrypt/decrypt
  Integrity       → SHA-256 file hash
  Authenticity    → RSA-2048 PSS sign/verify
"""

import os, hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend

IV_SIZE  = 12
KEY_SIZE = 32


# ── AES-256-GCM ───────────────────────────────────────────────────────────────

def generate_file_key() -> bytes:
    return os.urandom(KEY_SIZE)

def encrypt_file(data: bytes, key: bytes) -> bytes:
    iv     = os.urandom(IV_SIZE)
    aesgcm = AESGCM(key)
    ct     = aesgcm.encrypt(iv, data, None)
    return iv + ct

def decrypt_file(token: bytes, key: bytes) -> bytes:
    iv, ct = token[:IV_SIZE], token[IV_SIZE:]
    return AESGCM(key).decrypt(iv, ct, None)

def encrypt_key(file_key: bytes, aes_key: bytes) -> bytes:
    """Encrypt a file key with the user's master AES key."""
    iv     = os.urandom(IV_SIZE)
    aesgcm = AESGCM(aes_key)
    return iv + aesgcm.encrypt(iv, file_key, None)

def decrypt_key(token: bytes, aes_key: bytes) -> bytes:
    iv, ct = token[:IV_SIZE], token[IV_SIZE:]
    return AESGCM(aes_key).decrypt(iv, ct, None)


# ── SHA-256 File Hash ─────────────────────────────────────────────────────────

def hash_file(data: bytes) -> str:
    """Return hex SHA-256 digest of raw file bytes."""
    return hashlib.sha256(data).hexdigest()


# ── RSA-2048 ──────────────────────────────────────────────────────────────────

def generate_rsa_keypair():
    priv = rsa.generate_private_key(
        public_exponent=65537, key_size=2048, backend=default_backend()
    )
    return priv, priv.public_key()

def serialize_private_key(priv) -> bytes:
    return priv.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()
    )

def serialize_public_key(pub) -> bytes:
    return pub.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo
    )

def load_private_key(pem: bytes):
    return serialization.load_pem_private_key(pem, password=None, backend=default_backend())

def load_public_key(pem: bytes):
    return serialization.load_pem_public_key(pem, backend=default_backend())

def sign_file(file_hash: str, private_key) -> bytes:
    """Sign the hex file hash with RSA-PSS."""
    return private_key.sign(
        file_hash.encode(),
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256()
    )

def verify_signature(file_hash: str, signature: bytes, public_key) -> bool:
    """Verify RSA-PSS signature over file hash."""
    try:
        public_key.verify(
            signature,
            file_hash.encode(),
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False


# ── RSA OAEP Key Wrap (for file sharing) ─────────────────────────────────────

def rsa_decrypt_key(enc_file_key: bytes, private_key) -> bytes:
    """
    Decrypt a file key that was encrypted with RSA-OAEP for sharing.
    Used by recipients to unwrap the file key using their RSA private key.
    """
    from cryptography.hazmat.primitives.asymmetric import padding as apad
    from cryptography.hazmat.primitives import hashes as ahashes
    return private_key.decrypt(
        enc_file_key,
        apad.OAEP(
            mgf=apad.MGF1(algorithm=ahashes.SHA256()),
            algorithm=ahashes.SHA256(),
            label=None
        )
    )
