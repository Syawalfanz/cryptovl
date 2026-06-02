"""
key_utils.py — Smart file key decryption
Handles both owner keys (AES-wrapped) and shared keys (RSA-OAEP-wrapped).
"""

from crypto import decrypt_key, rsa_decrypt_key
from auth import get_private_key
from vault import get_enc_key_for_user, get_file

# RSA-2048 encrypted key is always 256 bytes
RSA_KEY_SIZE = 256

def get_file_key(fid: str, username: str, aes_key: bytes) -> bytes:
    """
    Retrieve and decrypt the file's AES key for this user.
    - Owner: key was encrypted with AES → decrypt with AES
    - Shared user: key was encrypted with RSA OAEP → decrypt with RSA private key
    """
    record  = get_file(fid)
    enc_key = get_enc_key_for_user(fid, username)

    if enc_key is None:
        raise ValueError("No decryption key found for your account.")

    if record["owner"] == username:
        # Owner: AES-wrapped key (IV=12 bytes prepended)
        return decrypt_key(enc_key, aes_key)
    else:
        # Shared user: RSA-OAEP wrapped key (256 bytes, no IV)
        if len(enc_key) == RSA_KEY_SIZE:
            private_key = get_private_key(username, aes_key)
            return rsa_decrypt_key(enc_key, private_key)
        else:
            # Fallback: try AES (backward compat)
            return decrypt_key(enc_key, aes_key)
