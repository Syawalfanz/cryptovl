"""
vault.py — SecureVault File Metadata Manager
Each file stores a dict of enc_keys: { username: base64_encrypted_key }
so each user can decrypt with their own AES key.
"""

import os, json, uuid, base64
from datetime import datetime

FILES_DB   = "data/files.json"
UPLOAD_DIR = "uploads"


def _load() -> list:
    if not os.path.exists(FILES_DB):
        return []
    with open(FILES_DB, "r") as f:
        return json.load(f)

def _save(records: list):
    os.makedirs("data", exist_ok=True)
    with open(FILES_DB, "w") as f:
        json.dump(records, f, indent=2)


def save_file_record(filename: str, owner: str, file_hash: str,
                     signature: bytes, enc_key: bytes,
                     size: int, shared_with: list = None) -> str:
    """Save metadata. enc_key is the owner's encrypted copy."""
    records = _load()
    fid = str(uuid.uuid4())
    records.append({
        "id"          : fid,
        "filename"    : filename,
        "owner"       : owner,
        "shared_with" : shared_with or [],
        "file_hash"   : file_hash,
        "signature"   : base64.b64encode(signature).decode(),
        # Per-user encrypted keys: { username: base64_enc_key }
        "enc_keys"    : { owner: base64.b64encode(enc_key).decode() },
        "uploaded_at" : datetime.now().isoformat(timespec="seconds"),
        "size"        : size
    })
    _save(records)
    return fid


def get_file(fid: str) -> dict:
    for r in _load():
        if r["id"] == fid:
            return r
    return None


def get_user_files(username: str) -> list:
    return [
        r for r in _load()
        if r["owner"] == username or username in r.get("shared_with", [])
    ]


def get_enc_key_for_user(fid: str, username: str) -> bytes | None:
    """Return the AES file key encrypted for this specific user."""
    record = get_file(fid)
    if not record:
        return None
    enc_keys = record.get("enc_keys", {})
    # Fallback to old "enc_key" field for backward compatibility
    if username in enc_keys:
        return base64.b64decode(enc_keys[username])
    if "enc_key" in record and username == record["owner"]:
        return base64.b64decode(record["enc_key"])
    return None


def add_enc_key_for_user(fid: str, username: str, enc_key: bytes) -> bool:
    """Store an encrypted copy of the file key for a new shared user."""
    records = _load()
    for r in records:
        if r["id"] == fid:
            if "enc_keys" not in r:
                r["enc_keys"] = {}
            r["enc_keys"][username] = base64.b64encode(enc_key).decode()
            if username not in r["shared_with"]:
                r["shared_with"].append(username)
            _save(records)
            return True
    return False


def delete_file(fid: str, username: str) -> bool:
    records = _load()
    target  = next((r for r in records if r["id"] == fid), None)
    if not target or target["owner"] != username:
        return False
    enc_path = os.path.join(UPLOAD_DIR, fid + ".enc")
    if os.path.exists(enc_path):
        os.remove(enc_path)
    _save([r for r in records if r["id"] != fid])
    return True


def get_enc_path(fid: str) -> str:
    return os.path.join(UPLOAD_DIR, fid + ".enc")


def format_size(size: int) -> str:
    if size < 1024:    return f"{size} B"
    if size < 1024**2: return f"{size/1024:.1f} KB"
    return                    f"{size/1024**2:.1f} MB"
