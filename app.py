"""
app.py — SecureVault Flask Application
"""

import os, base64
from flask import (Flask, render_template, request, redirect,
                   url_for, session, flash, send_file)
from io import BytesIO

from crypto import (encrypt_file, decrypt_file, encrypt_key, decrypt_key,
                    generate_file_key, hash_file, sign_file, verify_signature)
from auth  import register, login, get_private_key, get_public_key, user_exists, all_users, get_user
from key_utils import get_file_key
from vault import (save_file_record, get_file, get_user_files, delete_file,
                   get_enc_path, format_size, get_enc_key_for_user, add_enc_key_for_user)

app = Flask(__name__)
app.secret_key = os.urandom(32)

UPLOAD_DIR  = "uploads"
MAX_FILE_MB = 16
os.makedirs(UPLOAD_DIR, exist_ok=True)


# ── Helpers ───────────────────────────────────────────────────────────────────

def logged_in():
    return "username" in session

def get_aes_key() -> bytes:
    return base64.b64decode(session["aes_key"])


# ── Auth Routes ───────────────────────────────────────────────────────────────

@app.route("/register", methods=["GET", "POST"])
def register_page():
    if logged_in():
        return redirect(url_for("dashboard"))
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        confirm  = request.form.get("confirm", "")
        if password != confirm:
            flash("Passwords do not match.", "error")
            return render_template("login.html", mode="register")
        ok, result = register(username, password)
        if not ok:
            flash(result, "error")
            return render_template("login.html", mode="register")
        session["username"] = username
        session["aes_key"]  = base64.b64encode(result).decode()
        flash("Account created! Welcome to SecureVault.", "success")
        return redirect(url_for("dashboard"))
    return render_template("login.html", mode="register")


@app.route("/login", methods=["GET", "POST"])
def login_page():
    if logged_in():
        return redirect(url_for("dashboard"))
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        ok, result = login(username, password)
        if not ok:
            flash(result, "error")
            return render_template("login.html", mode="login")
        session["username"] = username
        session["aes_key"]  = base64.b64encode(result).decode()
        flash(f"Welcome back, {username}!", "success")
        return redirect(url_for("dashboard"))
    return render_template("login.html", mode="login")


@app.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for("login_page"))


# ── Dashboard ─────────────────────────────────────────────────────────────────

@app.route("/")
def dashboard():
    if not logged_in():
        return redirect(url_for("login_page"))
    username = session["username"]
    files    = get_user_files(username)
    for f in files:
        f["size_fmt"] = format_size(f["size"])
    return render_template("dashboard.html", files=files, username=username)


# ── Upload ────────────────────────────────────────────────────────────────────

@app.route("/upload", methods=["POST"])
def upload():
    if not logged_in():
        return redirect(url_for("login_page"))

    uploaded = request.files.get("file")
    if not uploaded or uploaded.filename == "":
        flash("No file selected.", "error")
        return redirect(url_for("dashboard"))

    raw = uploaded.read()
    if len(raw) > MAX_FILE_MB * 1024 * 1024:
        flash(f"File too large. Max {MAX_FILE_MB}MB.", "error")
        return redirect(url_for("dashboard"))

    username = session["username"]
    aes_key  = get_aes_key()

    # 1. SHA-256 hash of original file (Integrity)
    file_hash = hash_file(raw)

    # 2. RSA-PSS sign the hash (Authenticity)
    private_key = get_private_key(username, aes_key)
    signature   = sign_file(file_hash, private_key)

    # 3. Generate per-file AES key, encrypt file (Confidentiality)
    file_key     = generate_file_key()
    enc_data     = encrypt_file(raw, file_key)

    # 4. Encrypt the file key with owner's master AES key
    enc_file_key = encrypt_key(file_key, aes_key)

    # 5. Save record and encrypted file
    fid = save_file_record(
        filename  = uploaded.filename,
        owner     = username,
        file_hash = file_hash,
        signature = signature,
        enc_key   = enc_file_key,
        size      = len(raw)
    )
    with open(get_enc_path(fid), "wb") as f:
        f.write(enc_data)

    flash(f"✅ '{uploaded.filename}' encrypted and uploaded successfully.", "success")
    return redirect(url_for("dashboard"))


# ── Download ──────────────────────────────────────────────────────────────────

@app.route("/download/<fid>")
def download(fid):
    if not logged_in():
        return redirect(url_for("login_page"))

    username = session["username"]
    aes_key  = get_aes_key()
    record   = get_file(fid)

    if not record:
        flash("File not found.", "error")
        return redirect(url_for("dashboard"))
    if record["owner"] != username and username not in record.get("shared_with", []):
        flash("Access denied.", "error")
        return redirect(url_for("dashboard"))

    with open(get_enc_path(fid), "rb") as f:
        enc_data = f.read()

    try:
        file_key = get_file_key(fid, username, aes_key)
    except Exception as e:
        flash(f"Decryption error: {e}", "error")
        return redirect(url_for("dashboard"))
    raw = decrypt_file(enc_data, file_key)

    return send_file(BytesIO(raw), download_name=record["filename"], as_attachment=True)


# ── Verify ────────────────────────────────────────────────────────────────────

@app.route("/verify/<fid>")
def verify(fid):
    if not logged_in():
        return redirect(url_for("login_page"))

    username = session["username"]
    aes_key  = get_aes_key()
    record   = get_file(fid)

    if not record:
        flash("File not found.", "error")
        return redirect(url_for("dashboard"))

    with open(get_enc_path(fid), "rb") as f:
        enc_data = f.read()

    try:
        file_key = get_file_key(fid, username, aes_key)
    except Exception as e:
        flash(f"Decryption error: {e}", "error")
        return redirect(url_for("dashboard"))
    raw       = decrypt_file(enc_data, file_key)
    live_hash = hash_file(raw)

    integrity_ok = (live_hash == record["file_hash"])

    owner_pub    = get_public_key(record["owner"])
    signature    = base64.b64decode(record["signature"])
    authentic_ok = verify_signature(record["file_hash"], signature, owner_pub)

    return render_template("verify.html",
        record       = record,
        stored_hash  = record["file_hash"],
        live_hash    = live_hash,
        integrity_ok = integrity_ok,
        authentic_ok = authentic_ok,
        size_fmt     = format_size(record["size"]),
        username     = username
    )


# ── Delete ────────────────────────────────────────────────────────────────────

@app.route("/delete/<fid>", methods=["POST"])
def delete(fid):
    if not logged_in():
        return redirect(url_for("login_page"))
    ok = delete_file(fid, session["username"])
    flash("File deleted." if ok else "Could not delete file.", "info" if ok else "error")
    return redirect(url_for("dashboard"))


# ── Share ─────────────────────────────────────────────────────────────────────

@app.route("/share/<fid>", methods=["POST"])
def share(fid):
    if not logged_in():
        return redirect(url_for("login_page"))

    owner    = session["username"]
    aes_key  = get_aes_key()
    target   = request.form.get("target_user", "").strip()

    if not user_exists(target):
        flash(f"User '{target}' not found.", "error")
        return redirect(url_for("dashboard"))
    if target == owner:
        flash("You cannot share a file with yourself.", "error")
        return redirect(url_for("dashboard"))

    record = get_file(fid)
    if not record or record["owner"] != owner:
        flash("File not found or access denied.", "error")
        return redirect(url_for("dashboard"))

    # Decrypt the file key using owner's AES key
    enc_key  = get_enc_key_for_user(fid, owner)
    file_key = decrypt_key(enc_key, aes_key)

    # Re-encrypt the file key with the TARGET user's AES key
    # We need to derive their AES key — we use their stored salt
    from auth import derive_key
    target_user = get_user(target)
    import base64 as b64
    target_salt    = b64.b64decode(target_user["salt"])
    # We can't derive target's key from their password (we don't know it)
    # Instead we encrypt file_key with target's RSA PUBLIC key
    from crypto import load_public_key
    target_pub_pem = target_user["public_key"].encode()
    target_pub_key = load_public_key(target_pub_pem)

    from cryptography.hazmat.primitives.asymmetric import padding as apad
    from cryptography.hazmat.primitives import hashes as ahashes
    enc_for_target = target_pub_key.encrypt(
        file_key,
        apad.OAEP(
            mgf=apad.MGF1(algorithm=ahashes.SHA256()),
            algorithm=ahashes.SHA256(),
            label=None
        )
    )

    add_enc_key_for_user(fid, target, enc_for_target)
    flash(f"✅ File shared with {target}.", "success")
    return redirect(url_for("dashboard"))


if __name__ == "__main__":
    app.run(debug=True, port=5000)
