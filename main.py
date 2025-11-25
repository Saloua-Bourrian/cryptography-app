#!/usr/bin/env python3
# pip install cryptography
import os, json, base64, hmac, time
from getpass import getpass

from cryptography.hazmat.primitives.kdf.scrypt import Scrypt          # Salt_1 → pwd_token
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC      # Salt_2 → K_user
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM        # AEAD (AES-GCM)

# NEW: signatures & certificates helpers
from sign_pki import (
    gen_rsa_keypair, gen_ed25519_keypair,
    rsa_sign_bytes, rsa_verify_bytes,
    ed25519_sign_bytes, ed25519_verify_bytes,
    self_signed_cert, make_csr,
    verify_chain, verify_cert_signed_by,
    gen_root_ca, issue_cert_for_pubkey
)

DB_FILE = "users_db.json"

# ---- PBKDF2 params (for K_user) ----
PBKDF2_ITER = 200_000
KEY_LEN = 32                # 256-bit key

# ---- scrypt params (for pwd_token) ----
SCRYPT_N = 2**14            # 16384
SCRYPT_R = 8
SCRYPT_P = 1
SCRYPT_LEN = KEY_LEN

# ---- AES-GCM params ----
NONCE_LEN = 12              # 96-bit nonce

# ---- CA paths ----
CA_PRIV_PATH = "keys/ca_priv.pem"
CA_CERT_PATH = "keys/ca_cert.pem"


# ========== Utils ==========
def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("utf-8")


def b64d(s: str) -> bytes:
    return base64.b64decode(s.encode("utf-8"))


def sanitize_username(name: str) -> str:
    # allow only [A-Za-z0-9_-]
    return "".join(c for c in name if c.isalnum() or c in "-_")


def data_file_for(username: str) -> str:
    safe = sanitize_username(username)
    return f"data_{safe}.json"


def load_db() -> dict:
    if not os.path.exists(DB_FILE):
        return {}
    try:
        with open(DB_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def save_db(db: dict) -> None:
    with open(DB_FILE, "w", encoding="utf-8") as f:
        json.dump(db, f, indent=2, ensure_ascii=False)


def load_entries(username: str):
    path = data_file_for(username)
    if not os.path.exists(path):
        return []
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return []


def save_entries(username: str, entries) -> None:
    with open(data_file_for(username), "w", encoding="utf-8") as f:
        json.dump(entries, f, indent=2, ensure_ascii=False)


# ========== KDF Helpers ==========
def scrypt_derive(password: str, salt_b64: str) -> bytes:
    """Salt_1 → scrypt(password, salt) for pwd_token"""
    kdf = Scrypt(
        salt=b64d(salt_b64),
        length=SCRYPT_LEN,
        n=SCRYPT_N,
        r=SCRYPT_R,
        p=SCRYPT_P,
    )
    return kdf.derive(password.encode("utf-8"))


def scrypt_verify(password: str, salt_b64: str, expected_b64: str) -> bool:
    """Constant-time verify of scrypt output"""
    try:
        cand = scrypt_derive(password, salt_b64)
        return hmac.compare_digest(cand, b64d(expected_b64))
    except Exception:
        return False


def pbkdf2_derive_key(password: str, salt_b64: str, iterations: int = PBKDF2_ITER) -> bytes:
    """Salt_2 → PBKDF2(password, salt) for K_user (encryption key)"""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_LEN,
        salt=b64d(salt_b64),
        iterations=iterations,
    )
    return kdf.derive(password.encode("utf-8"))


# ========== Key/Cert Menu ==========
def key_cert_menu(username: str, db: dict):
    print("\n=== Keys & Certificates ===")
    print("1) Initialize Root CA (once per project)")
    print("2) Generate RSA keypair + CA-signed cert")
    print("3) Generate Ed25519 keypair + CA-signed cert")
    print("4) Make CSR for external CA (from existing key)")
    print("5) Back")
    choice = input("Select (1-5): ").strip()

    os.makedirs("keys", exist_ok=True)
    priv_path = f"keys/{username}_priv.pem"
    pub_path  = f"keys/{username}_pub.pem"
    cert_path = f"keys/{username}_cert.pem"
    csr_path  = f"keys/{username}.csr.pem"

    user = db[username]

    if choice == "1":
        # Initialize Root CA (RSA)
        if os.path.exists(CA_PRIV_PATH) or os.path.exists(CA_CERT_PATH):
            print("Root CA already exists at keys/ca_*.pem")
            return
        ca_pw = getpass("Password to protect Root CA private key: ")
        gen_root_ca(CA_PRIV_PATH, CA_CERT_PATH, ca_pw)
        print("Root CA generated (keys/ca_priv.pem, keys/ca_cert.pem). Keep these files safe.")
    elif choice in ("2", "3"):
        # User keypair + CA-signed cert
        if not (os.path.exists(CA_PRIV_PATH) and os.path.exists(CA_CERT_PATH)):
            print("Root CA not found. Initialize it first (option 1).")
            return
        pw = getpass("Password to encrypt your private key: ")
        if choice == "2":
            gen_rsa_keypair(priv_path, pub_path, pw)
        else:
            gen_ed25519_keypair(priv_path, pub_path, pw)

        ca_pw = getpass("Root CA private key password: ")
        issue_cert_for_pubkey(
            username,
            pub_path,
            CA_PRIV_PATH,
            ca_pw,
            CA_CERT_PATH,
            cert_path
        )
        user["priv_key_path"] = priv_path
        user["cert_path"] = cert_path
        save_db(db)
        print("User keypair + CA-signed certificate created in keys/.")
    elif choice == "4":
        # CSR for external/demo CA
        if "priv_key_path" not in user:
            print("No private key on file. Generate one first.")
            return
        pw = getpass("Private key password: ")
        make_csr(username, user["priv_key_path"], pw, csr_path)
        print(f"CSR written to {csr_path}. Submit to your external CA; place issued cert as {cert_path}")
    else:
        return


# ========== Core flows ==========
def register_user(db: dict) -> dict:
    print("\n=== Register User ===")
    username = input("Choose a username [A-Za-z0-9_-]: ").strip()
    if not username:
        print("Username cannot be empty.")
        return db
    if username != sanitize_username(username):
        print("Username contains invalid characters. Allowed: letters, digits, -, _")
        return db
    if username in db:
        print("That username is already taken.")
        return db

    pw1 = getpass("Choose a password: ").strip()
    pw2 = getpass("Repeat password: ").strip()
    if not pw1 or pw1 != pw2:
        print("Passwords empty or don’t match.")
        return db

    # Two independent salts per the spec
    salt_pwd = b64e(os.urandom(16))   # Salt_1 for scrypt (pwd_token)
    salt_key = b64e(os.urandom(16))   # Salt_2 for PBKDF2 (K_user)

    # Verifier: scrypt(password, Salt_1)
    pwd_token = scrypt_derive(pw1, salt_pwd)

    # Store a self-describing record so params can change per-user in the future
    db[username] = {
        "algo_version": "v1",
        "salt_pwd": salt_pwd,
        "pwd_token": b64e(pwd_token),
        "scrypt": {"n": SCRYPT_N, "r": SCRYPT_R, "p": SCRYPT_P, "dklen": SCRYPT_LEN},

        "salt_key": salt_key,
        "pbkdf2": {"iterations": PBKDF2_ITER, "dklen": KEY_LEN}
        # Later we add: priv_key_path, cert_path
    }
    save_db(db)
    print(f"User '{username}' registered.")
    print("Tip: Open the 'Keys & Certificates' menu after login to generate your key and cert.\n")
    return db


def authenticate_user(db: dict):
    print("\n=== Login ===")
    username = input("Username: ").strip()
    if username not in db:
        print("No such user.")
        return None, None

    record = db[username]
    password = getpass("Password: ").strip()

    # 1) Verify password with scrypt (Salt_1)
    if not scrypt_verify(password, record["salt_pwd"], record["pwd_token"]):
        print("Incorrect password.")
        return None, None

    # 2) Derive K_user with PBKDF2 (Salt_2)
    iters = record.get("pbkdf2", {}).get("iterations", PBKDF2_ITER)
    key_user = pbkdf2_derive_key(password, record["salt_key"], iters)

    print("Login successful!")
    return username, key_user


def add_entry(username: str, key: bytes, db: dict):
    print("\n=== New Encrypted Entry (with Signature) ===")
    title = input("Title: ").strip()
    body  = input("Body (single line is fine): ").strip()

    # canonical plaintext bytes
    pt = json.dumps({"title": title, "body": body}, separators=(',', ':')).encode("utf-8")

    # AES-GCM encrypt (ciphertext includes tag)
    aes = AESGCM(key)
    nonce = os.urandom(NONCE_LEN)
    aad = username.encode("utf-8")
    ct = aes.encrypt(nonce, pt, aad)

    # --- SIGN ---
    user = db[username]
    if "priv_key_path" not in user:
        print("You must generate a key/cert first (Keys & Certificates menu).")
        return
    priv_path = user["priv_key_path"]
    algo = input("Sign with (rsa/ed25519) [ed25519]: ").strip().lower() or "ed25519"
    pw = getpass("Private key password: ")

    if algo == "rsa":
        sig = rsa_sign_bytes(priv_path, pw, pt)
    else:
        sig = ed25519_sign_bytes(priv_path, pw, pt)

    entries = load_entries(username)
    entry = {
        "id": len(entries) + 1,
        "ts": int(time.time()),
        "nonce": b64e(nonce),
        "ciphertext": b64e(ct),
        "sig": b64e(sig),
        "sig_algo": algo
    }
    entries.append(entry)
    save_entries(username, entries)
    print("Saved.\n")


def view_entries(username: str, key: bytes):
    print("\n=== Your Entries (decrypted) ===")
    entries = load_entries(username)
    if not entries:
        print("(no entries yet)\n")
        return
    aes = AESGCM(key)
    aad = username.encode("utf-8")
    for e in entries:
        nonce = b64d(e["nonce"])
        ct = b64d(e["ciphertext"])
        try:
            pt = aes.decrypt(nonce, ct, aad).decode("utf-8")
            j = json.loads(pt)
            print(f"[{e['id']}] {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(e['ts']))}")
            print(f"  Title: {j['title']}")
            print(f"  Body : {j['body']}\n")
        except Exception:
            print(f"[{e['id']}] [AUTH FAILED: tampered or wrong key]\n")


def verify_entry(username: str, key: bytes, db: dict):
    print("\n=== Verify Entry Signature ===")
    if username not in db:
        print("No such user.")
        return
    user = db[username]

    entries = load_entries(username)
    if not entries:
        print("No entries.")
        return
    idx = int(input(f"Entry number (1..{len(entries)}): ").strip())
    if not (1 <= idx <= len(entries)):
        print("Invalid index.")
        return
    e = entries[idx-1]

    # decrypt to recover exact plaintext bytes
    aes = AESGCM(key)
    aad = username.encode("utf-8")
    try:
        pt = aes.decrypt(b64d(e["nonce"]), b64d(e["ciphertext"]), aad)
    except Exception:
        print("Decryption failed (wrong password or tampering).")
        return

    sig = b64d(e["sig"])
    algo = e.get("sig_algo", "ed25519")

    # certificate presence
    cert_path = user.get("cert_path")
    if not cert_path or not os.path.exists(cert_path):
        print("User cert not found. Create/import it first (Keys & Certificates).")
        return

    # If CA cert exists, verify chain; else verify self-signed
    if os.path.exists(CA_CERT_PATH):
        if not verify_chain(cert_path, CA_CERT_PATH):
            print("Certificate chain verification FAILED.")
            return
    else:
        if not verify_cert_signed_by(cert_path, cert_path):
            print("Self-signed certificate verification FAILED.")
            return

    # signature verification using cert public key
    if algo == "rsa":
        ok = rsa_verify_bytes(cert_path, pt, sig)
    else:
        ok = ed25519_verify_bytes(cert_path, pt, sig)
    print("VALID signature ✅" if ok else "INVALID signature ❌")


def main():
    # If you previously had a plaintext users_db.json, delete it once before using this.
    while True:
        print("\n=== Encrypted Multi-User Diary ===")
        print("1) Register")
        print("2) Login")
        print("3) Exit")
        choice = input("Select an option (1-3): ").strip()

        if choice == "1":
            db = load_db()
            register_user(db)
        elif choice == "2":
            db = load_db()
            auth = authenticate_user(db)
            if auth == (None, None):
                continue
            username, key = auth

            # per-user session
            while True:
                print("\n--- Session ---")
                print("1) Add entry")
                print("2) View entries")
                print("3) Keys & Certificates")
                print("4) Verify an entry signature")
                print("5) Logout")
                sub = input("Select (1-5): ").strip()
                if sub == "1":
                    add_entry(username, key, db)
                elif sub == "2":
                    view_entries(username, key)
                elif sub == "3":
                    key_cert_menu(username, db)
                elif sub == "4":
                    verify_entry(username, key, db)
                elif sub == "5":
                    break
                else:
                    print("Invalid option.")
        elif choice == "3":
            print("Goodbye!")
            break
        else:
            print("Invalid option. Please choose 1, 2, or 3.")


if __name__ == "__main__":
    main()
