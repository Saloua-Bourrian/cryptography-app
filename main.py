#!/usr/bin/env python3
# pip install cryptography
import os, json, base64, hmac
from getpass import getpass

from cryptography.hazmat.primitives.kdf.scrypt import Scrypt          # Salt_1 → pwd_token
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC      # Salt_2 → K_user
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM        # AEAD (AES-GCM)

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

# ========== Core flows ==========
def register_user(db: dict) -> dict:
    print("\n=== Register User ===")
    username = input("Choose a username [A-Za-z0-9_-]: ").strip()
    if not username:
        print("Username cannot be empty."); return db
    if username != sanitize_username(username):
        print("Username contains invalid characters. Allowed: letters, digits, -, _"); return db
    if username in db:
        print("That username is already taken."); return db

    pw1 = getpass("Choose a password: ").strip()
    pw2 = getpass("Repeat password: ").strip()
    if not pw1 or pw1 != pw2:
        print("Passwords empty or don’t match."); return db

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
        "scrypt": { "n": SCRYPT_N, "r": SCRYPT_R, "p": SCRYPT_P, "dklen": SCRYPT_LEN },

        "salt_key": salt_key,
        "pbkdf2": { "iterations": PBKDF2_ITER, "dklen": KEY_LEN }
    }
    save_db(db)
    print(f"User '{username}' registered.\n")
    return db

def authenticate_user(db: dict):
    print("\n=== Login ===")
    username = input("Username: ").strip()
    if username not in db:
        print("No such user."); return None, None

    record = db[username]
    password = getpass("Password: ").strip()

    # 1) Verify password with scrypt (Salt_1)
    if not scrypt_verify(password, record["salt_pwd"], record["pwd_token"]):
        print("Incorrect password."); return None, None

    # 2) Derive K_user with PBKDF2 (Salt_2)
    iters = record.get("pbkdf2", {}).get("iterations", PBKDF2_ITER)
    key_user = pbkdf2_derive_key(password, record["salt_key"], iters)

    print("Login successful!")
    return username, key_user

def add_entry(username: str, key: bytes):
    print("\n=== New Encrypted Entry ===")
    plaintext = input("Write your entry (single line): ")
    aes = AESGCM(key)
    nonce = os.urandom(NONCE_LEN)
    aad = username.encode("utf-8")  # bind entry to this user (AAD)

    # AES-GCM returns ciphertext||tag in one blob
    ct = aes.encrypt(nonce, plaintext.encode("utf-8"), aad)

    entry = {"nonce": b64e(nonce), "ciphertext": b64e(ct)}
    entries = load_entries(username)
    entries.append(entry)
    save_entries(username, entries)
    print("Saved.\n")

def view_entries(username: str, key: bytes):
    print("\n=== Your Entries (decrypted) ===")
    entries = load_entries(username)
    if not entries:
        print("(no entries yet)\n"); return
    aes = AESGCM(key)
    aad = username.encode("utf-8")
    for i, e in enumerate(entries, 1):
        nonce = b64d(e["nonce"])
        ct = b64d(e["ciphertext"])
        try:
            pt = aes.decrypt(nonce, ct, aad).decode("utf-8")
            print(f"{i}) {pt}")
        except Exception:
            print(f"{i}) [AUTHENTICATION FAILED: tampered or wrong key]")
    print()

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
            username, key = authenticate_user(db)
            if username is None:
                continue
            # per-user session
            while True:
                print("\n--- Session ---")
                print("1) Add entry")
                print("2) View entries")
                print("3) Logout")
                sub = input("Select (1-3): ").strip()
                if sub == "1":
                    add_entry(username, key)
                elif sub == "2":
                    view_entries(username, key)
                elif sub == "3":
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


