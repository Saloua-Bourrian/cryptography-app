#!/usr/bin/env python3
# pip install cryptography
import os, json, base64, hmac, datetime
from getpass import getpass

from cryptography.hazmat.primitives.kdf.scrypt import Scrypt          # Salt_1 → pwd_token
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC      # Salt_2 → K_user
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM        # AEAD (AES-GCM)
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography import x509
from cryptography.x509.oid import NameOID

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

# ---- Signature / Key / Cert paths ----
RSA_PRIV_PEM = "rsa_private.pem"   # encrypted PKCS8 PEM
RSA_PUB_PEM  = "rsa_public.pem"    # SubjectPublicKeyInfo PEM
SIGNER_CERT  = "signer_cert.pem"   # self-signed cert PEM

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

# ========== RSA Key / Cert Management ==========
def generate_rsa_keypair() -> tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
    priv = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    return priv, priv.public_key()

def save_rsa_private_key_pem_encrypted(private_key, path: str, password: bytes):
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,  # per spec
        encryption_algorithm=serialization.BestAvailableEncryption(password),
    )
    with open(path, "wb") as f:
        f.write(pem)

def save_rsa_public_key_pem(public_key, path: str):
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,  # per spec
    )
    with open(path, "wb") as f:
        f.write(pem)

def load_rsa_private_key_pem(path: str, password: bytes):
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=password)

def load_rsa_public_key_pem(path: str):
    with open(path, "rb") as f:
        return serialization.load_pem_public_key(f.read())

def create_self_signed_cert(private_key, common_name: str) -> x509.Certificate:
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = datetime.datetime.utcnow()
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=1))
        .not_valid_after(now + datetime.timedelta(days=365*2))
    )
    cert = builder.sign(private_key=private_key, algorithm=hashes.SHA256())
    return cert

def save_cert_pem(cert: x509.Certificate, path: str):
    with open(path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

def load_cert_pem(path: str) -> x509.Certificate:
    with open(path, "rb") as f:
        return x509.load_pem_x509_certificate(f.read())

def verify_cert_signature_self_signed(cert: x509.Certificate) -> bool:
    """Verify a self-signed cert by checking its own signature."""
    pub = cert.public_key()
    try:
        # Most self-signed RSA certs use PKCS1v15 with SHA256; library gives hash alg.
        pub.verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            asym_padding.PKCS1v15(),
            cert.signature_hash_algorithm,
        )
        return True
    except Exception:
        return False

# ========== RSA-PSS Sign/Verify ==========
def rsa_sign_pss_sha256(private_key, message_bytes: bytes) -> bytes:
    return private_key.sign(
        message_bytes,
        asym_padding.PSS(
            mgf=asym_padding.MGF1(hashes.SHA256()),
            salt_length=asym_padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )

def rsa_verify_pss_sha256(public_key, message_bytes: bytes, signature: bytes) -> bool:
    try:
        public_key.verify(
            signature,
            message_bytes,
            asym_padding.PSS(
                mgf=asym_padding.MGF1(hashes.SHA256()),
                salt_length=asym_padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
        return True
    except Exception:
        return False

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

def ensure_keys_and_cert_exist():
    """Generate RSA keys and a self-signed certificate if missing."""
    need = []
    if not os.path.exists(RSA_PRIV_PEM): need.append("private key")
    if not os.path.exists(RSA_PUB_PEM):  need.append("public key")
    if not os.path.exists(SIGNER_CERT):  need.append("self-signed cert")
    if not need:
        return True

    print("\n=== RSA Keypair & Self-Signed Certificate Setup ===")
    pw1 = getpass("Set a password to encrypt your private key (PEM): ").strip().encode()
    pw2 = getpass("Repeat password: ").strip().encode()
    if not pw1 or pw1 != pw2:
        print("Private key password empty or didn’t match."); return False

    cn = input("Common Name for certificate (e.g., your name or user id): ").strip() or "Diary Signer"

    priv, pub = generate_rsa_keypair()
    save_rsa_private_key_pem_encrypted(priv, RSA_PRIV_PEM, pw1)
    save_rsa_public_key_pem(pub, RSA_PUB_PEM)
    cert = create_self_signed_cert(priv, cn)
    save_cert_pem(cert, SIGNER_CERT)

    print(f"Generated {RSA_PRIV_PEM}, {RSA_PUB_PEM}, {SIGNER_CERT}\n")
    return True

def load_private_key_interactive():
    """Prompt for PEM password and load RSA private key."""
    if not os.path.exists(RSA_PRIV_PEM):
        print("Missing private key PEM. Use menu option 4 to generate it."); return None
    pw = getpass("Private key password (for rsa_private.pem): ").strip().encode()
    try:
        return load_rsa_private_key_pem(RSA_PRIV_PEM, pw)
    except Exception:
        print("Failed to load/decrypt private key. Wrong password or corrupt file.")
        return None

def load_signer_cert_or_pubkey():
    """Load certificate (preferred) or public key for verification."""
    if os.path.exists(SIGNER_CERT):
        try:
            cert = load_cert_pem(SIGNER_CERT)
            if not verify_cert_signature_self_signed(cert):
                print("[Warning] Self-signed certificate signature could not be verified.")
            return cert, cert.public_key()
        except Exception:
            print("[Warning] Failed to load/parse signer_cert.pem, falling back to public key.")
    if os.path.exists(RSA_PUB_PEM):
        try:
            return None, load_rsa_public_key_pem(RSA_PUB_PEM)
        except Exception:
            pass
    print("No certificate or public key available. Generate them with option 4.")
    return None, None

def add_entry(username: str, key: bytes):
    # Make sure we can sign
    if not (os.path.exists(RSA_PRIV_PEM) and (os.path.exists(SIGNER_CERT) or os.path.exists(RSA_PUB_PEM))):
        print("Signing material missing. Run option 4) Generate RSA keypair & self-signed cert first.")
        return
    priv = load_private_key_interactive()
    if priv is None:
        return

    print("\n=== New Encrypted & Signed Entry ===")
    plaintext = input("Write your entry (single line): ")
    aes = AESGCM(key)
    nonce = os.urandom(NONCE_LEN)
    aad = username.encode("utf-8")  # bind entry to this user (AAD)

    # Encrypt
    ct = aes.encrypt(nonce, plaintext.encode("utf-8"), aad)

    # Sign exact bytes we persist for confidentiality (nonce||ciphertext)
    message_bytes = nonce + ct
    signature = rsa_sign_pss_sha256(priv, message_bytes)

    entry = {
        "nonce": b64e(nonce),
        "ciphertext": b64e(ct),
        "signature": b64e(signature),
        "sig_alg": "RSA-PSS-SHA256",
        "cert": SIGNER_CERT if os.path.exists(SIGNER_CERT) else None
    }
    entries = load_entries(username)
    entries.append(entry)
    save_entries(username, entries)
    print("Saved (encrypted + signed).\n")

def view_entries(username: str, key: bytes):
    print("\n=== Your Entries (signature check → decrypt) ===")
    entries = load_entries(username)
    if not entries:
        print("(no entries yet)\n"); return

    # Load verification key (prefer the certificate)
    cert, pubkey = load_signer_cert_or_pubkey()
    if pubkey is None:
        return

    aes = AESGCM(key)
    aad = username.encode("utf-8")

    for i, e in enumerate(entries, 1):
        try:
            nonce = b64d(e["nonce"])
            ct = b64d(e["ciphertext"])
            sig = b64d(e.get("signature", "")) if e.get("signature") else None
            message_bytes = nonce + ct

            # Verify signature first (public verifiability)
            if sig is None:
                print(f"{i}) [NO SIGNATURE PRESENT]"); continue

            ok_sig = rsa_verify_pss_sha256(pubkey, message_bytes, sig)
            if not ok_sig:
                print(f"{i}) [INVALID SIGNATURE]"); continue

            # Optional: verify the (self-signed) cert every time (already done at load);
            # in a CA PKI, you would verify chain here.

            # Then decrypt (symmetric integrity via GCM tag)
            pt = aes.decrypt(nonce, ct, aad).decode("utf-8")
            print(f"{i}) {pt}")
        except Exception:
            print(f"{i}) [AUTHENTICATION FAILED: tampered or wrong key]")
    print()

def generate_keys_and_cert():
    ensure_keys_and_cert_exist()

def main():
    while True:
        print("\n=== Encrypted & Signed Multi-User Diary ===")
        print("1) Register")
        print("2) Login")
        print("3) Exit")
        print("4) Generate RSA keypair & self-signed cert")
        choice = input("Select an option (1-4): ").strip()

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
                print("1) Add entry (encrypt + sign)")
                print("2) View entries (verify + decrypt)")
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
        elif choice == "4":
            generate_keys_and_cert()
        else:
            print("Invalid option. Please choose 1–4.")

if __name__ == "__main__":
    main()



