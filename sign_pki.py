#!/usr/bin/env python3
# pip install cryptography
from __future__ import annotations
import base64, datetime, pathlib
from typing import Optional

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.serialization import (
    Encoding, PrivateFormat, PublicFormat, BestAvailableEncryption, NoEncryption,
    load_pem_private_key, load_pem_public_key
)
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding, ed25519
from cryptography import x509
from cryptography.x509.oid import NameOID


# ------------------------
# Key generation / storage
# ------------------------

def gen_rsa_keypair(priv_pem_path: str, pub_pem_path: str, password: Optional[str] = None, bits: int = 2048):
    """RSA keypair; private in PKCS8/PEM with password; public in SubjectPublicKeyInfo PEM."""
    sk = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    pk = sk.public_key()

    enc = BestAvailableEncryption(password.encode()) if password else NoEncryption()
    priv_pem = sk.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, enc)
    pub_pem  = pk.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)

    pathlib.Path(priv_pem_path).write_bytes(priv_pem)
    pathlib.Path(pub_pem_path).write_bytes(pub_pem)


def gen_ed25519_keypair(priv_pem_path: str, pub_pem_path: str, password: Optional[str] = None):
    """Ed25519 keypair; private in PKCS8/PEM with password; public in SubjectPublicKeyInfo PEM."""
    sk = ed25519.Ed25519PrivateKey.generate()
    pk = sk.public_key()

    enc = BestAvailableEncryption(password.encode()) if password else NoEncryption()
    priv_pem = sk.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, enc)
    pub_pem  = pk.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)

    pathlib.Path(priv_pem_path).write_bytes(priv_pem)
    pathlib.Path(pub_pem_path).write_bytes(pub_pem)


# -------------
# Sign / Verify
# -------------

def rsa_sign_bytes(priv_pem_path: str, password: Optional[str], msg: bytes) -> bytes:
    sk = load_pem_private_key(pathlib.Path(priv_pem_path).read_bytes(), password=password.encode() if password else None)
    if not isinstance(sk, rsa.RSAPrivateKey):
        raise ValueError("Not an RSA private key")
    # RSA-PSS with MGF1(SHA256) and PSS.MAX_LENGTH (per assignment)
    return sk.sign(
        msg,
        asym_padding.PSS(mgf=asym_padding.MGF1(hashes.SHA256()), salt_length=asym_padding.PSS.MAX_LENGTH),
        hashes.SHA256()
    )


def rsa_verify_bytes(pub_or_cert_pem_path: str, msg: bytes, sig: bytes) -> bool:
    data = pathlib.Path(pub_or_cert_pem_path).read_bytes()
    try:
        # Try public key
        pk = load_pem_public_key(data)
    except ValueError:
        # Try certificate
        cert = x509.load_pem_x509_certificate(data)
        pk = cert.public_key()
    if not hasattr(pk, "verify"):
        return False
    try:
        pk.verify(
            sig, msg,
            asym_padding.PSS(mgf=asym_padding.MGF1(hashes.SHA256()), salt_length=asym_padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False


def ed25519_sign_bytes(priv_pem_path: str, password: Optional[str], msg: bytes) -> bytes:
    sk = load_pem_private_key(pathlib.Path(priv_pem_path).read_bytes(), password=password.encode() if password else None)
    if not isinstance(sk, ed25519.Ed25519PrivateKey):
        raise ValueError("Not an Ed25519 private key")
    return sk.sign(msg)


def ed25519_verify_bytes(pub_or_cert_pem_path: str, msg: bytes, sig: bytes) -> bool:
    data = pathlib.Path(pub_or_cert_pem_path).read_bytes()
    try:
        pk = load_pem_public_key(data)
    except ValueError:
        cert = x509.load_pem_x509_certificate(data)
        pk = cert.public_key()
    if not isinstance(pk, ed25519.Ed25519PublicKey):
        return False
    try:
        pk.verify(sig, msg)
        return True
    except Exception:
        return False


# -----------------------------
# Self-signed X.509 certificate
# -----------------------------

def self_signed_cert(
    subject_common_name: str,
    priv_pem_path: str,
    password: Optional[str],
    cert_out_path: str,
    days_valid: int = 365
):
    """Create a self-signed certificate (works with RSA or Ed25519 private keys)."""
    key = load_pem_private_key(pathlib.Path(priv_pem_path).read_bytes(), password=password.encode() if password else None)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject_common_name)])

    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow() - datetime.timedelta(minutes=1))
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=days_valid))
    )
    cert = builder.sign(private_key=key, algorithm=hashes.SHA256() if isinstance(key, rsa.RSAPrivateKey) else None)
    pathlib.Path(cert_out_path).write_bytes(cert.public_bytes(Encoding.PEM))


# ----------------------------
# Root CA & issued user certs
# ----------------------------

def gen_root_ca(
    ca_priv_pem_path: str,
    ca_cert_pem_path: str,
    password: Optional[str],
    bits: int = 3072,
    days_valid: int = 3650,
    common_name: str = "RootCA"
):
    """
    Generate a Root CA:
      - RSA private key (encrypted with password)
      - Self-signed X.509 certificate marked as CA.
    """
    sk = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    enc = BestAvailableEncryption(password.encode()) if password else NoEncryption()
    priv_pem = sk.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, enc)
    pathlib.Path(ca_priv_pem_path).write_bytes(priv_pem)

    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(sk.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow() - datetime.timedelta(minutes=1))
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=days_valid))
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=0),
            critical=True
        )
    )
    cert = builder.sign(private_key=sk, algorithm=hashes.SHA256())
    pathlib.Path(ca_cert_pem_path).write_bytes(cert.public_bytes(Encoding.PEM))


def issue_cert_for_pubkey(
    subject_common_name: str,
    subject_pub_pem_path: str,
    ca_priv_pem_path: str,
    ca_password: Optional[str],
    ca_cert_pem_path: str,
    cert_out_path: str,
    days_valid: int = 365
):
    """
    Issue an end-entity certificate for a user's public key, signed by the Root CA.
    """
    ca_sk = load_pem_private_key(
        pathlib.Path(ca_priv_pem_path).read_bytes(),
        password=ca_password.encode() if ca_password else None
    )
    ca_cert = x509.load_pem_x509_certificate(pathlib.Path(ca_cert_pem_path).read_bytes())
    subject_pk = load_pem_public_key(pathlib.Path(subject_pub_pem_path).read_bytes())

    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject_common_name)])
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(subject_pk)
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow() - datetime.timedelta(minutes=1))
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=days_valid))
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True
        )
    )

    algorithm = hashes.SHA256() if isinstance(ca_sk, rsa.RSAPrivateKey) else None
    cert = builder.sign(private_key=ca_sk, algorithm=algorithm)
    pathlib.Path(cert_out_path).write_bytes(cert.public_bytes(Encoding.PEM))


# ---------------------
# CSR (for OpenSSL CA)
# ---------------------

def make_csr(
    subject_common_name: str,
    priv_pem_path: str,
    password: Optional[str],
    csr_out_path: str
):
    """Build a CSR in PEM to be signed by your OpenSSL demo CA."""
    key = load_pem_private_key(pathlib.Path(priv_pem_path).read_bytes(), password=password.encode() if password else None)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject_common_name)])
    csr = x509.CertificateSigningRequestBuilder().subject_name(subject).sign(
        key,
        hashes.SHA256() if isinstance(key, rsa.RSAPrivateKey) else None
    )
    pathlib.Path(csr_out_path).write_bytes(csr.public_bytes(Encoding.PEM))


# ------------------------------------------------
# Certificate verification (issuer → subject cert)
# ------------------------------------------------

def verify_cert_signed_by(cert_pem_path: str, issuer_cert_pem_path: str) -> bool:
    """Verify 'cert' is signed by 'issuer_cert' (signature & algorithm)."""
    cert   = x509.load_pem_x509_certificate(pathlib.Path(cert_pem_path).read_bytes())
    issuer = x509.load_pem_x509_certificate(pathlib.Path(issuer_cert_pem_path).read_bytes())
    issuer_pk = issuer.public_key()

    try:
        if isinstance(issuer_pk, rsa.RSAPublicKey):
            # X.509 certs typically use PKCS1v15 for RSA signatures
            issuer_pk.verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                asym_padding.PKCS1v15(),
                cert.signature_hash_algorithm
            )
            return True
        elif isinstance(issuer_pk, ed25519.Ed25519PublicKey):
            issuer_pk.verify(cert.signature, cert.tbs_certificate_bytes)
            return True
        else:
            return False
    except Exception:
        return False


def verify_chain(leaf_cert_pem_path: str, ca_cert_pem_path: str) -> bool:
    """Simple 1-link chain: leaf ← CA (self-signed CA)."""
    # Verify CA is self-signed:
    if not verify_cert_signed_by(ca_cert_pem_path, ca_cert_pem_path):
        return False
    # Verify leaf by CA:
    return verify_cert_signed_by(leaf_cert_pem_path, ca_cert_pem_path)
