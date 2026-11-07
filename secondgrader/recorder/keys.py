"""Ed25519 signing key for the recorder.

The private key lives outside every agent clone (default ``keys/sg_ed25519.pem``,
git-ignored). The recorder reads it once and keeps it in memory. Hooks never
read it: they only forward events to the recorder.
"""

from __future__ import annotations

import os
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

DEFAULT_KEY_PATH = "keys/sg_ed25519.pem"


def key_path(path: str | Path | None = None) -> Path:
    return Path(path or os.environ.get("SG_SIGNING_KEY_PATH") or DEFAULT_KEY_PATH)


def load_or_create_key(path: str | Path | None = None) -> Ed25519PrivateKey:
    """Load the PEM private key, creating it (mode 0600) if it does not exist."""
    p = key_path(path)
    if p.exists():
        key = serialization.load_pem_private_key(p.read_bytes(), password=None)
        if not isinstance(key, Ed25519PrivateKey):
            raise ValueError(f"{p}: not an Ed25519 private key")
        return key
    key = Ed25519PrivateKey.generate()
    p.parent.mkdir(parents=True, exist_ok=True)
    pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                            serialization.NoEncryption())
    fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(pem)
    return key


def public_hex(key: Ed25519PrivateKey | Ed25519PublicKey) -> str:
    pub = key.public_key() if isinstance(key, Ed25519PrivateKey) else key
    return pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()


def sign_hex(key: Ed25519PrivateKey, message: str) -> str:
    """Signature (hex) over the UTF-8 bytes of ``message`` (a record hash)."""
    return key.sign(message.encode("utf-8")).hex()


def verify_hex(pubkey_hex: str, message: str, sig_hex: str) -> bool:
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(pubkey_hex)).verify(
            bytes.fromhex(sig_hex), message.encode("utf-8"))
        return True
    except (InvalidSignature, ValueError, TypeError, AttributeError):
        return False
