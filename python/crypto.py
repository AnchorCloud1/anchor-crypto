# ============================================================
# ZERO-KNOWLEDGE CRYPTO
# Mirrors lib/ac_crypto.dart exactly: AES-256-GCM with the
# ciphertext and 16-byte GCM tag packed together as one blob,
# nonce (IV) carried separately as base64. The server only ever
# stores/relays ciphertext and wrapped keys — it never has the
# means to decrypt.
# ============================================================
import base64
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

PBKDF2_ITERATIONS = 210_000
NONCE_SIZE = 12  # 96-bit GCM nonce, matches the `cryptography` package's AesGcm default


def derive_master_key(password: str, salt_b64: str) -> bytes:
    """Derives the 256-bit master key from the account password + the
    server-issued (non-secret) PBKDF2 salt. Same inputs as the web/app
    login flow produce the same master key."""
    salt = base64.b64decode(salt_b64)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    return kdf.derive(password.encode("utf-8"))


def generate_file_key() -> bytes:
    """Random 256-bit key used to encrypt a single file's contents."""
    return AESGCM.generate_key(bit_length=256)


def encrypt_bytes(plaintext: bytes, key: bytes) -> tuple[bytes, str]:
    """Returns (packed_ciphertext, iv_b64). packed_ciphertext is
    ciphertext + 16-byte GCM tag concatenated, matching the Dart/JS
    clients' packing convention."""
    nonce = os.urandom(NONCE_SIZE)
    packed = AESGCM(key).encrypt(nonce, plaintext, None)
    return packed, base64.b64encode(nonce).decode("ascii")


def decrypt_bytes(packed: bytes, key: bytes, iv_b64: str) -> bytes:
    nonce = base64.b64decode(iv_b64)
    return AESGCM(key).decrypt(nonce, packed, None)


def wrap_key(inner_key: bytes, outer_key: bytes) -> tuple[str, str]:
    """Wraps a key (e.g. a per-file key, or the master key itself) under
    another key. Returns (wrapped_b64, iv_b64)."""
    packed, iv_b64 = encrypt_bytes(inner_key, outer_key)
    return base64.b64encode(packed).decode("ascii"), iv_b64


def unwrap_key(wrapped_b64: str, iv_b64: str, outer_key: bytes) -> bytes:
    packed = base64.b64decode(wrapped_b64)
    return decrypt_bytes(packed, outer_key, iv_b64)
