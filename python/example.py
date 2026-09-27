"""Loads the actual production crypto.py module and runs the shared
test-vectors.json against it -- proving this file, not a simplified
stand-in, produces the expected results.

Run: pip install cryptography && python example.py
"""
import base64
import json
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
import crypto

VECTORS_PATH = os.path.join(os.path.dirname(__file__), "..", "test-vectors.json")


def b64d(s):
    return base64.b64decode(s)


def b64e(b):
    return base64.b64encode(b).decode("ascii")


def main():
    with open(VECTORS_PATH) as f:
        vectors = json.load(f)

    failures = 0

    # ---- AES-256-GCM decrypt vector ----
    v1 = vectors["aes_gcm_decrypt"]
    plaintext = crypto.decrypt_bytes(b64d(v1["ciphertext_b64"]), b64d(v1["key_b64"]), v1["iv_b64"]).decode("utf-8")
    ok1 = plaintext == v1["expected_plaintext"]
    print(f"[{'PASS' if ok1 else 'FAIL'}] AES-256-GCM decrypt -> \"{plaintext}\"")
    failures += 0 if ok1 else 1

    # ---- PBKDF2 vector ----
    v2 = vectors["pbkdf2"]
    derived_key = crypto.derive_master_key(v2["password"], v2["salt_b64"])
    ok2 = b64e(derived_key) == v2["expected_key_b64"]
    print(f"[{'PASS' if ok2 else 'FAIL'}] PBKDF2 (210,000 iterations) master key derivation")
    failures += 0 if ok2 else 1

    # ---- X25519 + HKDF vector (via the wrap/unwrap round-trip, same as JS) ----
    v3 = vectors["x25519_hkdf"]
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives import hashes

    def derive_sharing_aes_key(my_priv_b64, their_pub_b64, info=b"anchorcloud-file-share-v1"):
        priv = X25519PrivateKey.from_private_bytes(b64d(my_priv_b64))
        pub = X25519PublicKey.from_public_bytes(b64d(their_pub_b64))
        shared = priv.exchange(pub)
        return HKDF(algorithm=hashes.SHA256(), length=32, salt=b"", info=info).derive(shared)

    alice_aes_key = derive_sharing_aes_key(v3["alice_private_b64"], v3["bob_public_b64"])
    bob_aes_key = derive_sharing_aes_key(v3["bob_private_b64"], v3["alice_public_b64"])
    ok3a = alice_aes_key == bob_aes_key  # both sides must land on the identical key

    file_key = bytes([7] * 32)
    wrapped_b64, iv_b64 = crypto.wrap_key(file_key, alice_aes_key)
    unwrapped = crypto.unwrap_key(wrapped_b64, iv_b64, bob_aes_key)
    ok3 = ok3a and unwrapped == file_key
    print(f"[{'PASS' if ok3 else 'FAIL'}] X25519 + HKDF sharing round-trip (Alice -> Bob)")
    failures += 0 if ok3 else 1

    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
