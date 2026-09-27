// Loads the actual production AC_CRYPTO module and runs the shared
// test-vectors.json against it -- proving this file, not a simplified
// stand-in, produces the expected results.
const fs = require('fs');
const path = require('path');
const AC_CRYPTO = require('./ac_crypto.js');

const vectors = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'test-vectors.json'), 'utf8'));

function b64ToBytes(b64) { return AC_CRYPTO.b64decode(b64); }

async function main() {
  let failures = 0;

  // ---- AES-256-GCM decrypt vector ----
  const v1 = vectors.aes_gcm_decrypt;
  const plainBuf = await AC_CRYPTO.decryptFile(
    b64ToBytes(v1.ciphertext_b64).buffer, b64ToBytes(v1.key_b64), v1.iv_b64
  );
  const plaintext = new TextDecoder().decode(plainBuf);
  const ok1 = plaintext === v1.expected_plaintext;
  console.log(`[${ok1 ? 'PASS' : 'FAIL'}] AES-256-GCM decrypt -> "${plaintext}"`);
  if (!ok1) failures++;

  // ---- PBKDF2 vector ----
  const v2 = vectors.pbkdf2;
  const derivedKey = await AC_CRYPTO.deriveMasterKeyBits(v2.password, v2.salt_b64);
  const ok2 = AC_CRYPTO.b64encode(derivedKey) === v2.expected_key_b64;
  console.log(`[${ok2 ? 'PASS' : 'FAIL'}] PBKDF2 (210,000 iterations) master key derivation`);
  if (!ok2) failures++;

  // ---- X25519 + HKDF vector ----
  const v3 = vectors.x25519_hkdf;
  // deriveSharingAesKey isn't exported directly; wrapFileKeyForRecipient/
  // unwrapFileKeyFromSender both call it internally with the same inputs,
  // so exercise it end-to-end: Alice wraps a known key for Bob, Bob unwraps it.
  const fileKey = new Uint8Array(32).fill(7);
  const wrapped = await AC_CRYPTO.wrapFileKeyForRecipient(
    fileKey, b64ToBytes(v3.alice_private_b64), b64ToBytes(v3.alice_public_b64), b64ToBytes(v3.bob_public_b64)
  );
  const unwrapped = await AC_CRYPTO.unwrapFileKeyFromSender(
    wrapped.wrappedB64, wrapped.ivB64, b64ToBytes(v3.bob_private_b64), b64ToBytes(v3.bob_public_b64), b64ToBytes(v3.alice_public_b64)
  );
  const ok3 = AC_CRYPTO.b64encode(unwrapped) === AC_CRYPTO.b64encode(fileKey);
  console.log(`[${ok3 ? 'PASS' : 'FAIL'}] X25519 + HKDF sharing round-trip (Alice -> Bob)`);
  if (!ok3) failures++;

  process.exit(failures ? 1 : 0);
}

main();
