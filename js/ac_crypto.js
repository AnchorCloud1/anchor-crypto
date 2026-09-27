// ============================================================
// ZERO-KNOWLEDGE CRYPTO — browser (Web Crypto API)
// This is the exact module used in production by Anchor Cloud's web
// dashboard. It is extracted here verbatim so anyone can read, run, and
// verify how file encryption actually works — no server code, no secrets,
// nothing removed.
//
// Design in one paragraph: your account password + a server-issued
// (non-secret) salt are run through PBKDF2 to derive a 256-bit master key
// that never leaves your device. Each file gets its own random AES-256-GCM
// key, which encrypts the file, and is itself "wrapped" (encrypted) under
// your master key before being sent to the server. The server only ever
// stores ciphertext and wrapped keys — it has no key that can decrypt
// either. Sharing a file with another account re-wraps that file's key
// under a key derived from an X25519 Diffie-Hellman exchange between the
// two accounts, so the server is never in possession of a usable key even
// during a share.
// ============================================================

const AC_CRYPTO = (function () {
  const PBKDF2_ITERATIONS = 210000;

  function b64encode(bytes) {
    let binary = '';
    const arr = new Uint8Array(bytes);
    for (let i = 0; i < arr.length; i++) binary += String.fromCharCode(arr[i]);
    return btoa(binary);
  }
  function b64decode(b64) {
    const binary = atob(b64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    return bytes;
  }

  // Derives this account's 256-bit master key from the password + the
  // server-issued (non-secret) PBKDF2 salt. Never sent to or computed by
  // the server — this happens entirely in the browser.
  async function deriveMasterKeyBits(password, saltB64) {
    const enc = new TextEncoder();
    const baseKey = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveBits']);
    const bits = await crypto.subtle.deriveBits(
      { name: 'PBKDF2', salt: b64decode(saltB64), iterations: PBKDF2_ITERATIONS, hash: 'SHA-256' },
      baseKey,
      256
    );
    return new Uint8Array(bits);
  }

  async function importAesKey(rawBytes) {
    return crypto.subtle.importKey('raw', rawBytes, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
  }

  function generateFileKeyBytes() {
    return crypto.getRandomValues(new Uint8Array(32));
  }

  async function encryptFile(fileArrayBuffer, fileKeyBytes) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const key = await importAesKey(fileKeyBytes);
    const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, fileArrayBuffer);
    return { ciphertext, ivB64: b64encode(iv) };
  }

  async function decryptFile(ciphertextArrayBuffer, fileKeyBytes, ivB64) {
    const key = await importAesKey(fileKeyBytes);
    return crypto.subtle.decrypt({ name: 'AES-GCM', iv: b64decode(ivB64) }, key, ciphertextArrayBuffer);
  }

  async function wrapFileKey(fileKeyBytes, masterKeyBytes) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const key = await importAesKey(masterKeyBytes);
    const wrapped = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, fileKeyBytes);
    return { wrappedB64: b64encode(wrapped), ivB64: b64encode(iv) };
  }

  async function unwrapFileKey(wrappedB64, ivB64, masterKeyBytes) {
    const key = await importAesKey(masterKeyBytes);
    const raw = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: b64decode(ivB64) }, key, b64decode(wrappedB64));
    return new Uint8Array(raw);
  }

  // ============================================================
  // CROSS-ACCOUNT SHARING (X25519 + HKDF)
  // Mirrors the mobile app's ac_crypto.dart byte-for-byte: raw 32-byte
  // X25519 keys, HKDF-SHA256 with an empty salt and a fixed info string,
  // AES-256-GCM for the actual wrap (reuses wrapFileKey/unwrapFileKey
  // above, which are generic AES-GCM wrap/unwrap under any 32-byte key).
  // WebCrypto's X25519 only accepts raw bytes for public keys via
  // importKey('raw', ...) -- for private keys the raw 32-byte scalar has
  // to go in as a JWK's "d" field instead, since 'raw'/'pkcs8' aren't
  // spec'd for private key import. That's just an import-format detail;
  // the underlying bytes are the same raw scalar the app stores directly.
  // ============================================================
  const SHARING_HKDF_INFO = 'anchorcloud-file-share-v1';

  function b64urlEncode(bytes) {
    return b64encode(bytes).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }
  function b64urlDecode(b64url) {
    const padded = b64url.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((b64url.length + 3) % 4);
    return b64decode(padded);
  }

  async function importX25519PrivateKey(privateKeyBytes, publicKeyBytes) {
    const jwk = {
      kty: 'OKP', crv: 'X25519',
      d: b64urlEncode(privateKeyBytes),
      x: b64urlEncode(publicKeyBytes),
    };
    return crypto.subtle.importKey('jwk', jwk, { name: 'X25519' }, false, ['deriveBits']);
  }
  async function importX25519PublicKey(publicKeyBytes) {
    return crypto.subtle.importKey('raw', publicKeyBytes, { name: 'X25519' }, false, []);
  }

  async function generateSharingKeyPair() {
    const keyPair = await crypto.subtle.generateKey({ name: 'X25519' }, true, ['deriveBits']);
    const publicKeyBytes = new Uint8Array(await crypto.subtle.exportKey('raw', keyPair.publicKey));
    const jwk = await crypto.subtle.exportKey('jwk', keyPair.privateKey);
    const privateKeyBytes = b64urlDecode(jwk.d);
    return { publicKeyBytes, privateKeyBytes };
  }

  // Reuse the generic AES-GCM wrap/unwrap for the private key too -- same
  // op as wrapFileKey/unwrapFileKey, just wrapping a keypair's private
  // scalar under the master key instead of a file key.
  const wrapSharingPrivateKey = wrapFileKey;
  const unwrapSharingPrivateKey = unwrapFileKey;

  // Derives the AES key both sides of a share independently arrive at:
  // ECDH(myPrivateKey, theirPublicKey) -> HKDF-SHA256 -> 32-byte AES key.
  async function deriveSharingAesKey(myPrivateKeyBytes, myPublicKeyBytes, theirPublicKeyBytes) {
    const myPrivateKey = await importX25519PrivateKey(myPrivateKeyBytes, myPublicKeyBytes);
    const theirPublicKey = await importX25519PublicKey(theirPublicKeyBytes);
    const sharedSecretBits = await crypto.subtle.deriveBits({ name: 'X25519', public: theirPublicKey }, myPrivateKey, 256);
    const hkdfKey = await crypto.subtle.importKey('raw', sharedSecretBits, 'HKDF', false, ['deriveBits']);
    const derivedBits = await crypto.subtle.deriveBits(
      { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0), info: new TextEncoder().encode(SHARING_HKDF_INFO) },
      hkdfKey, 256
    );
    return new Uint8Array(derivedBits);
  }

  // SENDER side: re-wraps a raw file key for a specific recipient.
  async function wrapFileKeyForRecipient(fileKeyBytes, myPrivateKeyBytes, myPublicKeyBytes, recipientPublicKeyBytes) {
    const aesKey = await deriveSharingAesKey(myPrivateKeyBytes, myPublicKeyBytes, recipientPublicKeyBytes);
    return wrapFileKey(fileKeyBytes, aesKey);
  }

  // RECIPIENT side: unwraps a file key that was wrapped for us specifically.
  async function unwrapFileKeyFromSender(wrappedB64, wrapIvB64, myPrivateKeyBytes, myPublicKeyBytes, senderPublicKeyBytes) {
    const aesKey = await deriveSharingAesKey(myPrivateKeyBytes, myPublicKeyBytes, senderPublicKeyBytes);
    return unwrapFileKey(wrappedB64, wrapIvB64, aesKey);
  }

  return {
    deriveMasterKeyBits, generateFileKeyBytes, encryptFile, decryptFile, wrapFileKey, unwrapFileKey, b64encode, b64decode,
    generateSharingKeyPair, wrapSharingPrivateKey, unwrapSharingPrivateKey,
    wrapFileKeyForRecipient, unwrapFileKeyFromSender,
  };
})();

if (typeof module !== 'undefined' && module.exports) {
  module.exports = AC_CRYPTO;
}
