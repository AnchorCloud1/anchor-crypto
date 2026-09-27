// ============================================================
// ZERO-KNOWLEDGE CRYPTO
// Files are encrypted client-side (AES-256-GCM) under a random
// per-file key, which is itself wrapped under this user's master
// key (PBKDF2-derived from their password + server-issued salt,
// which is not secret). The server only ever stores/relays
// ciphertext and wrapped keys — it never has the means to decrypt.
//
// Mirrors the same scheme used by the browser dashboard (acDash).
// ============================================================
import 'dart:convert';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';

const int _pbkdf2Iterations = 210000;

final _pbkdf2 = Pbkdf2(
  macAlgorithm: Hmac.sha256(),
  iterations: _pbkdf2Iterations,
  bits: 256,
);

final _aesGcm = AesGcm.with256bits();

/// Holds the derived master key in memory only, for the lifetime of the
/// running app — never written to SharedPreferences or disk. If the app
/// restarts with a persisted login session, this is null until the user
/// re-enters their password (see the "unlock vault" flow in dashboard.dart).
class VaultSession {
  static Uint8List? masterKeyBytes;

  // This account's own X25519 sharing keypair, unwrapped once per session
  // (same lifetime/never-persisted rule as masterKeyBytes above) — needed
  // for both sides of cross-account file sharing: re-wrapping a file key
  // for a recipient, and unwrapping a file key someone else shared with us.
  static Uint8List? sharingPublicKeyBytes;
  static Uint8List? sharingPrivateKeyBytes;

  static void clear() {
    masterKeyBytes = null;
    sharingPublicKeyBytes = null;
    sharingPrivateKeyBytes = null;
  }
}

/// Derives this user's 256-bit master key from their password + the
/// server-issued (non-secret) PBKDF2 salt.
Future<Uint8List> deriveMasterKeyBytes(String password, String saltB64) async {
  final salt = base64Decode(saltB64);
  final newSecretKey = await _pbkdf2.deriveKeyFromPassword(
    password: password,
    nonce: salt,
  );
  final bytes = await newSecretKey.extractBytes();
  return Uint8List.fromList(bytes);
}

/// Generates a random 256-bit file key.
Future<Uint8List> generateFileKey() async {
  final key = await _aesGcm.newSecretKey();
  final bytes = await key.extractBytes();
  return Uint8List.fromList(bytes);
}

class EncryptedPayload {
  final Uint8List ciphertext; // nonce-less; IV returned separately
  final String ivB64;
  EncryptedPayload(this.ciphertext, this.ivB64);
}

Future<EncryptedPayload> encryptBytes(
    Uint8List plaintext, Uint8List keyBytes) async {
  final secretKey = SecretKey(keyBytes);
  final secretBox = await _aesGcm.encrypt(plaintext, secretKey: secretKey);
  // Pack ciphertext + MAC together (MAC appended), matching how the browser
  // side treats Web Crypto's AES-GCM output as one opaque blob.
  final packed = Uint8List.fromList(
      [...secretBox.cipherText, ...secretBox.mac.bytes]);
  return EncryptedPayload(packed, base64Encode(secretBox.nonce));
}

Future<Uint8List> decryptBytes(
    Uint8List packed, Uint8List keyBytes, String ivB64) async {
  final nonce = base64Decode(ivB64);
  // Last 16 bytes are the GCM MAC (128-bit tag), matching encryptBytes' packing.
  final macBytes = packed.sublist(packed.length - 16);
  final cipherBytes = packed.sublist(0, packed.length - 16);
  final secretBox =
      SecretBox(cipherBytes, nonce: nonce, mac: Mac(macBytes));
  final secretKey = SecretKey(keyBytes);
  final plaintext = await _aesGcm.decrypt(secretBox, secretKey: secretKey);
  return Uint8List.fromList(plaintext);
}

class WrappedKey {
  final String wrappedB64;
  final String ivB64;
  WrappedKey(this.wrappedB64, this.ivB64);
}

Future<WrappedKey> wrapFileKey(
    Uint8List fileKeyBytes, Uint8List masterKeyBytes) async {
  final result = await encryptBytes(fileKeyBytes, masterKeyBytes);
  return WrappedKey(base64Encode(result.ciphertext), result.ivB64);
}

Future<Uint8List> unwrapFileKey(
    String wrappedB64, String wrapIvB64, Uint8List masterKeyBytes) async {
  final packed = base64Decode(wrappedB64);
  return decryptBytes(packed, masterKeyBytes, wrapIvB64);
}

// ============================================================
// CROSS-ACCOUNT SHARING (X25519 + HKDF)
// A file's per-file key is normally only ever wrapped under its owner's
// own master key, which no other account can unwrap. To actually let a
// different account decrypt a shared file, the owner re-wraps the raw
// file key under an AES key derived from an X25519 ECDH exchange between
// the two accounts' long-term keypairs. Mirrors acDash's AC_CRYPTO
// (browser WebCrypto) byte-for-byte: raw 32-byte X25519 keys, HKDF-SHA256
// with an empty salt and a fixed info string, AES-256-GCM for the actual
// wrap (same packed ciphertext+MAC format as wrapFileKey above).
// ============================================================
final _x25519 = X25519();
const _sharingHkdfInfo = 'anchorcloud-file-share-v1';

class SharingKeyPair {
  final Uint8List publicKeyBytes;
  final Uint8List privateKeyBytes;
  SharingKeyPair(this.publicKeyBytes, this.privateKeyBytes);
}

/// Generates a brand-new X25519 keypair. Called once per account, the
/// first time it's needed — the private key is wrapped under the user's
/// master key (see wrapSharingPrivateKey) before ever leaving the device.
Future<SharingKeyPair> generateSharingKeyPair() async {
  final keyPair = await _x25519.newKeyPair();
  final privBytes = await keyPair.extractPrivateKeyBytes();
  final pubKey = await keyPair.extractPublicKey();
  return SharingKeyPair(
      Uint8List.fromList(pubKey.bytes), Uint8List.fromList(privBytes));
}

Future<WrappedKey> wrapSharingPrivateKey(
    Uint8List privateKeyBytes, Uint8List masterKeyBytes) async {
  final result = await encryptBytes(privateKeyBytes, masterKeyBytes);
  return WrappedKey(base64Encode(result.ciphertext), result.ivB64);
}

Future<Uint8List> unwrapSharingPrivateKey(
    String wrappedB64, String wrapIvB64, Uint8List masterKeyBytes) async {
  final packed = base64Decode(wrappedB64);
  return decryptBytes(packed, masterKeyBytes, wrapIvB64);
}

/// Derives the AES key both sides of a share independently arrive at:
/// ECDH(myPrivateKey, theirPublicKey) -> HKDF-SHA256 -> 32-byte AES key.
/// X25519 is commutative, so the sender (their priv + recipient's pub) and
/// the recipient (their priv + sender's pub) always land on the same key.
/// myPublicKeyBytes isn't used in the actual scalar multiplication (ECDH
/// only needs the private scalar + the other side's public point) but is
/// required to build a valid SimpleKeyPairData — pass the caller's own
/// real public key (already known locally / returned by the server),
/// never a placeholder.
Future<Uint8List> deriveSharingAesKey(Uint8List myPrivateKeyBytes,
    Uint8List myPublicKeyBytes, Uint8List theirPublicKeyBytes) async {
  final myKeyPair = SimpleKeyPairData(
    myPrivateKeyBytes,
    publicKey: SimplePublicKey(myPublicKeyBytes, type: KeyPairType.x25519),
    type: KeyPairType.x25519,
  );
  final theirPublicKey =
      SimplePublicKey(theirPublicKeyBytes, type: KeyPairType.x25519);
  final sharedSecret = await _x25519.sharedSecretKey(
      keyPair: myKeyPair, remotePublicKey: theirPublicKey);

  final hkdf = Hkdf(hmac: Hmac.sha256(), outputLength: 32);
  final derivedKey = await hkdf.deriveKey(
    secretKey: sharedSecret,
    nonce: const <int>[],
    info: utf8.encode(_sharingHkdfInfo),
  );
  final bytes = await derivedKey.extractBytes();
  return Uint8List.fromList(bytes);
}

/// Re-wraps a raw file key for a specific recipient, for the SENDER side
/// of a share: fileKeyBytes + ECDH(myPrivateKey, recipientPublicKey).
Future<WrappedKey> wrapFileKeyForRecipient(
    Uint8List fileKeyBytes,
    Uint8List myPrivateKeyBytes,
    Uint8List myPublicKeyBytes,
    Uint8List recipientPublicKeyBytes) async {
  final aesKey = await deriveSharingAesKey(
      myPrivateKeyBytes, myPublicKeyBytes, recipientPublicKeyBytes);
  final result = await encryptBytes(fileKeyBytes, aesKey);
  return WrappedKey(base64Encode(result.ciphertext), result.ivB64);
}

/// Unwraps a file key that was wrapped for us specifically, for the
/// RECIPIENT side: ECDH(myPrivateKey, senderPublicKey) -> unwrap.
Future<Uint8List> unwrapFileKeyFromSender(
    String wrappedB64,
    String wrapIvB64,
    Uint8List myPrivateKeyBytes,
    Uint8List myPublicKeyBytes,
    Uint8List senderPublicKeyBytes) async {
  final aesKey = await deriveSharingAesKey(
      myPrivateKeyBytes, myPublicKeyBytes, senderPublicKeyBytes);
  final packed = base64Decode(wrappedB64);
  return decryptBytes(packed, aesKey, wrapIvB64);
}
