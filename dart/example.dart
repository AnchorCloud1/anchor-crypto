// Loads the actual production ac_crypto.dart module and runs the shared
// test-vectors.json against it -- proving this file, not a simplified
// stand-in, produces the expected results.
//
// Run: dart pub get && dart run example.dart
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'ac_crypto.dart';

Uint8List b64d(String s) => base64Decode(s);
String b64e(Uint8List b) => base64Encode(b);

Future<void> main() async {
  final vectors = jsonDecode(
      await File('../test-vectors.json').readAsString()) as Map<String, dynamic>;
  var failures = 0;

  // ---- AES-256-GCM decrypt vector ----
  final v1 = vectors['aes_gcm_decrypt'] as Map<String, dynamic>;
  final plainBytes = await decryptBytes(
    b64d(v1['ciphertext_b64'] as String),
    b64d(v1['key_b64'] as String),
    v1['iv_b64'] as String,
  );
  final plaintext = utf8.decode(plainBytes);
  final ok1 = plaintext == v1['expected_plaintext'];
  print('[${ok1 ? 'PASS' : 'FAIL'}] AES-256-GCM decrypt -> "$plaintext"');
  if (!ok1) failures++;

  // ---- PBKDF2 vector ----
  final v2 = vectors['pbkdf2'] as Map<String, dynamic>;
  final derivedKey = await deriveMasterKeyBytes(
      v2['password'] as String, v2['salt_b64'] as String);
  final ok2 = b64e(derivedKey) == v2['expected_key_b64'];
  print('[${ok2 ? 'PASS' : 'FAIL'}] PBKDF2 (210,000 iterations) master key derivation');
  if (!ok2) failures++;

  // ---- X25519 + HKDF vector ----
  final v3 = vectors['x25519_hkdf'] as Map<String, dynamic>;
  final fileKey = Uint8List.fromList(List.filled(32, 7));
  final wrapped = await wrapFileKeyForRecipient(
    fileKey,
    b64d(v3['alice_private_b64'] as String),
    b64d(v3['alice_public_b64'] as String),
    b64d(v3['bob_public_b64'] as String),
  );
  final unwrapped = await unwrapFileKeyFromSender(
    wrapped.wrappedB64,
    wrapped.ivB64,
    b64d(v3['bob_private_b64'] as String),
    b64d(v3['bob_public_b64'] as String),
    b64d(v3['alice_public_b64'] as String),
  );
  final ok3 = b64e(unwrapped) == b64e(fileKey);
  print('[${ok3 ? 'PASS' : 'FAIL'}] X25519 + HKDF sharing round-trip (Alice -> Bob)');
  if (!ok3) failures++;

  exit(failures > 0 ? 1 : 0);
}
