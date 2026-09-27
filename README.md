# anchor-crypto

This is the actual, unmodified encryption code used in production by
[Anchor Cloud](https://anchorcloud.org) — the zero-knowledge encrypted file
vault built by [Anchor Technologies](https://anchortechs.org). It's published
here so anyone can read it, run it, and verify the claim for themselves
instead of taking our word for it: **the server that stores your files never
has the ability to decrypt them.**

## Why this exists

If you're going to trust a company with your files, "trust us" shouldn't be
the whole pitch — especially not a small, independent one. This repo is the
part of Anchor Cloud that actually matters for that trust: the code that
decides what leaves your device, and in what form. Everything else (the
server, the database, the UI) only ever sees what this code produces:
ciphertext and wrapped keys, never plaintext, never a usable key.

Three implementations are included, one per client, kept in sync by hand and
tested to interoperate byte-for-byte:
- `js/ac_crypto.js` — the browser dashboard (Web Crypto API)
- `dart/ac_crypto.dart` — the Android/desktop app (`package:cryptography`)
- `python/crypto.py` — the official Python SDK (`cryptography` package)

## How it actually works

1. **Your master key never leaves your device.** When you set your password,
   the browser/app derives a 256-bit key from it using PBKDF2-HMAC-SHA256
   with 210,000 iterations, combined with a random salt the server issues
   (the salt isn't secret — it doesn't need to be, since it can't derive
   your key without your password too). That derived key is never sent
   anywhere.
2. **Every file gets its own random key.** Before upload, a fresh 256-bit
   key is generated just for that file, and the file is encrypted with
   AES-256-GCM under it.
3. **The file's key is then "wrapped"** — itself encrypted, under your
   master key — before it's sent to the server alongside the ciphertext.
4. **The server stores ciphertext and a wrapped key.** It has no key capable
   of unwrapping that file key, so it has no path to the plaintext. Not by
   policy — by what data it actually possesses.
5. **Sharing a file with another account** doesn't mean re-uploading a
   plaintext copy. The two accounts' public keys (X25519) are combined via
   Diffie-Hellman into a shared secret (HKDF-SHA256), and *that* key is used
   to re-wrap the file's key for the recipient specifically. The server
   relays this exchange but never derives the shared secret itself.

This is also the direct answer to the question we kept getting asked: **"how
does the AI manage your files without seeing their content?"** — Fathom-1
(Anchor Cloud's built-in AI) only ever receives file *metadata* (name, size,
MIME type, upload date, and the encrypted content's hash) from the server,
which is all the server itself has. It structurally cannot see what's inside
a file, because nothing in this codebase ever gives it — or the server — a
way to.

## Verifying it yourself

- Read the three files — they're short, commented, and each one names the
  primitives used (PBKDF2, AES-256-GCM, X25519, HKDF) so you can check them
  against the actual specs rather than trusting a description of them.
- Compare the three implementations to each other — they're written to
  produce byte-identical results (same iteration counts, same nonce sizes,
  same key-wrapping format) so a file encrypted on the web dashboard can be
  decrypted by the mobile app and vice versa.
- Open a browser's dev tools while using Anchor Cloud, or point a proxy at
  the mobile app's traffic — you will only ever see ciphertext and wrapped
  keys go over the wire, never a plaintext file or master key.

## What this repo is *not*

This is the client-side encryption logic only — not the server, not the
account/auth system, not the AI, not the rest of the app. Those aren't
published, the same way most companies don't open-source their whole
codebase. What's published is specifically the part where "trust us" would
otherwise be the only option, so it doesn't have to be.

## Reporting an issue

Found a real problem with the cryptography here? Please email
**hello@anchortechs.org** with details before disclosing publicly, so it can
be fixed. This is a young, independent project — a real, responsibly
disclosed finding is taken seriously and credited.
