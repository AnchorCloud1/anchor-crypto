# Contributing

This repo exists specifically so the zero-knowledge encryption Anchor Cloud
uses can be independently read and verified. Contributions in that spirit are
welcome:

- **Found a real cryptographic issue** (a weak parameter, an implementation
  bug, a way the client-side design could leak information it shouldn't)?
  Please email **hello@anchortechs.org** with details *before* opening a
  public issue or PR, so it can be fixed first. This is a young, independent
  project — a genuine, responsibly disclosed finding is taken seriously and
  you'll be credited for it.
- **Found a bug in the examples or test vectors** (not the cryptography
  itself — e.g. a typo, a script that doesn't run on your machine)? A normal
  GitHub issue or PR is completely fine for that.
- **Want to add a fourth language implementation** (Rust, Go, Swift, etc.)?
  Open an issue first to discuss — the goal is exact byte-for-byte
  interoperability with the existing three (same PBKDF2 iteration count, same
  AES-GCM nonce size, same HKDF info string), verified against
  `test-vectors.json`, not just "an implementation that also does AES-GCM."

## What won't be accepted here

This repo is intentionally scoped to client-side encryption only. Anchor
Cloud's server, account/auth system, AI, and app UI aren't part of this repo
and PRs touching unrelated functionality won't be merged here.
