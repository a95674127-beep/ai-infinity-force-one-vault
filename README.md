# AI Infinity Force One — Vault Core

A small zero-trust vault core in Rust: three independent pieces wired
together so no secret can be read or written without an authorization
check, and every check — allowed or denied — is logged in a tamper-evident
chain.

## Pieces

- **`vault::crypto`** — envelope encryption. A passphrase is stretched into
  a key with Argon2id (memory-hard, so a stolen blob resists offline
  brute-forcing), then used once with XChaCha20-Poly1305 (authenticated
  encryption — tampering with ciphertext is detected, not silently
  accepted). Each blob carries its own random salt and nonce.
- **`vault::policy`** — deny-by-default access control. A principal can act
  on a resource only if explicitly granted that exact action; there is no
  default-allow path anywhere in this module.
- **`vault::audit`** — a hash-chained log of every access decision. Each
  entry embeds the previous entry's hash, so altering or deleting a past
  entry is detectable via `verify_integrity()`.
- **`Vault`** (in `vault/mod.rs`) — ties the three together: `put_secret`
  and `get_secret` both check policy first and log the outcome before
  touching any ciphertext.

## Try it

```bash
cargo test    # crypto round-trip, policy deny/allow, audit tamper detection
cargo run     # demo: alice can read/write, mallory is denied and logged
