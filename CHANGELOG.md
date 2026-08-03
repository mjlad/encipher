# Changelog

All notable changes to this crate are documented here. Format loosely
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [2.0.0]

A complete, from-scratch rewrite. The previous design used a custom
substitution cipher with rotating lookup tables and HMAC-SHA256 for
integrity. As the crate's audience grew, we wanted every part of the
cryptographic core to be a standard, independently-audited construction
rather than a bespoke one — so 2.0 replaces that design entirely with
AES-256-GCM and XChaCha20-Poly1305, both via the well-established
[RustCrypto](https://github.com/RustCrypto) implementations. This
crate's contribution is now, deliberately, the ergonomic layer around a
proven primitive, not the primitive itself.

This is a clean break, not an incremental update — the token format,
public API, and error types are all new.

### Added
- `Backend::Aes256Gcm` and `Backend::XChaCha20Poly1305`, both standard
  AEAD constructions with independent key derivation (domain-separated,
  so the same master key never produces the same derived key twice).
- Purpose binding: every token states what it's for (`"session"` by
  default), authenticated as part of the token itself.
  `decrypt`/`decrypt_at` only accept the default purpose;
  `decrypt_for`/`decrypt_for_at` read a token minted for any other one.
  A token minted for one purpose can never be mistaken for another, even
  under the same key.
- Optional expiry (`expires_at`), checked only after full AEAD
  authentication has already succeeded.
- Explicit size limits on both plaintext and the token itself, checked
  before any decoding work is done on untrusted input.
- `encrypt_into` / `encrypt_into_with_scratch`: allocation-free variants
  for callers minting many tokens per second.
- A `fuzz/` suite (via `cargo-fuzz`) covering both the token decryption
  path and the token-context parser directly.

### Changed
- `Encipher::new`'s third parameter is now `Backend` instead of a `step:
  u8` substitution offset.
- `key` is still a `u128`, but is now widened per-backend via SHA-256
  purely as a formatting step — the entropy of the derived key is still
  bounded by the entropy of `key` itself, so it must be a genuinely
  random value, never a memorable or predictable number. This was true
  before too; it's called out explicitly now.
- `key` and `key_env` are mutually exclusive — providing both is now a
  reported error (`ConflictingKeySources`) instead of silently
  preferring one.
- `encrypt` takes two new parameters, `expires_at: Option<u64>` and
  `purpose: Option<&str>`, and now returns `Result<String, EncipherError>`
  instead of an infallible `String` (an oversized plaintext is a normal,
  recoverable condition, not a reason to panic).

### Removed
- The rotating-substitution-table cipher and its `step` parameter.
- HMAC-based signing — AEAD's own authentication tag replaces it, so
  there's no separate signature segment in the token anymore.
- `Backend::Auto` was never released, so there's nothing to note here
  beyond: if you're choosing a backend, pick one explicitly and keep it
  consistent across every machine that needs to read the same tokens.

### Upgrading from 0.x
Tokens minted by any 0.x release cannot be read by 2.0, and vice versa —
the two use unrelated cryptographic constructions, not just a different
token format. There's no compatibility shim, by design: a "read either
format" mode would mean keeping the old design's code paths alive
indefinitely, which defeats the point of retiring them.

In practice, this only matters for tokens with a lifetime that could
still be active at your deployment moment. Session tokens are typically
short-lived enough that this is a non-issue — old tokens simply expire
on their own within their normal window, and every token minted after
upgrading is a 2.0 token from the start. If you mint anything long-lived
(password-reset links, "remember me" tokens with a long expiry), plan
for those to be invalidated by the upgrade rather than silently
translated.

## [0.1.3] and earlier

Initial design: a rotating substitution cipher (100 lookup tables seeded
from the key, indexed by a per-message random starting offset) with a
separate HMAC-SHA256 signature for integrity. Superseded entirely by
2.0 — see above.
