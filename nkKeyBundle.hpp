/*
 * Copyright (c) 2024-2026 Naohiro KORIYAMA <nkoriyama@gmail.com>
 *
 * This file is part of nkCryptoTool.
 */

// NKKB "KeyBundle": a self-signed unit binding a set of encryption public keys
// to an ML-DSA-65 identity. Normative wire format: nkCryptoTool-rust
// src/keybundle.rs (SPEC §5/§6). This C++ port interoperates byte-for-byte with
// the Rust implementation (verified live).
//
//   body = "NKKB" | u8 version(1) | LP(owner_pk_raw) | LP(handle)
//          | u64_be(created_at) | u16_le(n) | entry*n
//   entry = u8(key_usage) | LP(target_pk) | u64_be(created_at)
//           | u8(has_expiry) [| u64_be(expires_at)] | LP(keybind_sig)
//   file = body | LP(self_sig)
//
//   keybind blob (signed under ctx "nkct-keybind-v1"):
//     LP(owner_pk) | u8(key_usage) | LP(target_pk) | LP(handle)
//     | u64_be(created_at) | u8(has_expiry) [| u64_be(expires_at)]
//   self-signature is over the body bytes under ctx "nkct-bundle-v1".
//
//   owner fingerprint = SHA3-256(owner_pk_raw).
//   key_usage: 0x01 = ML-KEM encryption key (raw ek), 0x02 = P-256 hybrid (SPKI DER).
//   identity DSA is always ML-DSA-65.

#ifndef NK_KEYBUNDLE_HPP
#define NK_KEYBUNDLE_HPP

#include <array>
#include <cstdint>
#include <expected>
#include <optional>
#include <string>
#include <vector>
#include "CryptoError.hpp"
#include "SecureMemory.hpp"

namespace nk::keybundle {

inline constexpr uint8_t KEY_USAGE_ENC = 0x01;    // ML-KEM ek (raw)
inline constexpr uint8_t KEY_USAGE_HYBRID = 0x02; // P-256 SPKI DER
inline constexpr const char* IDENTITY_DSA = "ML-DSA-65";

struct BoundKey {
    uint8_t key_usage = 0;
    std::vector<uint8_t> target_pk;
    uint64_t created_at = 0;
    std::optional<uint64_t> expires_at;
    std::vector<uint8_t> keybind_sig;
};

struct VerifiedKeyBundle {
    std::vector<uint8_t> owner_pk; // raw ML-DSA-65 public key
    std::string handle;
    uint64_t created_at = 0;
    std::vector<BoundKey> keys;
};

// One (usage, target_pk, created_at, expires_at) to bind.
struct KeyToBind {
    uint8_t key_usage;
    std::vector<uint8_t> target_pk;
    uint64_t created_at;
    std::optional<uint64_t> expires_at;
};

// Build a signed KeyBundle. `owner_priv_der` is the ML-DSA-65 signing key
// (PKCS#8 DER); `owner_pk_raw` is its raw public key (SHA3-256 of which is the
// pinned fingerprint). Returns the full serialized bundle.
std::expected<std::vector<uint8_t>, CryptoError> buildSigned(
    const std::vector<uint8_t>& owner_priv_der,
    const std::vector<uint8_t>& owner_pk_raw, const std::string& handle,
    uint64_t created_at, const std::vector<KeyToBind>& keys,
    const SecureString& passphrase);

// Parse and fully verify a bundle against a pinned owner fingerprint
// (SHA3-256(owner_pk_raw), obtained out-of-band). Expiry is authenticated but
// NOT enforced here — the caller compares expires_at to its clock.
std::expected<VerifiedKeyBundle, CryptoError> parseAndVerify(
    const std::vector<uint8_t>& bytes,
    const std::array<uint8_t, 32>& pinned_fingerprint);

// SHA3-256(owner_pk_raw) as 64-hex, for printing the fingerprint to share.
std::expected<std::string, CryptoError> ownerFingerprintHex(
    const std::vector<uint8_t>& owner_pk_raw);

} // namespace nk::keybundle

#endif // NK_KEYBUNDLE_HPP
