/*
 * Copyright (c) 2024-2026 Naohiro KORIYAMA <nkoriyama@gmail.com>
 *
 * This file is part of nkCryptoTool.
 */

// NKCT v3 "ChunkedAead" container helpers.
//
// The wire format is normatively specified by the Rust implementation
// (nkCryptoTool-rust SPEC.md §16). Summary:
//   header  = the v2 header skeleton with version word 3 and a trailing
//             uint32 LE chunk_size
//   body    = concatenation of independently authenticated chunks
//             (ciphertext || 16-byte tag); every chunk is exactly
//             chunk_size+16 bytes on the wire except the final one
//   keys    = HKDF-SHA3-256(ikm = shared secret, salt = header salt)
//             info "nkct-v3-enc-key"      -> 32-byte AEAD key
//             info "nkct-v3-nonce-prefix" ->  8-byte nonce prefix
//   nonce   = nonce_prefix(8) || chunk counter (uint32 BE), counter from 0
//   AAD     = SID(16) || counter (uint32 BE) || flags(1)
//   SID     = SHA-256(serialized header bytes)[..16]
//   flags   = 0x00 intermediate, 0x01 final (marks the last chunk; a file
//             truncated at a chunk boundary therefore fails authentication)

#ifndef NK_V3_FORMAT_HPP
#define NK_V3_FORMAT_HPP

#include <array>
#include <cstdint>
#include <expected>
#include <string>
#include <vector>
#include "CryptoError.hpp"

namespace nk::v3 {

inline constexpr size_t NONCE_PREFIX_LEN = 8;
inline constexpr size_t COUNTER_LEN = 4;
inline constexpr size_t NONCE_LEN = NONCE_PREFIX_LEN + COUNTER_LEN; // 12
inline constexpr size_t TAG_LEN = 16;
inline constexpr size_t SESSION_ID_LEN = 16;
inline constexpr uint8_t FLAG_INTERMEDIATE = 0x00;
inline constexpr uint8_t FLAG_FINAL = 0x01;
inline constexpr uint32_t DEFAULT_CHUNK_SIZE = 1024 * 1024;

inline constexpr const char* INFO_ENC_KEY = "nkct-v3-enc-key";
inline constexpr const char* INFO_NONCE_PREFIX = "nkct-v3-nonce-prefix";

// NKCT_V3_CHUNK_SIZE env override (tests/interop only), else the default.
uint32_t chunkSizeFromEnv();

// SID = SHA-256(header bytes)[..16].
std::expected<std::array<uint8_t, SESSION_ID_LEN>, CryptoError>
sessionId(const std::vector<char>& header_bytes);

std::array<uint8_t, NONCE_LEN> buildNonce(const std::vector<unsigned char>& prefix,
                                          uint32_t counter);

std::vector<uint8_t> buildAad(const std::array<uint8_t, SESSION_ID_LEN>& sid,
                              uint32_t counter, uint8_t flags);

// Seal one chunk: returns ciphertext || tag. `counter` is the caller-managed
// chunk index (starts at 0, +1 per chunk).
std::expected<std::vector<char>, CryptoError> sealChunk(
    const std::string& aead_algo, const std::vector<unsigned char>& key,
    const std::vector<unsigned char>& nonce_prefix,
    const std::array<uint8_t, SESSION_ID_LEN>& sid, uint32_t counter,
    const char* plaintext, size_t plaintext_len, bool is_final);

// Open one chunk (ciphertext || tag). Fails on any tag/AAD mismatch.
std::expected<std::vector<char>, CryptoError> openChunk(
    const std::string& aead_algo, const std::vector<unsigned char>& key,
    const std::vector<unsigned char>& nonce_prefix,
    const std::array<uint8_t, SESSION_ID_LEN>& sid, uint32_t counter,
    const char* ct_and_tag, size_t ct_and_tag_len, bool is_final);

} // namespace nk::v3

#endif // NK_V3_FORMAT_HPP
