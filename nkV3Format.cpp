/*
 * Copyright (c) 2024-2026 Naohiro KORIYAMA <nkoriyama@gmail.com>
 *
 * This file is part of nkCryptoTool.
 */

#include "nkV3Format.hpp"
#include "backend/IBackend.hpp"
#include <cstdlib>
#include <cstring>

std::shared_ptr<nk::backend::ICryptoBackend> get_nk_backend();

namespace nk::v3 {

uint32_t chunkSizeFromEnv() {
    if (const char* env = std::getenv("NKCT_V3_CHUNK_SIZE")) {
        char* end = nullptr;
        unsigned long v = std::strtoul(env, &end, 10);
        if (end && *end == '\0' && v > 0 && v <= 64ul * 1024 * 1024) {
            return (uint32_t)v;
        }
    }
    return DEFAULT_CHUNK_SIZE;
}

std::expected<std::array<uint8_t, SESSION_ID_LEN>, CryptoError>
sessionId(const std::vector<char>& header_bytes) {
    auto digest = ::get_nk_backend()->sha256(
        reinterpret_cast<const uint8_t*>(header_bytes.data()), header_bytes.size());
    if (!digest) return std::unexpected(digest.error());
    std::array<uint8_t, SESSION_ID_LEN> sid{};
    std::memcpy(sid.data(), digest->data(), SESSION_ID_LEN);
    return sid;
}

std::array<uint8_t, NONCE_LEN> buildNonce(const std::vector<unsigned char>& prefix,
                                          uint32_t counter) {
    std::array<uint8_t, NONCE_LEN> nonce{};
    std::memcpy(nonce.data(), prefix.data(), NONCE_PREFIX_LEN);
    // Counter is big-endian (matches the Rust implementation).
    nonce[NONCE_PREFIX_LEN + 0] = (uint8_t)(counter >> 24);
    nonce[NONCE_PREFIX_LEN + 1] = (uint8_t)(counter >> 16);
    nonce[NONCE_PREFIX_LEN + 2] = (uint8_t)(counter >> 8);
    nonce[NONCE_PREFIX_LEN + 3] = (uint8_t)(counter);
    return nonce;
}

std::vector<uint8_t> buildAad(const std::array<uint8_t, SESSION_ID_LEN>& sid,
                              uint32_t counter, uint8_t flags) {
    std::vector<uint8_t> aad;
    aad.reserve(SESSION_ID_LEN + COUNTER_LEN + 1);
    aad.insert(aad.end(), sid.begin(), sid.end());
    aad.push_back((uint8_t)(counter >> 24));
    aad.push_back((uint8_t)(counter >> 16));
    aad.push_back((uint8_t)(counter >> 8));
    aad.push_back((uint8_t)(counter));
    aad.push_back(flags);
    return aad;
}

std::expected<std::vector<char>, CryptoError> sealChunk(
    const std::string& aead_algo, const std::vector<unsigned char>& key,
    const std::vector<unsigned char>& nonce_prefix,
    const std::array<uint8_t, SESSION_ID_LEN>& sid, uint32_t counter,
    const char* plaintext, size_t plaintext_len, bool is_final) {
    if (nonce_prefix.size() != NONCE_PREFIX_LEN)
        return std::unexpected(CryptoError::ParameterError);

    auto nonce = buildNonce(nonce_prefix, counter);
    auto aad = buildAad(sid, counter, is_final ? FLAG_FINAL : FLAG_INTERMEDIATE);

    auto backend = ::get_nk_backend();
    std::vector<uint8_t> nonce_v(nonce.begin(), nonce.end());
    auto aead = backend->createAead(aead_algo, key, nonce_v, true);
    if (!aead) return std::unexpected(aead.error());

    if (auto r = (*aead)->setAad(aad.data(), aad.size()); !r)
        return std::unexpected(r.error());

    std::vector<char> out(plaintext_len + TAG_LEN + 16);
    size_t written = 0;
    auto up = (*aead)->update(reinterpret_cast<const uint8_t*>(plaintext),
                              plaintext_len,
                              reinterpret_cast<uint8_t*>(out.data()));
    if (!up) return std::unexpected(up.error());
    written += *up;
    auto fin = (*aead)->finalize(reinterpret_cast<uint8_t*>(out.data()) + written);
    if (!fin) return std::unexpected(fin.error());
    written += *fin;

    uint8_t tag[TAG_LEN];
    if (auto t = (*aead)->getTag(tag, TAG_LEN); !t) return std::unexpected(t.error());
    out.resize(written);
    out.insert(out.end(), tag, tag + TAG_LEN);
    return out;
}

std::expected<std::vector<char>, CryptoError> openChunk(
    const std::string& aead_algo, const std::vector<unsigned char>& key,
    const std::vector<unsigned char>& nonce_prefix,
    const std::array<uint8_t, SESSION_ID_LEN>& sid, uint32_t counter,
    const char* ct_and_tag, size_t ct_and_tag_len, bool is_final) {
    if (nonce_prefix.size() != NONCE_PREFIX_LEN || ct_and_tag_len < TAG_LEN)
        return std::unexpected(CryptoError::ParameterError);

    const size_t ct_len = ct_and_tag_len - TAG_LEN;
    auto nonce = buildNonce(nonce_prefix, counter);
    auto aad = buildAad(sid, counter, is_final ? FLAG_FINAL : FLAG_INTERMEDIATE);

    auto backend = ::get_nk_backend();
    std::vector<uint8_t> nonce_v(nonce.begin(), nonce.end());
    auto aead = backend->createAead(aead_algo, key, nonce_v, false);
    if (!aead) return std::unexpected(aead.error());

    if (auto r = (*aead)->setAad(aad.data(), aad.size()); !r)
        return std::unexpected(r.error());

    std::vector<char> out(ct_len + 16);
    size_t written = 0;
    auto up = (*aead)->update(reinterpret_cast<const uint8_t*>(ct_and_tag), ct_len,
                              reinterpret_cast<uint8_t*>(out.data()));
    if (!up) return std::unexpected(up.error());
    written += *up;

    if (auto t = (*aead)->setTag(
            reinterpret_cast<const uint8_t*>(ct_and_tag) + ct_len, TAG_LEN);
        !t)
        return std::unexpected(t.error());

    auto fin = (*aead)->finalize(reinterpret_cast<uint8_t*>(out.data()) + written);
    if (!fin) return std::unexpected(CryptoError::SignatureVerificationError);
    written += *fin;
    out.resize(written);
    return out;
}

} // namespace nk::v3
