/*
 * Copyright (c) 2024-2026 Naohiro KORIYAMA <nkoriyama@gmail.com>
 *
 * This file is part of nkCryptoTool.
 */

#include "nkKeyBundle.hpp"
#include "backend/IBackend.hpp"
#include <cstring>

std::shared_ptr<nk::backend::ICryptoBackend> get_nk_backend();

namespace nk::keybundle {

namespace {

constexpr uint8_t BUNDLE_VERSION = 1;
const std::vector<uint8_t> BUNDLE_CTX = {'n','k','c','t','-','b','u','n','d','l','e','-','v','1'};
const std::vector<uint8_t> KEYBIND_CTX = {'n','k','c','t','-','k','e','y','b','i','n','d','-','v','1'};
constexpr size_t MAX_BUNDLE_KEYS = 64;
constexpr size_t MAX_FIELD_LEN = 64 * 1024;

void putLp(std::vector<uint8_t>& buf, const uint8_t* b, size_t len) {
    uint32_t l = (uint32_t)len; // caller bounds-checks against MAX_FIELD_LEN
    buf.push_back((uint8_t)(l & 0xff));
    buf.push_back((uint8_t)((l >> 8) & 0xff));
    buf.push_back((uint8_t)((l >> 16) & 0xff));
    buf.push_back((uint8_t)((l >> 24) & 0xff));
    buf.insert(buf.end(), b, b + len);
}
void putLp(std::vector<uint8_t>& buf, const std::vector<uint8_t>& v) { putLp(buf, v.data(), v.size()); }
void putLpStr(std::vector<uint8_t>& buf, const std::string& s) {
    putLp(buf, reinterpret_cast<const uint8_t*>(s.data()), s.size());
}
void putU64Be(std::vector<uint8_t>& buf, uint64_t v) {
    for (int i = 7; i >= 0; --i) buf.push_back((uint8_t)((v >> (i * 8)) & 0xff));
}

// bounds-checked LP read; never over-reads.
std::expected<std::vector<uint8_t>, CryptoError> readLp(const std::vector<uint8_t>& buf, size_t& off) {
    if (buf.size() < off + 4) return std::unexpected(CryptoError::WireFormatError);
    uint32_t len = (uint32_t)buf[off] | ((uint32_t)buf[off+1] << 8) |
                   ((uint32_t)buf[off+2] << 16) | ((uint32_t)buf[off+3] << 24);
    off += 4;
    if (buf.size() < off + len) return std::unexpected(CryptoError::WireFormatError);
    std::vector<uint8_t> v(buf.begin() + off, buf.begin() + off + len);
    off += len;
    return v;
}
std::expected<uint64_t, CryptoError> readU64Be(const std::vector<uint8_t>& buf, size_t& off) {
    if (buf.size() < off + 8) return std::unexpected(CryptoError::WireFormatError);
    uint64_t v = 0;
    for (int i = 0; i < 8; ++i) v = (v << 8) | buf[off + i];
    off += 8;
    return v;
}

// The exact bytes a keybind signature covers (SPEC §5).
std::vector<uint8_t> keybindBlob(const std::vector<uint8_t>& owner_pk, uint8_t key_usage,
                                 const std::vector<uint8_t>& target_pk, const std::string& handle,
                                 uint64_t created_at, std::optional<uint64_t> expires_at) {
    std::vector<uint8_t> b;
    putLp(b, owner_pk);
    b.push_back(key_usage);
    putLp(b, target_pk);
    putLpStr(b, handle);
    putU64Be(b, created_at);
    if (expires_at) { b.push_back(1); putU64Be(b, *expires_at); }
    else b.push_back(0);
    return b;
}

// The bundle body (everything the self-signature covers).
std::vector<uint8_t> bundleBody(const std::vector<uint8_t>& owner_pk, const std::string& handle,
                                uint64_t created_at, const std::vector<BoundKey>& keys) {
    std::vector<uint8_t> b = {'N','K','K','B', BUNDLE_VERSION};
    putLp(b, owner_pk);
    putLpStr(b, handle);
    putU64Be(b, created_at);
    uint16_t n = (uint16_t)keys.size();
    b.push_back((uint8_t)(n & 0xff));
    b.push_back((uint8_t)((n >> 8) & 0xff)); // u16 LE count
    for (const auto& k : keys) {
        b.push_back(k.key_usage);
        putLp(b, k.target_pk);
        putU64Be(b, k.created_at);
        if (k.expires_at) { b.push_back(1); putU64Be(b, *k.expires_at); }
        else b.push_back(0);
        putLp(b, k.keybind_sig);
    }
    return b;
}

} // namespace

std::expected<std::vector<uint8_t>, CryptoError> buildSigned(
    const std::vector<uint8_t>& owner_priv_der, const std::vector<uint8_t>& owner_pk_raw,
    const std::string& handle, uint64_t created_at, const std::vector<KeyToBind>& keys,
    const SecureString& passphrase) {
    if (keys.size() > MAX_BUNDLE_KEYS) return std::unexpected(CryptoError::WireFormatError);
    if (owner_pk_raw.size() > MAX_FIELD_LEN || handle.size() > MAX_FIELD_LEN)
        return std::unexpected(CryptoError::WireFormatError);
    for (const auto& k : keys)
        if (k.target_pk.size() > MAX_FIELD_LEN) return std::unexpected(CryptoError::WireFormatError);

    auto backend = ::get_nk_backend();
    std::vector<BoundKey> bound;
    bound.reserve(keys.size());
    for (const auto& k : keys) {
        if (k.key_usage != KEY_USAGE_ENC && k.key_usage != KEY_USAGE_HYBRID)
            return std::unexpected(CryptoError::WireFormatError);
        auto blob = keybindBlob(owner_pk_raw, k.key_usage, k.target_pk, handle, k.created_at, k.expires_at);
        auto sig = backend->mldsaSignCtx(owner_priv_der, blob, KEYBIND_CTX, passphrase);
        if (!sig) return std::unexpected(sig.error());
        bound.push_back(BoundKey{k.key_usage, k.target_pk, k.created_at, k.expires_at, *sig});
    }
    auto body = bundleBody(owner_pk_raw, handle, created_at, bound);
    auto self_sig = backend->mldsaSignCtx(owner_priv_der, body, BUNDLE_CTX, passphrase);
    if (!self_sig) return std::unexpected(self_sig.error());
    putLp(body, *self_sig);
    return body;
}

std::expected<VerifiedKeyBundle, CryptoError> parseAndVerify(
    const std::vector<uint8_t>& bytes, const std::array<uint8_t, 32>& pinned_fingerprint) {
    if (bytes.size() < 5 || std::memcmp(bytes.data(), "NKKB", 4) != 0)
        return std::unexpected(CryptoError::WireFormatError);
    if (bytes[4] != BUNDLE_VERSION) return std::unexpected(CryptoError::WireFormatError);

    size_t off = 5;
    auto owner_pk = readLp(bytes, off);
    if (!owner_pk) return std::unexpected(owner_pk.error());
    auto handle_v = readLp(bytes, off);
    if (!handle_v) return std::unexpected(handle_v.error());
    auto created_at = readU64Be(bytes, off);
    if (!created_at) return std::unexpected(created_at.error());
    if (bytes.size() < off + 2) return std::unexpected(CryptoError::WireFormatError);
    uint16_t n = (uint16_t)bytes[off] | ((uint16_t)bytes[off + 1] << 8);
    off += 2;
    if (n > MAX_BUNDLE_KEYS) return std::unexpected(CryptoError::WireFormatError);

    auto backend = ::get_nk_backend();

    // (1) the wire owner pub must hash to the pinned fingerprint.
    auto fp = backend->sha3_256(owner_pk->data(), owner_pk->size());
    if (!fp) return std::unexpected(fp.error());
    if (fp->size() != 32 || std::memcmp(fp->data(), pinned_fingerprint.data(), 32) != 0)
        return std::unexpected(CryptoError::SignatureVerificationError);

    // The owner is ML-DSA-65; verification needs its SPKI DER.
    auto owner_spki = backend->spkiFromRawPublicKey(*owner_pk, IDENTITY_DSA);
    if (!owner_spki) return std::unexpected(owner_spki.error());

    std::string handle(handle_v->begin(), handle_v->end());
    VerifiedKeyBundle vb;
    vb.owner_pk = *owner_pk;
    vb.handle = handle;
    vb.created_at = *created_at;

    for (uint16_t i = 0; i < n; ++i) {
        if (bytes.size() < off + 1) return std::unexpected(CryptoError::WireFormatError);
        uint8_t usage = bytes[off++];
        if (usage != KEY_USAGE_ENC && usage != KEY_USAGE_HYBRID)
            return std::unexpected(CryptoError::WireFormatError);
        auto target = readLp(bytes, off);
        if (!target) return std::unexpected(target.error());
        auto k_created = readU64Be(bytes, off);
        if (!k_created) return std::unexpected(k_created.error());
        if (bytes.size() < off + 1) return std::unexpected(CryptoError::WireFormatError);
        uint8_t has_exp = bytes[off++];
        std::optional<uint64_t> expires;
        if (has_exp == 1) {
            auto e = readU64Be(bytes, off);
            if (!e) return std::unexpected(e.error());
            expires = *e;
        } else if (has_exp != 0) {
            return std::unexpected(CryptoError::WireFormatError);
        }
        auto keybind_sig = readLp(bytes, off);
        if (!keybind_sig) return std::unexpected(keybind_sig.error());

        // (3) each keybind reconstructs from the PINNED owner and verifies.
        auto blob = keybindBlob(*owner_pk, usage, *target, handle, *k_created, expires);
        auto ok = backend->mldsaVerifyCtx(*owner_spki, blob, *keybind_sig, KEYBIND_CTX);
        if (!ok || !*ok) return std::unexpected(CryptoError::SignatureVerificationError);

        vb.keys.push_back(BoundKey{usage, *target, *k_created, expires, *keybind_sig});
    }

    // (2) the self-signature covers the body (= everything before LP(self_sig)).
    size_t body_end = off;
    auto self_sig = readLp(bytes, off);
    if (!self_sig) return std::unexpected(self_sig.error());
    if (off != bytes.size()) return std::unexpected(CryptoError::WireFormatError); // no trailing bytes
    std::vector<uint8_t> body(bytes.begin(), bytes.begin() + body_end);
    auto ok = backend->mldsaVerifyCtx(*owner_spki, body, *self_sig, BUNDLE_CTX);
    if (!ok || !*ok) return std::unexpected(CryptoError::SignatureVerificationError);

    return vb;
}

std::expected<std::string, CryptoError> ownerFingerprintHex(const std::vector<uint8_t>& owner_pk_raw) {
    auto fp = ::get_nk_backend()->sha3_256(owner_pk_raw.data(), owner_pk_raw.size());
    if (!fp) return std::unexpected(fp.error());
    static const char* hex = "0123456789abcdef";
    std::string out;
    out.reserve(64);
    for (uint8_t b : *fp) { out.push_back(hex[b >> 4]); out.push_back(hex[b & 0xf]); }
    return out;
}

} // namespace nk::keybundle
