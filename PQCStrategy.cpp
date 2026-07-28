/*
 * Copyright (c) 2024-2026 Naohiro KORIYAMA <nkoriyama@gmail.com>
 *
 * This file is part of nkCryptoTool.
 */

#include "PQCStrategy.hpp"
#include "nkV3Format.hpp"
#include <stdexcept>
#include <cstring>
#include <iostream>
#include <fstream>
#include "nkCryptoToolBase.hpp"
#include "TPMConstants.hpp"
#include "nkCryptoToolUtils.hpp"
#include "backend/IBackend.hpp"

namespace nk {

// FIPS 204 context string for detached **file** signatures (`--sign`).
//
// Without it, file signing runs ML-DSA over attacker-supplied bytes under the
// empty context — the same context the MLS transport-binding signature uses,
// with the same key. One "please sign this attestation" request would then
// yield a valid transport_sig for a MemberBinding of the requester's choosing,
// defeating the proof-of-possession that binding verification rests on.
//
// Must stay byte-identical to `FILE_SIGN_CTX` in the Rust implementation
// (src/strategy/pqc.rs) or detached signatures stop interoperating.
static const std::vector<uint8_t> FILE_SIGN_CTX = {
    'n','k','c','t','-','f','i','l','e','-','s','i','g','n','-','v','1'
};

// NKCS container version that signed under the empty context. Still *verified*
// so signatures produced before this change keep validating; never produced.
static constexpr uint16_t NKCS_VERSION_CTX_FREE = 1;
// NKCS container version that signs under FILE_SIGN_CTX. What we produce.
static constexpr uint16_t NKCS_VERSION_DOMAIN_SEP = 2;

static void write_u16_le(std::vector<char>& buf, uint16_t val) {
    buf.push_back((char)(val & 0xff));
    buf.push_back((char)((val >> 8) & 0xff));
}

static void write_u32_le(std::vector<char>& buf, uint32_t val) {
    buf.push_back((char)(val & 0xff));
    buf.push_back((char)((val >> 8) & 0xff));
    buf.push_back((char)((val >> 16) & 0xff));
    buf.push_back((char)((val >> 24) & 0xff));
}

static bool read_u32_le(const std::vector<char>& buf, size_t& pos, uint32_t& val) {
    if (pos + 4 > buf.size()) return false;
    val = (uint32_t)(unsigned char)buf[pos] | 
          ((uint32_t)(unsigned char)buf[pos+1] << 8) | 
          ((uint32_t)(unsigned char)buf[pos+2] << 16) | 
          ((uint32_t)(unsigned char)buf[pos+3] << 24);
    pos += 4;
    return true;
}

PQCStrategy::PQCStrategy() : kem_algo_("ML-KEM-768"), dsa_algo_("ML-DSA-65"), digest_algo_("SHA3-512"), aead_algo_("AES-256-GCM") {}
PQCStrategy::~PQCStrategy() = default;

std::expected<void, CryptoError> PQCStrategy::generateEncryptionKeyPair(const std::map<std::string, std::string>& key_paths, SecureString& passphrase, bool force) {
    if (key_paths.count("kem-algo")) kem_algo_ = key_paths.at("kem-algo");
    
    std::string pub, priv;
    if (key_paths.count("public-key") && key_paths.count("private-key")) {
        pub = key_paths.at("public-key");
        priv = key_paths.at("private-key");
    } else if (key_paths.count("recipient-pubkey") && key_paths.count("user-privkey")) {
        pub = key_paths.at("recipient-pubkey");
        priv = key_paths.at("user-privkey");
    } else {
        return std::unexpected(CryptoError::ParameterError);
    }

    auto pair = ::get_nk_backend()->generatePqcKemKeyPair(kem_algo_);
    if (!pair) return std::unexpected(pair.error());

    if (key_paths.count("use-tpm") && key_paths.at("use-tpm") == "true") {
        auto wrapped = key_provider_.wrap(pair->first, passphrase);
        if (!wrapped) return std::unexpected(wrapped.error());
        std::vector<uint8_t> wrapped_v(wrapped->begin(), wrapped->end());
        auto res = nkCryptoToolUtils::secureWrite(priv, wrapped_v, force);
        if (!res) return std::unexpected(res.error());
    } else {
        std::string pem = nkCryptoToolUtils::wrapToPem(pair->first, "PRIVATE KEY");
        std::vector<uint8_t> pem_v(pem.begin(), pem.end());
        auto res = nkCryptoToolUtils::secureWrite(priv, pem_v, force);
        if (!res) return std::unexpected(res.error());
    }

    std::string pub_pem = nkCryptoToolUtils::wrapToPem(pair->second, "PUBLIC KEY");
    std::vector<uint8_t> pub_pem_v(pub_pem.begin(), pub_pem.end());
    auto res_pub = nkCryptoToolUtils::secureWrite(pub, pub_pem_v, force);
    if (!res_pub) return std::unexpected(res_pub.error());

    return {};
}

std::expected<void, CryptoError> PQCStrategy::prepareEncryption(const std::map<std::string, std::string>& key_paths) {
    if (key_paths.count("kem-algo")) kem_algo_ = key_paths.at("kem-algo");
    if (key_paths.count("aead-algo")) aead_algo_ = key_paths.at("aead-algo");
    
    std::string pubkey_path;
    if (key_paths.count("public-key")) pubkey_path = key_paths.at("public-key");
    else if (key_paths.count("recipient-pubkey")) pubkey_path = key_paths.at("recipient-pubkey");
    else return std::unexpected(CryptoError::PublicKeyLoadError);

    std::ifstream ifs(pubkey_path, std::ios::binary);
    if (!ifs) return std::unexpected(CryptoError::FileReadError);
    std::string content((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());
    auto pub_der = nkCryptoToolUtils::unwrapFromPem(content, "PUBLIC KEY");
    if (!pub_der) return std::unexpected(pub_der.error());

    auto backend = ::get_nk_backend();
    auto res = backend->pqcEncap(*pub_der);
    if (!res) return std::unexpected(res.error());

    shared_secret_ = res->first;
    kem_ct_ = res->second;
    salt_.resize(16);
    backend->randomBytes(salt_.data(), 16);
    iv_.resize(12);
    backend->randomBytes(iv_.data(), 12);

    // v3 (ChunkedAead) material — encryption always writes v3 now.
    std::vector<uint8_t> salt_v(salt_.begin(), salt_.end());
    format_version_ = 3;
    chunk_size_ = nk::v3::chunkSizeFromEnv();
    auto key_raw = backend->hkdf(shared_secret_, 32, salt_v, nk::v3::INFO_ENC_KEY, "SHA3-256");
    v3_key_.assign(key_raw.begin(), key_raw.end());
    auto prefix_raw = backend->hkdf(shared_secret_, nk::v3::NONCE_PREFIX_LEN, salt_v,
                                    nk::v3::INFO_NONCE_PREFIX, "SHA3-256");
    v3_nonce_prefix_.assign(prefix_raw.begin(), prefix_raw.end());
    return {};
}

std::expected<void, CryptoError> PQCStrategy::prepareDecryption(const std::map<std::string, std::string>& key_paths, SecureString& passphrase) {
    std::string privkey_path;
    if (key_paths.count("private-key")) privkey_path = key_paths.at("private-key");
    else if (key_paths.count("user-privkey")) privkey_path = key_paths.at("user-privkey");
    else return std::unexpected(CryptoError::ParameterError);

    std::ifstream ifs(privkey_path, std::ios::binary);
    if (!ifs) return std::unexpected(CryptoError::FileReadError);
    std::string content((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());
    
    std::vector<uint8_t> priv_der;
    if (content.find("-----BEGIN TPM WRAPPED BLOB-----") != std::string::npos) {
        auto unwrapped = key_provider_.unwrap(SecureString(content.begin(), content.end()), passphrase);
        if (!unwrapped) return std::unexpected(unwrapped.error());
        priv_der = std::move(*unwrapped);
    } else {
        passphrase = nkCryptoToolUtils::getPassphraseIfNeeded(content, passphrase);
        auto der = nkCryptoToolUtils::unwrapFromPem(content, "PRIVATE KEY");
        if (!der) return std::unexpected(der.error());
        priv_der = std::move(*der);
    }

    auto backend = ::get_nk_backend();
    auto secret = backend->pqcDecap(priv_der, kem_ct_, passphrase);
    if (!secret) return std::unexpected(secret.error());

    shared_secret_ = *secret;
    std::vector<uint8_t> salt_v(salt_.begin(), salt_.end());

    if (format_version_ >= 3) {
        auto key_raw = backend->hkdf(shared_secret_, 32, salt_v, nk::v3::INFO_ENC_KEY, "SHA3-256");
        v3_key_.assign(key_raw.begin(), key_raw.end());
        auto prefix_raw = backend->hkdf(shared_secret_, nk::v3::NONCE_PREFIX_LEN, salt_v,
                                        nk::v3::INFO_NONCE_PREFIX, "SHA3-256");
        v3_nonce_prefix_.assign(prefix_raw.begin(), prefix_raw.end());
        return {};
    }

    // Legacy v1/v2: single streaming AEAD over the whole body.
    auto key_raw = backend->hkdf(shared_secret_, 32, salt_v, "pqc-encryption", "SHA3-256");
    encryption_key_.assign(key_raw.begin(), key_raw.end());
    
    auto aead = backend->createAead(aead_algo_, encryption_key_, iv_, false);
    if (!aead) return std::unexpected(aead.error());
    aead_ctx_ = std::move(*aead);
    return {};
}

std::vector<char> PQCStrategy::encryptTransform(const std::vector<char>& data) {
    if (!aead_ctx_) return {};
    std::vector<uint8_t> out(data.size());
    auto res = aead_ctx_->update(reinterpret_cast<const uint8_t*>(data.data()), data.size(), out.data());
    if (!res) return {};
    return std::vector<char>(out.begin(), out.begin() + *res);
}

std::vector<char> PQCStrategy::decryptTransform(const std::vector<char>& data) {
    if (!aead_ctx_) return {};
    std::vector<uint8_t> out(data.size());
    auto res = aead_ctx_->update(reinterpret_cast<const uint8_t*>(data.data()), data.size(), out.data());
    if (!res) return {};
    return std::vector<char>(out.begin(), out.begin() + *res);
}

std::expected<void, CryptoError> PQCStrategy::finalizeEncryption(std::vector<char>& tag) {
    if (!aead_ctx_) return std::unexpected(CryptoError::ParameterError);
    std::vector<uint8_t> out(16);
    auto res = aead_ctx_->finalize(out.data());
    if (!res) return std::unexpected(CryptoError::OpenSSLError);
    std::vector<uint8_t> tag_v(16);
    aead_ctx_->getTag(tag_v.data(), 16);
    tag.assign(tag_v.begin(), tag_v.end());
    return {};
}

std::expected<void, CryptoError> PQCStrategy::finalizeDecryption(const std::vector<char>& tag) {
    if (!aead_ctx_) return std::unexpected(CryptoError::ParameterError);
    aead_ctx_->setTag((const uint8_t*)tag.data(), tag.size());
    std::vector<uint8_t> out(16);
    auto res = aead_ctx_->finalize(out.data());
    if (!res) return std::unexpected(CryptoError::SignatureVerificationError);
    return {};
}

size_t PQCStrategy::getHeaderSize() const {
    return 4 + 2 + 1 + 4 + kem_algo_.size() + 4 + dsa_algo_.size() + 4 + kem_ct_.size() + 4 + salt_.size() + 4 + iv_.size() + 4 + aead_algo_.size() + 4 /* v3 chunk_size */;
}

std::vector<char> PQCStrategy::serializeHeader() const {
    std::vector<char> header;
    header.insert(header.end(), {'N', 'K', 'C', 'T'});
    write_u16_le(header, 3); // Version 3 (ChunkedAead)
    header.push_back((char)getStrategyType());

    auto add_string = [&](const std::string& s) {
        write_u32_le(header, (uint32_t)s.size());
        header.insert(header.end(), s.begin(), s.end());
    };
    auto add_vec = [&](const std::vector<unsigned char>& vec) {
        write_u32_le(header, (uint32_t)vec.size());
        header.insert(header.end(), vec.begin(), vec.end());
    };
    add_string(kem_algo_);
    add_string(dsa_algo_);
    add_vec(kem_ct_);
    add_vec(salt_);
    add_vec(iv_);
    add_string(aead_algo_);
    write_u32_le(header, chunk_size_ ? chunk_size_ : nk::v3::DEFAULT_CHUNK_SIZE);
    return header;
}

std::expected<size_t, CryptoError> PQCStrategy::deserializeHeader(const std::vector<char>& data) {
    if (data.size() < 7 || std::memcmp(data.data(), "NKCT", 4) != 0) return std::unexpected(CryptoError::ParameterError);
    
    size_t pos = 4;
    uint16_t version;
    if (!read_u16_le(data, pos, version)) return std::unexpected(CryptoError::ParameterError);
    pos = 7;

    auto read_string = [&](std::string& s) {
        uint32_t len;
        if (!read_u32_le(data, pos, len)) return false;
        if (pos + len > data.size()) return false;
        s.assign(data.begin() + pos, data.begin() + pos + len); pos += len;
        return true;
    };
    auto read_vec = [&](std::vector<unsigned char>& vec) {
        uint32_t len;
        if (!read_u32_le(data, pos, len)) return false;
        if (pos + len > data.size()) return false;
        vec.assign(data.begin() + pos, data.begin() + pos + len); pos += len;
        return true;
    };
    if (!read_string(kem_algo_) || !read_string(dsa_algo_) || !read_vec(kem_ct_) || !read_vec(salt_) || !read_vec(iv_)) return std::unexpected(CryptoError::ParameterError);
    
    if (version >= 2) {
        if (!read_string(aead_algo_)) return std::unexpected(CryptoError::ParameterError);
    } else {
        aead_algo_ = "AES-256-GCM";
    }

    format_version_ = version;
    if (version >= 3) {
        if (!read_u32_le(data, pos, chunk_size_) || chunk_size_ == 0) {
            return std::unexpected(CryptoError::ParameterError);
        }
    }

    return pos;
}

size_t PQCStrategy::getTagSize() const { return 16; }

std::expected<void, CryptoError> PQCStrategy::generateSigningKeyPair(const std::map<std::string, std::string>& key_paths, SecureString& passphrase, bool force) {
    if (key_paths.count("dsa-algo")) dsa_algo_ = key_paths.at("dsa-algo");
    std::string pub, priv;
    if (key_paths.count("signing-public-key") && key_paths.count("signing-private-key")) {
        pub = key_paths.at("signing-public-key");
        priv = key_paths.at("signing-private-key");
    } else if (key_paths.count("public-key") && key_paths.count("private-key")) {
        pub = key_paths.at("public-key");
        priv = key_paths.at("private-key");
    } else {
        return std::unexpected(CryptoError::ParameterError);
    }
    auto pair = ::get_nk_backend()->generatePqcSignKeyPair(dsa_algo_);
    if (!pair) return std::unexpected(pair.error());
    std::string pem = nkCryptoToolUtils::wrapToPem(pair->first, "PRIVATE KEY");
    std::vector<uint8_t> pem_v(pem.begin(), pem.end());
    auto res = nkCryptoToolUtils::secureWrite(priv, pem_v, force);
    if (!res) return std::unexpected(res.error());

    std::string pub_pem = nkCryptoToolUtils::wrapToPem(pair->second, "PUBLIC KEY");
    std::vector<uint8_t> pub_pem_v(pub_pem.begin(), pub_pem.end());
    auto res_pub = nkCryptoToolUtils::secureWrite(pub, pub_pem_v, force);
    if (!res_pub) return std::unexpected(res_pub.error());
    
    return {};
}

std::expected<void, CryptoError> PQCStrategy::regeneratePublicKey(const std::filesystem::path& priv, const std::filesystem::path& pub, SecureString& passphrase, bool force) {
    std::ifstream ifs(priv, std::ios::binary);
    if (!ifs) return std::unexpected(CryptoError::FileReadError);
    std::string content((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());

    passphrase = nkCryptoToolUtils::getPassphraseIfNeeded(content, passphrase);

    auto der = nkCryptoToolUtils::unwrapFromPem(content, "PRIVATE KEY");
    if (!der) return std::unexpected(der.error());
    auto pub_der = ::get_nk_backend()->extractPublicKey(*der, passphrase);
    if (!pub_der) return std::unexpected(pub_der.error());
    std::string pub_pem = nkCryptoToolUtils::wrapToPem(*pub_der, "PUBLIC KEY");
    std::vector<uint8_t> pub_pem_v(pub_pem.begin(), pub_pem.end());
    auto res = nkCryptoToolUtils::secureWrite(pub, pub_pem_v, force);
    if (!res) return std::unexpected(res.error());
    return {};
}

std::expected<void, CryptoError> PQCStrategy::prepareSigning(const std::filesystem::path& priv, SecureString& passphrase, const std::string& algo) {
    digest_algo_ = algo;
    std::ifstream ifs(priv, std::ios::binary);
    if (!ifs) return std::unexpected(CryptoError::FileReadError);
    std::string content((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());

    passphrase = nkCryptoToolUtils::getPassphraseIfNeeded(content, passphrase);

    auto der = nkCryptoToolUtils::unwrapFromPem(content, "PRIVATE KEY");
    if (!der) return std::unexpected(der.error());
    // The key and passphrase are kept for signHash(): the signature is produced
    // with mldsaSignCtx (a FIPS 204 context is required, see FILE_SIGN_CTX)
    // rather than through the streaming digest path, which takes no context.
    sign_key_der_ = *der;
    sign_passphrase_ = passphrase;
    sign_buffer_.clear();
    sig_version_ = NKCS_VERSION_DOMAIN_SEP;
    return {};
}

std::expected<void, CryptoError> PQCStrategy::prepareVerification(const std::filesystem::path& pub, const std::string& algo) {
    digest_algo_ = algo;
    std::ifstream ifs(pub, std::ios::binary);
    if (!ifs) return std::unexpected(CryptoError::FileReadError);
    std::string content((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());
    auto der = nkCryptoToolUtils::unwrapFromPem(content, "PUBLIC KEY");
    if (!der) return std::unexpected(der.error());
    // Kept for verifyHash(), which needs mldsaVerifyCtx to pass the context the
    // NKCS version selects. `sig_version_` is filled in by
    // deserializeSignatureHeader before verifyHash runs.
    verify_key_der_ = *der;
    sign_buffer_.clear();
    return {};
}

void PQCStrategy::updateHash(const std::vector<char>& data) {
    sign_buffer_.insert(sign_buffer_.end(), data.begin(), data.end());
}

std::expected<std::vector<char>, CryptoError> PQCStrategy::signHash() {
    if (sign_key_der_.empty()) return std::unexpected(CryptoError::ParameterError);
    auto backend = ::get_nk_backend();
    // Always the domain-separated context: a signature produced here must not
    // be reusable as an MLS transport-binding signature made with the same key.
    auto sig = backend->mldsaSignCtx(sign_key_der_, sign_buffer_, FILE_SIGN_CTX, sign_passphrase_);
    if (!sig) return std::unexpected(sig.error());
    return std::vector<char>(sig->begin(), sig->end());
}

std::expected<bool, CryptoError> PQCStrategy::verifyHash(const std::vector<char>& sig) {
    if (verify_key_der_.empty()) return std::unexpected(CryptoError::ParameterError);
    auto backend = ::get_nk_backend();
    // Verify under the context the container declares, so signatures written by
    // an older build (NKCS v1, empty context) still validate. This does not
    // reopen the cross-protocol reuse: that needs a freshly produced victim
    // signature, and nothing emits v1 any more.
    const std::vector<uint8_t> ctx =
        (sig_version_ >= NKCS_VERSION_DOMAIN_SEP) ? FILE_SIGN_CTX : std::vector<uint8_t>{};
    return backend->mldsaVerifyCtx(verify_key_der_, sign_buffer_,
                                   std::vector<uint8_t>(sig.begin(), sig.end()), ctx);
}

std::vector<char> PQCStrategy::serializeSignatureHeader() const {
    std::vector<char> header;
    header.insert(header.end(), {'N', 'K', 'C', 'S'});
    write_u16_le(header, NKCS_VERSION_DOMAIN_SEP);
    header.push_back((char)getStrategyType());
    auto add_string = [&](const std::string& s) {
        write_u32_le(header, (uint32_t)s.size());
        header.insert(header.end(), s.begin(), s.end());
    };
    add_string(kem_algo_);
    add_string(dsa_algo_);
    add_string(digest_algo_);
    return header;
}

std::expected<size_t, CryptoError> PQCStrategy::deserializeSignatureHeader(const std::vector<char>& data) {
    if (data.size() < 7 || std::memcmp(data.data(), "NKCS", 4) != 0) return std::unexpected(CryptoError::ParameterError);
    // The version selects the FIPS 204 context verifyHash() uses, so it has to
    // be read rather than skipped. Reject anything unknown: guessing a context
    // on an unknown container is exactly the ambiguity this version removes.
    const uint16_t version = (uint16_t)((uint8_t)data[4]) | (uint16_t)((uint8_t)data[5] << 8);
    if (version != NKCS_VERSION_CTX_FREE && version != NKCS_VERSION_DOMAIN_SEP) {
        return std::unexpected(CryptoError::ParameterError);
    }
    sig_version_ = version;
    size_t pos = 7;
    auto read_string = [&](std::string& s) {
        uint32_t len;
        if (!read_u32_le(data, pos, len)) return false;
        if (pos + len > data.size()) return false;
        s.assign(data.begin() + pos, data.begin() + pos + len); pos += len;
        return true;
    };
    if (!read_string(kem_algo_) || !read_string(dsa_algo_) || !read_string(digest_algo_)) return std::unexpected(CryptoError::ParameterError);
    return pos;
}

std::map<std::string, std::string> PQCStrategy::getMetadata(const std::string&) const {
    return {{"Strategy", "PQC"}, {"KEM-Algorithm", kem_algo_}, {"DSA-Algorithm", dsa_algo_}};
}

} // namespace nk
