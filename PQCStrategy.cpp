/*
 * Copyright (c) 2024-2026 Naohiro KORIYAMA <nkoriyama@gmail.com>
 *
 * This file is part of nkCryptoTool.
 */

#include "PQCStrategy.hpp"
#include <stdexcept>
#include <cstring>
#include <iostream>
#include <fstream>
#include "nkCryptoToolBase.hpp"
#include "TPMConstants.hpp"
#include "nkCryptoToolUtils.hpp"
#include "backend/IBackend.hpp"

namespace nk {

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

PQCStrategy::PQCStrategy() : kem_algo_("ML-KEM-768"), dsa_algo_("ML-DSA-65"), digest_algo_("SHA3-512") {}
PQCStrategy::~PQCStrategy() = default;

std::expected<void, CryptoError> PQCStrategy::generateEncryptionKeyPair(const std::map<std::string, std::string>& key_paths, SecureString& passphrase) {
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

    auto backend = ::get_nk_backend();
    auto pair = backend->generatePqcSignKeyPair(kem_algo_);
    if (!pair) return std::unexpected(pair.error());

    if (key_paths.count("use-tpm") && key_paths.at("use-tpm") == "true") {
        auto wrapped = key_provider_.wrap(pair->first, passphrase);
        if (!wrapped) return std::unexpected(wrapped.error());
        std::ofstream ofs(priv, std::ios::binary);
        ofs.write(wrapped->data(), (std::streamsize)wrapped->size());
    } else {
        std::string pem = nkCryptoToolUtils::wrapToPem(pair->first, "PRIVATE KEY");
        std::ofstream ofs(priv, std::ios::binary);
        ofs.write(pem.data(), (std::streamsize)pem.size());
    }

    std::string pub_pem = nkCryptoToolUtils::wrapToPem(pair->second, "PUBLIC KEY");
    std::ofstream ofs_pub(pub, std::ios::binary);
    ofs_pub.write(pub_pem.data(), (std::streamsize)pub_pem.size());

    return {};
}

std::expected<void, CryptoError> PQCStrategy::prepareEncryption(const std::map<std::string, std::string>& key_paths) {
    if (key_paths.count("kem-algo")) kem_algo_ = key_paths.at("kem-algo");
    
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

    std::vector<uint8_t> salt_v(salt_.begin(), salt_.end());
    auto key_raw = backend->hkdf(shared_secret_, 32, salt_v, "pqc-encryption", "SHA3-256");
    encryption_key_.assign(key_raw.begin(), key_raw.end());
    
    auto aead = backend->createAead("AES-256-GCM", encryption_key_, iv_, true);
    if (!aead) return std::unexpected(aead.error());
    aead_ctx_ = std::move(*aead);
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
        auto der = nkCryptoToolUtils::unwrapFromPem(content, "PRIVATE KEY");
        if (!der) return std::unexpected(der.error());
        priv_der = std::move(*der);
    }

    auto backend = ::get_nk_backend();
    auto secret = backend->pqcDecap(priv_der, kem_ct_);
    if (!secret) return std::unexpected(secret.error());

    shared_secret_ = *secret;
    std::vector<uint8_t> salt_v(salt_.begin(), salt_.end());
    auto key_raw = backend->hkdf(shared_secret_, 32, salt_v, "pqc-encryption", "SHA3-256");
    encryption_key_.assign(key_raw.begin(), key_raw.end());
    
    auto aead = backend->createAead("AES-256-GCM", encryption_key_, iv_, false);
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
    return 4 + 2 + 1 + 4 + kem_algo_.size() + 4 + dsa_algo_.size() + 4 + kem_ct_.size() + 4 + salt_.size() + 4 + iv_.size();
}

std::vector<char> PQCStrategy::serializeHeader() const {
    std::vector<char> header;
    header.insert(header.end(), {'N', 'K', 'C', 'T'});
    write_u16_le(header, 1);
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
    return header;
}

std::expected<size_t, CryptoError> PQCStrategy::deserializeHeader(const std::vector<char>& data) {
    if (data.size() < 7 || std::memcmp(data.data(), "NKCT", 4) != 0) return std::unexpected(CryptoError::ParameterError);
    size_t pos = 7;
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
    return pos;
}

size_t PQCStrategy::getTagSize() const { return 16; }

std::expected<void, CryptoError> PQCStrategy::generateSigningKeyPair(const std::map<std::string, std::string>& key_paths, SecureString& passphrase) {
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
    std::ofstream ofs(priv, std::ios::binary);
    ofs.write(pem.data(), (std::streamsize)pem.size());
    std::string pub_pem = nkCryptoToolUtils::wrapToPem(pair->second, "PUBLIC KEY");
    std::ofstream ofs_pub(pub, std::ios::binary);
    ofs_pub.write(pub_pem.data(), (std::streamsize)pub_pem.size());
    return {};
}

std::expected<void, CryptoError> PQCStrategy::regeneratePublicKey(const std::filesystem::path& priv, const std::filesystem::path& pub, SecureString&) {
    std::ifstream ifs(priv, std::ios::binary);
    if (!ifs) return std::unexpected(CryptoError::FileReadError);
    std::string content((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());
    auto der = nkCryptoToolUtils::unwrapFromPem(content, "PRIVATE KEY");
    if (!der) return std::unexpected(der.error());
    auto pub_der = ::get_nk_backend()->extractPublicKey(*der);
    if (!pub_der) return std::unexpected(pub_der.error());
    std::string pub_pem = nkCryptoToolUtils::wrapToPem(*pub_der, "PUBLIC KEY");
    std::ofstream ofs(pub, std::ios::binary);
    ofs.write(pub_pem.data(), (std::streamsize)pub_pem.size());
    return {};
}

std::expected<void, CryptoError> PQCStrategy::prepareSigning(const std::filesystem::path& priv, SecureString&, const std::string& algo) {
    digest_algo_ = algo;
    std::ifstream ifs(priv, std::ios::binary);
    if (!ifs) return std::unexpected(CryptoError::FileReadError);
    std::string content((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());
    auto der = nkCryptoToolUtils::unwrapFromPem(content, "PRIVATE KEY");
    if (!der) return std::unexpected(der.error());
    auto backend = ::get_nk_backend();
    auto hash = backend->createHash(algo);
    if (!hash) return std::unexpected(hash.error());
    hash_ctx_ = std::move(*hash);
    return hash_ctx_->initSign(*der);
}

std::expected<void, CryptoError> PQCStrategy::prepareVerification(const std::filesystem::path& pub, const std::string& algo) {
    digest_algo_ = algo;
    std::ifstream ifs(pub, std::ios::binary);
    if (!ifs) return std::unexpected(CryptoError::FileReadError);
    std::string content((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());
    auto der = nkCryptoToolUtils::unwrapFromPem(content, "PUBLIC KEY");
    if (!der) return std::unexpected(der.error());
    auto backend = ::get_nk_backend();
    auto hash = backend->createHash(algo);
    if (!hash) return std::unexpected(hash.error());
    hash_ctx_ = std::move(*hash);
    return hash_ctx_->initVerify(*der);
}

void PQCStrategy::updateHash(const std::vector<char>& data) {
    if (!hash_ctx_) return;
    hash_ctx_->update(reinterpret_cast<const uint8_t*>(data.data()), data.size());
}

std::expected<std::vector<char>, CryptoError> PQCStrategy::signHash() {
    if (!hash_ctx_) return std::unexpected(CryptoError::ParameterError);
    auto sig = hash_ctx_->finalizeSign();
    if (!sig) return std::unexpected(sig.error());
    return std::vector<char>(sig->begin(), sig->end());
}

std::expected<bool, CryptoError> PQCStrategy::verifyHash(const std::vector<char>& sig) {
    if (!hash_ctx_) return std::unexpected(CryptoError::ParameterError);
    return hash_ctx_->finalizeVerify(std::vector<uint8_t>(sig.begin(), sig.end()));
}

std::vector<char> PQCStrategy::serializeSignatureHeader() const {
    std::vector<char> header;
    header.insert(header.end(), {'N', 'K', 'C', 'S'});
    write_u16_le(header, 1);
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
