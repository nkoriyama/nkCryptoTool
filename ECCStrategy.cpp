/*
 * Copyright (c) 2024-2026 Naohiro KORIYAMA <nkoriyama@gmail.com>
 *
 * This file is part of nkCryptoTool.
 */

#include "ECCStrategy.hpp"
#include "nkCryptoToolUtils.hpp"
#include "backend/IBackend.hpp"
#include <fstream>
#include <iostream>
#include <cstring>

namespace nk {

ECCStrategy::ECCStrategy() : curve_name_("prime256v1"), digest_algo_("SHA3-512") {}
ECCStrategy::~ECCStrategy() = default;

std::expected<void, CryptoError> ECCStrategy::generateEncryptionKeyPair(const std::map<std::string, std::string>& key_paths, SecureString& passphrase) {
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
    auto key_pair = backend->generateEccKeyPair(curve_name_);
    if (!key_pair) return std::unexpected(key_pair.error());

    std::string priv_pem = nkCryptoToolUtils::wrapToPem(key_pair->first, "PRIVATE KEY");
    std::ofstream ofs_priv(priv, std::ios::binary);
    if (!ofs_priv) return std::unexpected(CryptoError::FileCreationError);
    ofs_priv.write(priv_pem.data(), (std::streamsize)priv_pem.size());

    std::string pub_pem = nkCryptoToolUtils::wrapToPem(key_pair->second, "PUBLIC KEY");
    std::ofstream ofs_pub(pub, std::ios::binary);
    if (!ofs_pub) return std::unexpected(CryptoError::FileCreationError);
    ofs_pub.write(pub_pem.data(), (std::streamsize)pub_pem.size());

    return {};
}

std::expected<void, CryptoError> ECCStrategy::prepareEncryption(const std::map<std::string, std::string>& key_paths) {
    if (key_paths.count("digest-algo")) digest_algo_ = key_paths.at("digest-algo");
    
    std::string pubkey_path;
    if (key_paths.count("public-key")) pubkey_path = key_paths.at("public-key");
    else if (key_paths.count("recipient-pubkey")) pubkey_path = key_paths.at("recipient-pubkey");
    else return std::unexpected(CryptoError::PublicKeyLoadError);

    std::ifstream ifs(pubkey_path, std::ios::binary);
    if (!ifs) return std::unexpected(CryptoError::FileReadError);
    std::string content((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());
    
    auto recipient_pub_der = nkCryptoToolUtils::unwrapFromPem(content, "PUBLIC KEY");
    if (!recipient_pub_der) return std::unexpected(recipient_pub_der.error());

    auto backend = ::get_nk_backend();
    auto ephem_pair = backend->generateEccKeyPair(curve_name_);
    if (!ephem_pair) return std::unexpected(ephem_pair.error());
    
    auto secret = backend->eccDh(ephem_pair->first, *recipient_pub_der);
    if (!secret) return std::unexpected(secret.error());

    shared_secret_ = *secret;
    auto ikm = shared_secret_;
    salt_.resize(16);
    backend->randomBytes(salt_.data(), 16);
    iv_.resize(12);
    backend->randomBytes(iv_.data(), 12);

    std::vector<uint8_t> salt_v(salt_.begin(), salt_.end());
    std::string info = "ecc-encryption";
    auto key_raw = backend->hkdf(ikm, 32, salt_v, info, "SHA256");
    
    encryption_key_.assign(key_raw.begin(), key_raw.end());

    auto res = backend->createAead("AES-256-GCM", encryption_key_, iv_, true);
    if (!res) return std::unexpected(CryptoError::OpenSSLError);
    aead_ctx_ = std::move(*res);

    ephemeral_pubkey_ = ephem_pair->second;
    return {};
}

std::expected<void, CryptoError> ECCStrategy::prepareDecryption(const std::map<std::string, std::string>& key_paths, SecureString& passphrase) {
    std::string privkey_path;
    if (key_paths.count("private-key")) privkey_path = key_paths.at("private-key");
    else if (key_paths.count("user-privkey")) privkey_path = key_paths.at("user-privkey");
    else return std::unexpected(CryptoError::ParameterError);

    std::ifstream ifs(privkey_path, std::ios::binary);
    if (!ifs) return std::unexpected(CryptoError::FileReadError);
    std::string content((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());
    
    auto user_priv_der = nkCryptoToolUtils::unwrapFromPem(content, "PRIVATE KEY");
    if (!user_priv_der) return std::unexpected(CryptoError::PrivateKeyLoadError);

    auto backend = ::get_nk_backend();
    auto secret = backend->eccDh(*user_priv_der, ephemeral_pubkey_);
    if (!secret) return std::unexpected(secret.error());

    shared_secret_ = *secret;
    auto ikm = shared_secret_;
    std::vector<uint8_t> salt_v(salt_.begin(), salt_.end());
    std::string info = "ecc-encryption";
    auto key_raw = backend->hkdf(ikm, 32, salt_v, info, "SHA256");
    
    encryption_key_.assign(key_raw.begin(), key_raw.end());

    auto res = backend->createAead("AES-256-GCM", encryption_key_, iv_, false);
    if (!res) return std::unexpected(CryptoError::OpenSSLError);
    aead_ctx_ = std::move(*res);

    return {};
}

std::vector<char> ECCStrategy::encryptTransform(const std::vector<char>& data) {
    std::vector<uint8_t> out(data.size());
    auto res = aead_ctx_->update(reinterpret_cast<const uint8_t*>(data.data()), data.size(), out.data());
    if (!res) return {};
    return std::vector<char>(out.begin(), out.begin() + *res);
}

std::vector<char> ECCStrategy::decryptTransform(const std::vector<char>& data) {
    std::vector<uint8_t> out(data.size());
    auto res = aead_ctx_->update(reinterpret_cast<const uint8_t*>(data.data()), data.size(), out.data());
    if (!res) return {};
    return std::vector<char>(out.begin(), out.begin() + *res);
}

std::expected<void, CryptoError> ECCStrategy::finalizeEncryption(std::vector<char>& tag) {
    std::vector<uint8_t> out(16);
    auto res = aead_ctx_->finalize(out.data());
    if (!res) return std::unexpected(CryptoError::OpenSSLError);
    
    std::vector<uint8_t> tag_v(16);
    auto tag_res = aead_ctx_->getTag(tag_v.data(), 16);
    if (!tag_res) return std::unexpected(CryptoError::OpenSSLError);
    
    tag.assign(tag_v.begin(), tag_v.end());
    return {};
}

std::expected<void, CryptoError> ECCStrategy::finalizeDecryption(const std::vector<char>& tag) {
    auto res = aead_ctx_->setTag(reinterpret_cast<const uint8_t*>(tag.data()), tag.size());
    if (!res) return std::unexpected(CryptoError::OpenSSLError);
    
    std::vector<uint8_t> out(16);
    auto fin_res = aead_ctx_->finalize(out.data());
    if (!fin_res) return std::unexpected(CryptoError::OpenSSLError);
    
    return {};
}

size_t ECCStrategy::getHeaderSize() const {
    return 4 + 2 + 1 + 
        4 + curve_name_.size() + 
        4 + digest_algo_.size() + 
        4 + ephemeral_pubkey_.size() + 4 + salt_.size() + 4 + iv_.size();
}

std::vector<char> ECCStrategy::serializeHeader() const {
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
    add_string(curve_name_);
    add_string(digest_algo_);
    add_vec(ephemeral_pubkey_);
    add_vec(salt_);
    add_vec(iv_);
    return header;
}

std::expected<size_t, CryptoError> ECCStrategy::deserializeHeader(const std::vector<char>& data) {
    if (data.size() < 7) return std::unexpected(CryptoError::ParameterError);
    if (std::memcmp(data.data(), "NKCT", 4) != 0) return std::unexpected(CryptoError::ParameterError);
    
    size_t pos = 7;
    auto read_string = [&](std::string& s) {
        uint32_t len;
        if (!read_u32_le(data, pos, len)) return false;
        if (pos + len > data.size()) return false;
        s.assign(data.begin() + pos, data.begin() + pos + len);
        pos += len;
        return true;
    };
    auto read_vec = [&](std::vector<unsigned char>& vec) {
        uint32_t len;
        if (!read_u32_le(data, pos, len)) return false;
        if (pos + len > data.size()) return false;
        vec.assign(data.begin() + pos, data.begin() + pos + len);
        pos += len;
        return true;
    };

    if (!read_string(curve_name_) || !read_string(digest_algo_) ||
        !read_vec(ephemeral_pubkey_) || !read_vec(salt_) || !read_vec(iv_)) {
        return std::unexpected(CryptoError::ParameterError);
    }
    return pos;
}

size_t ECCStrategy::getTagSize() const { return 16; }

std::expected<void, CryptoError> ECCStrategy::generateSigningKeyPair(const std::map<std::string, std::string>& key_paths, SecureString& passphrase) {
    return generateEncryptionKeyPair(key_paths, passphrase);
}

std::expected<void, CryptoError> ECCStrategy::regeneratePublicKey(const std::filesystem::path& priv, const std::filesystem::path& pub, SecureString& pass) {
    std::ifstream ifs(priv, std::ios::binary);
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

std::expected<void, CryptoError> ECCStrategy::prepareSigning(const std::filesystem::path& priv, SecureString&, const std::string& algo) {
    std::ifstream ifs(priv, std::ios::binary);
    std::string content((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());
    auto der = nkCryptoToolUtils::unwrapFromPem(content, "PRIVATE KEY");
    if (!der) return std::unexpected(der.error());
    auto backend = ::get_nk_backend();
    auto hash = backend->createHash(algo);
    if (!hash) return std::unexpected(hash.error());
    hash_backend_ = std::move(*hash);
    return hash_backend_->initSign(*der);
}

std::expected<void, CryptoError> ECCStrategy::prepareVerification(const std::filesystem::path& pub, const std::string& algo) {
    std::ifstream ifs(pub, std::ios::binary);
    std::string content((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());
    auto der = nkCryptoToolUtils::unwrapFromPem(content, "PUBLIC KEY");
    if (!der) return std::unexpected(der.error());
    auto backend = ::get_nk_backend();
    auto hash = backend->createHash(algo);
    if (!hash) return std::unexpected(hash.error());
    hash_backend_ = std::move(*hash);
    return hash_backend_->initVerify(*der);
}

void ECCStrategy::updateHash(const std::vector<char>& data) {
    hash_backend_->update(reinterpret_cast<const uint8_t*>(data.data()), data.size());
}

std::expected<std::vector<char>, CryptoError> ECCStrategy::signHash() {
    auto sig = hash_backend_->finalizeSign();
    if (!sig) return std::unexpected(sig.error());
    return std::vector<char>(sig->begin(), sig->end());
}

std::expected<bool, CryptoError> ECCStrategy::verifyHash(const std::vector<char>& sig) {
    return hash_backend_->finalizeVerify(std::vector<uint8_t>(sig.begin(), sig.end()));
}

std::vector<char> ECCStrategy::serializeSignatureHeader() const {
    std::vector<char> header;
    header.insert(header.end(), {'N', 'K', 'C', 'S'});
    write_u16_le(header, 1);
    header.push_back((char)getStrategyType());

    auto add_string = [&](const std::string& s) {
        write_u32_le(header, (uint32_t)s.size());
        header.insert(header.end(), s.begin(), s.end());
    };
    add_string(curve_name_);
    add_string(digest_algo_);
    return header;
}

std::expected<size_t, CryptoError> ECCStrategy::deserializeSignatureHeader(const std::vector<char>& data) {
    if (data.size() < 7) return std::unexpected(CryptoError::ParameterError);
    if (std::memcmp(data.data(), "NKCS", 4) != 0) return std::unexpected(CryptoError::ParameterError);
    
    size_t pos = 7;
    auto read_string = [&](std::string& s) {
        uint32_t len;
        if (!read_u32_le(data, pos, len)) return false;
        if (pos + len > data.size()) return false;
        s.assign(data.begin() + pos, data.begin() + pos + len);
        pos += len;
        return true;
    };

    if (!read_string(curve_name_) || !read_string(digest_algo_)) {
        return std::unexpected(CryptoError::ParameterError);
    }
    return pos;
}

std::map<std::string, std::string> ECCStrategy::getMetadata(const std::string&) const { return {}; }

} // namespace nk
