#include "ECCStrategy.hpp"
#include <stdexcept>
#include <cstring>
#include <iostream>
#include <fstream>
#include "nkCryptoToolBase.hpp"
#include "TPMConstants.hpp"
#include "nkCryptoToolUtils.hpp"
#include "backend/IBackend.hpp"

ECCStrategy::ECCStrategy() {}
ECCStrategy::~ECCStrategy() {}

std::map<std::string, std::string> ECCStrategy::getMetadata(const std::string& magic) const {
    std::map<std::string, std::string> res;
    res["Strategy"] = "ECC";
    if (magic == "NKCS") {
        res["File-Type"] = "Signature";
    } else {
        res["File-Type"] = "Encrypted";
    }
    res["Curve-Name"] = curve_name_;
    res["Digest-Algorithm"] = digest_algo_;
    return res;
}

size_t ECCStrategy::getHeaderSize() const {
    return 4 + 2 + 1 + 
           4 + curve_name_.size() + 
           4 + digest_algo_.size() + 
           4 + ephemeral_pubkey_.size() + 4 + salt_.size() + 4 + iv_.size();
}

size_t ECCStrategy::getTagSize() const { return 16; }

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
    size_t pos = 0;
    if (data.size() < 7) return std::unexpected(CryptoError::FileReadError);
    if (std::string(data.data(), 4) != "NKCT") return std::unexpected(CryptoError::FileReadError);
    pos += 4;
    
    uint16_t version;
    if (!read_u16_le(data, pos, version) || version != 1) return std::unexpected(CryptoError::FileReadError);
    
    uint8_t type = (uint8_t)data[pos++];
    if (type != (uint8_t)getStrategyType()) return std::unexpected(CryptoError::FileReadError);

    auto read_string = [&](std::string& s) -> bool {
        uint32_t len;
        if (!read_u32_le(data, pos, len)) return false;
        if (len > data.size() || pos > data.size() - len) return false;
        s.assign(data.begin() + pos, data.begin() + pos + len);
        pos += len;
        return true;
    };
    auto read_vec = [&](std::vector<unsigned char>& vec) -> bool { 
        uint32_t len;
        if (!read_u32_le(data, pos, len)) return false;
        if (len > data.size() || pos > data.size() - len) return false;
        vec.assign(data.begin() + pos, data.begin() + pos + len);
        pos += len;
        return true;
    };
    if (!read_string(curve_name_) || !read_string(digest_algo_) || 
        !read_vec(ephemeral_pubkey_) || !read_vec(salt_) || !read_vec(iv_)) return std::unexpected(CryptoError::FileReadError);
    return pos;
}

std::expected<void, CryptoError> ECCStrategy::generateEncryptionKeyPair(const std::map<std::string, std::string>& key_paths, SecureString& passphrase) {
    std::string pub, priv;
    if (key_paths.count("public-ecdh-key") && key_paths.count("private-ecdh-key")) {
        pub = key_paths.at("public-ecdh-key");
        priv = key_paths.at("private-ecdh-key");
    } else if (key_paths.count("public-key") && key_paths.count("private-key")) {
        pub = key_paths.at("public-key");
        priv = key_paths.at("private-key");
    } else if (key_paths.count("signing-public-key") && key_paths.count("signing-private-key")) {
        pub = key_paths.at("signing-public-key");
        priv = key_paths.at("signing-private-key");
    } else {
        return std::unexpected(CryptoError::ParameterError);
    }

    bool use_tpm = key_paths.count("use-tpm") && key_paths.at("use-tpm") == "true";
    
    auto backend = nk::backend::getBackend();
    auto key_pair = backend->generateEccKeyPair(curve_name_);
    if (!key_pair) return std::unexpected(key_pair.error());

    if (use_tpm) {
        auto wrapped = key_provider_.wrap(key_pair->first, passphrase);
        if (!wrapped) return std::unexpected(wrapped.error());
        std::ofstream ofs(priv, std::ios::binary);
        ofs.write(wrapped->data(), (std::streamsize)wrapped->size());
    } else {
        std::string pem = nkCryptoToolUtils::wrapToPem(key_pair->first, "PRIVATE KEY");
        std::ofstream ofs(priv, std::ios::binary);
        ofs.write(pem.data(), (std::streamsize)pem.size());
    }
    
    std::string pub_pem = nkCryptoToolUtils::wrapToPem(key_pair->second, "PUBLIC KEY");
    std::ofstream ofs_pub(pub, std::ios::binary);
    ofs_pub.write(pub_pem.data(), (std::streamsize)pub_pem.size());
    return {};
}

std::expected<void, CryptoError> ECCStrategy::generateSigningKeyPair(const std::map<std::string, std::string>& key_paths, SecureString& passphrase) {
    return generateEncryptionKeyPair(key_paths, passphrase);
}

std::expected<void, CryptoError> ECCStrategy::regeneratePublicKey(const std::filesystem::path& priv_path, const std::filesystem::path& pub_path, SecureString& passphrase) {
    std::ifstream ifs(priv_path, std::ios::binary);
    std::string content((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());
    
    std::vector<uint8_t> priv_der;
    if (content.find(TPMUtils::TPM_BLOB_HEADER) != std::string::npos) {
        auto loaded = key_provider_.unwrap(SecureString(content.begin(), content.end()), passphrase);
        if (!loaded) return std::unexpected(loaded.error());
        priv_der = std::move(*loaded);
    } else {
        auto der = nkCryptoToolUtils::unwrapFromPem(content, "PRIVATE KEY");
        if (!der) return std::unexpected(der.error());
        priv_der = std::move(*der);
    }

    auto backend = nk::backend::getBackend();
    auto pub_der = backend->extractPublicKey(priv_der);
    if (!pub_der) return std::unexpected(pub_der.error());

    std::string pub_pem = nkCryptoToolUtils::wrapToPem(*pub_der, "PUBLIC KEY");
    std::ofstream ofs_pub(pub_path, std::ios::binary);
    ofs_pub.write(pub_pem.data(), (std::streamsize)pub_pem.size());
    return {};
}

std::expected<void, CryptoError> ECCStrategy::prepareEncryption(const std::map<std::string, std::string>& key_paths) {
    if (key_paths.count("digest-algo")) digest_algo_ = key_paths.at("digest-algo");
    
    std::string pubkey_path;
    if (key_paths.count("recipient-pubkey")) pubkey_path = key_paths.at("recipient-pubkey");
    else if (key_paths.count("recipient-ecdh-pubkey")) pubkey_path = key_paths.at("recipient-ecdh-pubkey");
    else return std::unexpected(CryptoError::PublicKeyLoadError);

    std::ifstream ifs(pubkey_path, std::ios::binary);
    std::string pub_pem((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());
    auto recipient_pub_der = nkCryptoToolUtils::unwrapFromPem(pub_pem, "PUBLIC KEY");
    if (!recipient_pub_der) return std::unexpected(recipient_pub_der.error());

    auto backend = nk::backend::getBackend();
    auto ephem_pair = backend->generateEccKeyPair(curve_name_);
    if (!ephem_pair) return std::unexpected(ephem_pair.error());
    
    auto secret = backend->eccDh(ephem_pair->first, *recipient_pub_der);
    if (!secret) return std::unexpected(secret.error());
    shared_secret_ = *secret;

    ephemeral_pubkey_ = ephem_pair->second;
    salt_.resize(16); iv_.resize(12);
    backend->randomBytes(salt_.data(), 16);
    backend->randomBytes(iv_.data(), 12);
    
    std::vector<uint8_t> salt_v(salt_.begin(), salt_.end());
    auto key_raw = backend->hkdf(shared_secret_, 32, salt_v, "ecc-encryption", "SHA3-256");
    encryption_key_.assign(key_raw.begin(), key_raw.end());

    auto aead = backend->createAead("AES-256-GCM", encryption_key_, iv_, true);
    if (!aead) return std::unexpected(aead.error());
    aead_ctx_ = std::move(*aead);

    return {};
}

std::vector<char> ECCStrategy::encryptTransform(const std::vector<char>& data) {
    if (data.empty()) return {};
    std::vector<char> out(data.size() + 16);
    auto res = aead_ctx_->update((const uint8_t*)data.data(), data.size(), (uint8_t*)out.data());
    if (!res) return {};
    out.resize(*res);
    return out;
}

std::expected<void, CryptoError> ECCStrategy::finalizeEncryption(std::vector<char>& out_final) {
    std::vector<char> final_block(16);
    auto res = aead_ctx_->finalize((uint8_t*)final_block.data());
    if (!res) return std::unexpected(res.error());
    
    std::vector<uint8_t> tag(16);
    aead_ctx_->getTag(tag.data(), 16);
    
    out_final.assign(final_block.begin(), final_block.begin() + *res);
    out_final.insert(out_final.end(), tag.begin(), tag.end());
    return {};
}

std::expected<void, CryptoError> ECCStrategy::prepareDecryption(const std::map<std::string, std::string>& key_paths, SecureString& passphrase) {
    std::string priv_key_path;
    if (key_paths.count("user-privkey")) priv_key_path = key_paths.at("user-privkey");
    else if (key_paths.count("recipient-ecdh-privkey")) priv_key_path = key_paths.at("recipient-ecdh-privkey");
    else if (key_paths.count("private-ecdh-key")) priv_key_path = key_paths.at("private-ecdh-key");
    else return std::unexpected(CryptoError::PrivateKeyLoadError);

    std::ifstream ifs(priv_key_path, std::ios::binary);
    std::string pem_content((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());

    std::vector<uint8_t> priv_der;
    if (pem_content.find(TPMUtils::TPM_BLOB_HEADER) != std::string::npos) {
        auto loaded = key_provider_.unwrap(SecureString(pem_content.begin(), pem_content.end()), passphrase);
        if (!loaded) return std::unexpected(loaded.error());
        priv_der = std::move(*loaded);
    } else {
        auto der = nkCryptoToolUtils::unwrapFromPem(pem_content, "PRIVATE KEY");
        if (!der) return std::unexpected(der.error());
        priv_der = std::move(*der);
    }

    auto backend = nk::backend::getBackend();
    auto secret = backend->eccDh(priv_der, ephemeral_pubkey_);
    if (!secret) return std::unexpected(secret.error());
    shared_secret_ = *secret;
    
    std::vector<uint8_t> salt_v(salt_.begin(), salt_.end());
    auto key_raw = backend->hkdf(shared_secret_, 32, salt_v, "ecc-encryption", "SHA3-256");
    encryption_key_.assign(key_raw.begin(), key_raw.end());

    auto aead = backend->createAead("AES-256-GCM", encryption_key_, iv_, false);
    if (!aead) return std::unexpected(aead.error());
    aead_ctx_ = std::move(*aead);
    
    return {};
}

std::vector<char> ECCStrategy::decryptTransform(const std::vector<char>& data) {
    if (data.empty()) return {};
    std::vector<char> out(data.size() + 16);
    auto res = aead_ctx_->update((const uint8_t*)data.data(), data.size(), (uint8_t*)out.data());
    if (!res) return {};
    out.resize(*res);
    return out;
}

std::expected<void, CryptoError> ECCStrategy::finalizeDecryption(const std::vector<char>& tag) {
    aead_ctx_->setTag((const uint8_t*)tag.data(), tag.size());
    std::vector<char> final_block(16);
    auto res = aead_ctx_->finalize((uint8_t*)final_block.data());
    if (!res) return std::unexpected(CryptoError::SignatureVerificationError);
    return {};
}

std::expected<void, CryptoError> ECCStrategy::prepareSigning(const std::filesystem::path& priv_key_path, SecureString& passphrase, const std::string& digest_algo) {
    digest_algo_ = digest_algo;
    std::ifstream ifs(priv_key_path, std::ios::binary);
    if (!ifs) return std::unexpected(CryptoError::PrivateKeyLoadError);
    std::string pem_content((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());

    std::vector<uint8_t> priv_der;
    if (pem_content.find(TPMUtils::TPM_BLOB_HEADER) != std::string::npos) {
        auto loaded = key_provider_.unwrap(SecureString(pem_content.begin(), pem_content.end()), passphrase);
        if (!loaded) return std::unexpected(loaded.error());
        priv_der = std::move(*loaded);
    } else {
        auto der = nkCryptoToolUtils::unwrapFromPem(pem_content, "PRIVATE KEY");
        if (!der) return std::unexpected(der.error());
        priv_der = std::move(*der);
    }

    auto backend = nk::backend::getBackend();
    auto hash = backend->createHash(digest_algo_);
    if (!hash) return std::unexpected(hash.error());
    hash_ctx_ = std::move(*hash);
    return hash_ctx_->initSign(priv_der);
}

std::expected<void, CryptoError> ECCStrategy::prepareVerification(const std::filesystem::path& pub_key_path, const std::string& digest_algo) {
    digest_algo_ = digest_algo;
    std::ifstream ifs(pub_key_path, std::ios::binary);
    if (!ifs) return std::unexpected(CryptoError::PublicKeyLoadError);
    std::string pem_content((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());
    auto pub_der = nkCryptoToolUtils::unwrapFromPem(pem_content, "PUBLIC KEY");
    if (!pub_der) return std::unexpected(pub_der.error());

    auto backend = nk::backend::getBackend();
    auto hash = backend->createHash(digest_algo_);
    if (!hash) return std::unexpected(hash.error());
    hash_ctx_ = std::move(*hash);
    return hash_ctx_->initVerify(*pub_der);
}

void ECCStrategy::updateHash(const std::vector<char>& data) {
    hash_ctx_->update((const uint8_t*)data.data(), data.size());
}

std::expected<std::vector<char>, CryptoError> ECCStrategy::signHash() {
    auto res = hash_ctx_->finalizeSign();
    if (!res) return std::unexpected(res.error());
    return std::vector<char>(res->begin(), res->end());
}

std::expected<bool, CryptoError> ECCStrategy::verifyHash(const std::vector<char>& signature) {
    std::vector<uint8_t> sig_v(signature.begin(), signature.end());
    return hash_ctx_->finalizeVerify(sig_v);
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
    size_t pos = 0;
    if (data.size() < 7) return std::unexpected(CryptoError::FileReadError);
    if (std::string(data.data(), 4) != "NKCS") return std::unexpected(CryptoError::FileReadError);
    pos += 4;
    uint16_t version; if (!read_u16_le(data, pos, version) || version != 1) return std::unexpected(CryptoError::FileReadError);
    uint8_t type = (uint8_t)data[pos++];
    if (type != (uint8_t)getStrategyType()) return std::unexpected(CryptoError::FileReadError);

    auto read_string = [&](std::string& s) -> bool {
        uint32_t len;
        if (!read_u32_le(data, pos, len)) return false;
        if (pos + len > data.size()) return false;
        s.assign(data.begin() + pos, data.begin() + pos + len); pos += len;
        return true;
    };
    if (!read_string(curve_name_) || !read_string(digest_algo_)) return std::unexpected(CryptoError::FileReadError);
    return pos;
}
