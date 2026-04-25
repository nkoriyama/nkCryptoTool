#include "PQCStrategy.hpp"
#include <stdexcept>
#include <cstring>
#include <iostream>
#include <fstream>
#include "nkCryptoToolBase.hpp"
#include "TPMConstants.hpp"
#include "nkCryptoToolUtils.hpp"
#include "backend/IBackend.hpp"

PQCStrategy::PQCStrategy() {}
PQCStrategy::~PQCStrategy() {}

std::map<std::string, std::string> PQCStrategy::getMetadata(const std::string& magic) const {
    std::map<std::string, std::string> res;
    res["Strategy"] = "PQC";
    if (magic == "NKCS") {
        res["File-Type"] = "Signature";
        res["DSA-Algorithm"] = dsa_algo_;
    } else {
        res["File-Type"] = "Encrypted";
        res["KEM-Algorithm"] = kem_algo_;
        res["DSA-Algorithm"] = dsa_algo_;
    }
    return res;
}

size_t PQCStrategy::getHeaderSize() const {
    return 4 + 2 + 1 + 
           4 + kem_algo_.size() + 
           4 + dsa_algo_.size() + 
           4 + kem_ct_.size() + 4 + salt_.size() + 4 + iv_.size();
}

size_t PQCStrategy::getTagSize() const { return 16; }

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
    if (!read_string(kem_algo_) || !read_string(dsa_algo_) || 
        !read_vec(kem_ct_) || !read_vec(salt_) || !read_vec(iv_)) return std::unexpected(CryptoError::FileReadError);
    return pos;
}

std::expected<void, CryptoError> PQCStrategy::generateEncryptionKeyPair(const std::map<std::string, std::string>& key_paths, SecureString& passphrase) {
    std::string pub, priv;
    if (key_paths.count("public-mlkem-key") && key_paths.count("private-mlkem-key")) {
        pub = key_paths.at("public-mlkem-key");
        priv = key_paths.at("private-mlkem-key");
    } else if (key_paths.count("public-key") && key_paths.count("private-key")) {
        pub = key_paths.at("public-key");
        priv = key_paths.at("private-key");
    } else {
        return std::unexpected(CryptoError::ParameterError);
    }
    bool use_tpm = key_paths.count("use-tpm") && key_paths.at("use-tpm") == "true";

    auto backend = nk::backend::getBackend();
    auto pair = backend->generatePqcSignKeyPair(kem_algo_); 
    if (!pair) return std::unexpected(pair.error());

    if (use_tpm) {
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

std::expected<void, CryptoError> PQCStrategy::generateSigningKeyPair(const std::map<std::string, std::string>& key_paths, SecureString& passphrase) {
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
    bool use_tpm = key_paths.count("use-tpm") && key_paths.at("use-tpm") == "true";

    auto backend = nk::backend::getBackend();
    auto pair = backend->generatePqcSignKeyPair(dsa_algo_);
    if (!pair) return std::unexpected(pair.error());

    if (use_tpm) {
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

std::expected<void, CryptoError> PQCStrategy::regeneratePublicKey(const std::filesystem::path& priv_path, const std::filesystem::path& pub_path, SecureString& passphrase) {
    std::ifstream ifs(priv_path, std::ios::binary);
    std::string content((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());

    std::vector<uint8_t> priv_der;
    if (content.find(TPMUtils::TPM_BLOB_HEADER) != std::string::npos) {
        auto unwrapped = key_provider_.unwrap(SecureString(content.begin(), content.end()), passphrase);
        if (!unwrapped) return std::unexpected(unwrapped.error());
        priv_der = std::move(*unwrapped);
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

std::expected<void, CryptoError> PQCStrategy::prepareEncryption(const std::map<std::string, std::string>& key_paths) {
    std::string pubkey_path;
    if (key_paths.count("recipient-pubkey")) pubkey_path = key_paths.at("recipient-pubkey");
    else if (key_paths.count("recipient-mlkem-pubkey")) pubkey_path = key_paths.at("recipient-mlkem-pubkey");
    else return std::unexpected(CryptoError::PublicKeyLoadError);

    std::ifstream ifs(pubkey_path, std::ios::binary);
    std::string pub_pem((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());
    auto pub_der = nkCryptoToolUtils::unwrapFromPem(pub_pem, "PUBLIC KEY");
    if (!pub_der) return std::unexpected(pub_der.error());

    auto backend = nk::backend::getBackend();
    auto res = backend->pqcEncap(*pub_der);
    if (!res) return std::unexpected(res.error());
    
    shared_secret_ = res->first;
    kem_ct_ = res->second;
    
    salt_.resize(16); iv_.resize(12);
    backend->randomBytes(salt_.data(), 16);
    backend->randomBytes(iv_.data(), 12);
    
    std::vector<uint8_t> salt_v(salt_.begin(), salt_.end());
    auto key_raw = backend->hkdf(shared_secret_, 32, salt_v, "pqc-encryption", "SHA3-256");
    encryption_key_.assign(key_raw.begin(), key_raw.end());
    
    auto aead = backend->createAead("AES-256-GCM", encryption_key_, iv_, true);
    if (!aead) return std::unexpected(aead.error());
    aead_ctx_ = std::move(*aead);
    return {};
}

std::vector<char> PQCStrategy::encryptTransform(const std::vector<char>& data) {
    if (data.empty()) return {};
    std::vector<char> out(data.size() + 16);
    auto res = aead_ctx_->update((const uint8_t*)data.data(), data.size(), (uint8_t*)out.data());
    if (!res) return {};
    out.resize(*res);
    return out;
}

std::expected<void, CryptoError> PQCStrategy::finalizeEncryption(std::vector<char>& out_final) {
    std::vector<char> final_block(16);
    auto res = aead_ctx_->finalize((uint8_t*)final_block.data());
    if (!res) return std::unexpected(res.error());
    
    std::vector<uint8_t> tag(16);
    aead_ctx_->getTag(tag.data(), 16);
    
    out_final.assign(final_block.begin(), final_block.begin() + *res);
    out_final.insert(out_final.end(), tag.begin(), tag.end());
    return {};
}

std::expected<void, CryptoError> PQCStrategy::prepareDecryption(const std::map<std::string, std::string>& key_paths, SecureString& passphrase) {
    std::string priv_key_path;
    if (key_paths.count("user-privkey")) priv_key_path = key_paths.at("user-privkey");
    else if (key_paths.count("recipient-mlkem-privkey")) priv_key_path = key_paths.at("recipient-mlkem-privkey");
    else if (key_paths.count("private-mlkem-key")) priv_key_path = key_paths.at("private-mlkem-key");
    else return std::unexpected(CryptoError::PrivateKeyLoadError);

    std::ifstream ifs(priv_key_path, std::ios::binary);
    std::string content((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());

    std::vector<uint8_t> priv_der;
    if (content.find(TPMUtils::TPM_BLOB_HEADER) != std::string::npos) {
        auto unwrapped = key_provider_.unwrap(SecureString(content.begin(), content.end()), passphrase);
        if (!unwrapped) return std::unexpected(unwrapped.error());
        priv_der = std::move(*unwrapped);
    } else {
        auto der = nkCryptoToolUtils::unwrapFromPem(content, "PRIVATE KEY");
        if (!der) return std::unexpected(der.error());
        priv_der = std::move(*der);
    }

    auto backend = nk::backend::getBackend();
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

std::vector<char> PQCStrategy::decryptTransform(const std::vector<char>& data) {
    if (data.empty()) return {};
    std::vector<char> out(data.size() + 16);
    auto res = aead_ctx_->update((const uint8_t*)data.data(), data.size(), (uint8_t*)out.data());
    if (!res) return {};
    out.resize(*res);
    return out;
}

std::expected<void, CryptoError> PQCStrategy::finalizeDecryption(const std::vector<char>& tag) {
    aead_ctx_->setTag((const uint8_t*)tag.data(), tag.size());
    std::vector<char> final_block(16);
    auto res = aead_ctx_->finalize((uint8_t*)final_block.data());
    if (!res) return std::unexpected(CryptoError::SignatureVerificationError);
    return {};
}

std::expected<void, CryptoError> PQCStrategy::prepareSigning(const std::filesystem::path& priv_key_path, SecureString& passphrase, const std::string& digest_algo) {
    std::ifstream ifs(priv_key_path, std::ios::binary);
    if (!ifs) return std::unexpected(CryptoError::PrivateKeyLoadError);
    std::string content((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());

    std::vector<uint8_t> priv_der;
    if (content.find(TPMUtils::TPM_BLOB_HEADER) != std::string::npos) {
        auto unwrapped = key_provider_.unwrap(SecureString(content.begin(), content.end()), passphrase);
        if (!unwrapped) return std::unexpected(unwrapped.error());
        priv_der = std::move(*unwrapped);
    } else {
        auto der = nkCryptoToolUtils::unwrapFromPem(content, "PRIVATE KEY");
        if (!der) return std::unexpected(der.error());
        priv_der = std::move(*der);
    }

    auto backend = nk::backend::getBackend();
    auto hash = backend->createHash(digest_algo);
    if (!hash) return std::unexpected(hash.error());
    hash_ctx_ = std::move(*hash);
    return hash_ctx_->initSign(priv_der);
}

std::expected<void, CryptoError> PQCStrategy::prepareVerification(const std::filesystem::path& pub_key_path, const std::string& digest_algo) {
    std::ifstream ifs(pub_key_path, std::ios::binary);
    if (!ifs) return std::unexpected(CryptoError::PublicKeyLoadError);
    std::string content((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());
    auto der = nkCryptoToolUtils::unwrapFromPem(content, "PUBLIC KEY");
    if (!der) return std::unexpected(der.error());

    auto backend = nk::backend::getBackend();
    auto hash = backend->createHash(digest_algo);
    if (!hash) return std::unexpected(hash.error());
    hash_ctx_ = std::move(*hash);
    return hash_ctx_->initVerify(*der);
}

void PQCStrategy::updateHash(const std::vector<char>& data) {
    hash_ctx_->update((const uint8_t*)data.data(), data.size());
}

std::expected<std::vector<char>, CryptoError> PQCStrategy::signHash() {
    auto res = hash_ctx_->finalizeSign();
    if (!res) return std::unexpected(res.error());
    return std::vector<char>(res->begin(), res->end());
}

std::expected<bool, CryptoError> PQCStrategy::verifyHash(const std::vector<char>& signature) {
    std::vector<uint8_t> sig_v(signature.begin(), signature.end());
    return hash_ctx_->finalizeVerify(sig_v);
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
    return header;
}

std::expected<size_t, CryptoError> PQCStrategy::deserializeSignatureHeader(const std::vector<char>& data) {
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
    if (!read_string(kem_algo_) || !read_string(dsa_algo_)) return std::unexpected(CryptoError::FileReadError);
    return pos;
}
