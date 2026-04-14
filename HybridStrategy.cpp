#include "HybridStrategy.hpp"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/core_names.h>
#include <stdexcept>
#include <cstring>
#include <iostream>
#include <fstream>
#include "nkCryptoToolBase.hpp"
#include "nkCryptoToolUtils.hpp"

HybridStrategy::HybridStrategy() : 
    pqc_strategy_(std::make_unique<PQCStrategy>()),
    ecc_strategy_(std::make_unique<ECCStrategy>()),
    cipher_ctx_(EVP_CIPHER_CTX_new()) {}

HybridStrategy::~HybridStrategy() {
    if (!shared_secret_.empty()) OPENSSL_cleanse(shared_secret_.data(), shared_secret_.size());
    if (!encryption_key_.empty()) OPENSSL_cleanse(encryption_key_.data(), encryption_key_.size());
}

std::expected<void, CryptoError> HybridStrategy::generateEncryptionKeyPair(const std::map<std::string, std::string>& key_paths, SecureString& passphrase) {
    auto res1 = pqc_strategy_->generateEncryptionKeyPair(key_paths, passphrase);
    if (!res1) return res1;
    auto res2 = ecc_strategy_->generateEncryptionKeyPair(key_paths, passphrase);
    return res2;
}

std::expected<void, CryptoError> HybridStrategy::generateSigningKeyPair(const std::map<std::string, std::string>& key_paths, SecureString& passphrase) {
    return pqc_strategy_->generateSigningKeyPair(key_paths, passphrase);
}

std::expected<void, CryptoError> HybridStrategy::prepareEncryption(const std::map<std::string, std::string>& key_paths) {
    auto res1 = pqc_strategy_->prepareEncryption(key_paths);
    if (!res1) return res1;
    auto res2 = ecc_strategy_->prepareEncryption(key_paths);
    if (!res2) return res2;

    // 共有秘密の取得と統合
    std::vector<unsigned char> pqc_secret = pqc_strategy_->getSharedSecret();
    std::vector<unsigned char> ecc_secret = ecc_strategy_->getSharedSecret();
    
    std::vector<unsigned char> combined_secret = pqc_secret;
    combined_secret.insert(combined_secret.end(), ecc_secret.begin(), ecc_secret.end());
    
    salt_ = pqc_strategy_->getSalt();
    iv_ = pqc_strategy_->getIV();
    
    encryption_key_ = nkCryptoToolBase::hkdfDerive(combined_secret, 32, std::string(salt_.begin(), salt_.end()), "hybrid-encryption", "SHA3-256");
    
    // 機密情報の消去
    OPENSSL_cleanse(combined_secret.data(), combined_secret.size());
    OPENSSL_cleanse(pqc_secret.data(), pqc_secret.size());
    OPENSSL_cleanse(ecc_secret.data(), ecc_secret.size());
    
    if (!cipher_ctx_ || EVP_EncryptInit_ex(cipher_ctx_.get(), EVP_aes_256_gcm(), nullptr, encryption_key_.data(), iv_.data()) <= 0) {
        return std::unexpected(CryptoError::OpenSSLError);
    }

    return {};
}

std::expected<void, CryptoError> HybridStrategy::prepareDecryption(const std::map<std::string, std::string>& key_paths, SecureString& passphrase) {
    SecureString pass_copy = passphrase; 

    std::map<std::string, std::string> pqc_paths = {{"user-privkey", key_paths.at("recipient-mlkem-privkey")}};
    auto res1 = pqc_strategy_->prepareDecryption(pqc_paths, pass_copy);
    if (!res1) return res1;

    std::map<std::string, std::string> ecc_paths = {{"user-privkey", key_paths.at("recipient-ecdh-privkey")}};
    auto res2 = ecc_strategy_->prepareDecryption(ecc_paths, pass_copy);
    if (!res2) return res2;

    std::vector<unsigned char> pqc_secret = pqc_strategy_->getSharedSecret();
    std::vector<unsigned char> ecc_secret = ecc_strategy_->getSharedSecret();
    
    std::vector<unsigned char> combined_secret = pqc_secret;
    combined_secret.insert(combined_secret.end(), ecc_secret.begin(), ecc_secret.end());
    
    salt_ = pqc_strategy_->getSalt();
    iv_ = pqc_strategy_->getIV();
    
    encryption_key_ = nkCryptoToolBase::hkdfDerive(combined_secret, 32, std::string(salt_.begin(), salt_.end()), "hybrid-encryption", "SHA3-256");
    
    OPENSSL_cleanse(combined_secret.data(), combined_secret.size());
    OPENSSL_cleanse(pqc_secret.data(), pqc_secret.size());
    OPENSSL_cleanse(ecc_secret.data(), ecc_secret.size());
    
    cipher_ctx_.reset(EVP_CIPHER_CTX_new());
    if (!cipher_ctx_ || EVP_DecryptInit_ex(cipher_ctx_.get(), EVP_aes_256_gcm(), nullptr, encryption_key_.data(), iv_.data()) <= 0) {
        return std::unexpected(CryptoError::OpenSSLError);
    }

    return {};
}

std::expected<void, CryptoError> HybridStrategy::prepareSigning(const std::filesystem::path& priv_key_path, SecureString& passphrase, const std::string& digest_algo) {
    return pqc_strategy_->prepareSigning(priv_key_path, passphrase, digest_algo);
}

std::expected<void, CryptoError> HybridStrategy::prepareVerification(const std::filesystem::path& pub_key_path, const std::string& digest_algo) {
    return pqc_strategy_->prepareVerification(pub_key_path, digest_algo);
}

void HybridStrategy::updateHash(const std::vector<char>& data) {
    pqc_strategy_->updateHash(data);
}

std::expected<std::vector<char>, CryptoError> HybridStrategy::signHash() {
    return pqc_strategy_->signHash();
}

std::expected<bool, CryptoError> HybridStrategy::verifyHash(const std::vector<char>& signature) {
    return pqc_strategy_->verifyHash(signature);
}

std::vector<char> HybridStrategy::encryptTransform(const std::vector<char>& data) {
    if (data.empty()) return {};
    std::vector<unsigned char> out(data.size() + EVP_MAX_BLOCK_LENGTH);
    int out_len = 0;
    EVP_EncryptUpdate(cipher_ctx_.get(), out.data(), &out_len, (const unsigned char*)data.data(), (int)data.size());
    out.resize(out_len);
    return std::vector<char>(out.begin(), out.end());
}

std::vector<char> HybridStrategy::decryptTransform(const std::vector<char>& data) {
    if (data.empty()) return {};
    std::vector<unsigned char> out(data.size() + EVP_MAX_BLOCK_LENGTH);
    int out_len = 0;
    EVP_DecryptUpdate(cipher_ctx_.get(), out.data(), &out_len, (const unsigned char*)data.data(), (int)data.size());
    out.resize(out_len);
    return std::vector<char>(out.begin(), out.end());
}

std::expected<void, CryptoError> HybridStrategy::finalizeEncryption(std::vector<char>& out) {
    int out_len = 0;
    std::vector<unsigned char> final_block(EVP_MAX_BLOCK_LENGTH);
    EVP_EncryptFinal_ex(cipher_ctx_.get(), final_block.data(), &out_len);
    out.assign(final_block.begin(), final_block.begin() + out_len);
    std::vector<unsigned char> tag(16);
    EVP_CIPHER_CTX_ctrl(cipher_ctx_.get(), EVP_CTRL_GCM_GET_TAG, 16, tag.data());
    out.insert(out.end(), tag.begin(), tag.end());
    return {};
}

std::expected<void, CryptoError> HybridStrategy::finalizeDecryption(const std::vector<char>& tag) {
    EVP_CIPHER_CTX_ctrl(cipher_ctx_.get(), EVP_CTRL_GCM_SET_TAG, 16, (void*)tag.data());
    int out_len = 0;
    std::vector<unsigned char> out(EVP_MAX_BLOCK_LENGTH);
    if (EVP_DecryptFinal_ex(cipher_ctx_.get(), out.data(), &out_len) <= 0) return std::unexpected(CryptoError::OpenSSLError);
    return {};
}

std::map<std::string, std::string> HybridStrategy::getMetadata(const std::string& magic) const {
    auto meta = pqc_strategy_->getMetadata(magic);
    meta["Strategy"] = "Hybrid";
    meta["Encryption-Type"] = "Hybrid (ML-KEM-1024 + ECDH-P256)";
    return meta;
}

size_t HybridStrategy::getHeaderSize() const {
    return 7 + pqc_strategy_->getHeaderSize() + ecc_strategy_->getHeaderSize();
}

size_t HybridStrategy::getTagSize() const { return 16; }

std::vector<char> HybridStrategy::serializeHeader() const {
    std::vector<char> header;
    header.insert(header.end(), {'N', 'K', 'C', 'T'});
    write_u16_le(header, 1);
    header.push_back((char)getStrategyType());

    auto h1 = pqc_strategy_->serializeHeader();
    auto h2 = ecc_strategy_->serializeHeader();
    header.insert(header.end(), h1.begin(), h1.end());
    header.insert(header.end(), h2.begin(), h2.end());
    return header;
}

std::expected<size_t, CryptoError> HybridStrategy::deserializeHeader(const std::vector<char>& data) {
    size_t pos = 0;
    if (data.size() < 7) return std::unexpected(CryptoError::FileReadError);
    if (std::string(data.data(), 4) != "NKCT") return std::unexpected(CryptoError::FileReadError);
    pos += 4;

    uint16_t version;
    if (!read_u16_le(data, pos, version) || version != 1) return std::unexpected(CryptoError::FileReadError);

    uint8_t type = (uint8_t)data[pos++];
    if (type != (uint8_t)getStrategyType()) return std::unexpected(CryptoError::FileReadError);

    std::vector<char> pqc_data(data.begin() + pos, data.end());
    auto res1 = pqc_strategy_->deserializeHeader(pqc_data);
    if (!res1) return std::unexpected(res1.error());
    pos += *res1;

    if (pos >= data.size()) return std::unexpected(CryptoError::FileReadError);
    std::vector<char> ecc_data(data.begin() + pos, data.end());
    auto res2 = ecc_strategy_->deserializeHeader(ecc_data);
    if (!res2) return std::unexpected(res2.error());
    pos += *res2;

    salt_ = pqc_strategy_->getSalt();
    iv_ = pqc_strategy_->getIV();
    return pos;
}

std::vector<char> HybridStrategy::serializeSignatureHeader() const {
    std::vector<char> header;
    header.insert(header.end(), {'N', 'K', 'C', 'S'});
    write_u16_le(header, 1);
    header.push_back((char)getStrategyType());
    auto h = pqc_strategy_->serializeSignatureHeader();
    header.insert(header.end(), h.begin() + 7, h.end());
    return header;
}

std::expected<size_t, CryptoError> HybridStrategy::deserializeSignatureHeader(const std::vector<char>& data) {
    return pqc_strategy_->deserializeSignatureHeader(data);
}
