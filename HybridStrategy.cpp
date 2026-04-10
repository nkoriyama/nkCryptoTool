#include "HybridStrategy.hpp"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <stdexcept>
#include <cstring>
#include "nkCryptoToolBase.hpp"

HybridStrategy::HybridStrategy() 
    : pqc_strategy_(std::make_unique<PQCStrategy>()), 
      ecc_strategy_(std::make_unique<ECCStrategy>()),
      cipher_ctx_(EVP_CIPHER_CTX_new()) {}

HybridStrategy::~HybridStrategy() {
    if (!encryption_key_.empty()) OPENSSL_cleanse(encryption_key_.data(), encryption_key_.size());
}

std::expected<void, CryptoError> HybridStrategy::generateEncryptionKeyPair(const std::map<std::string, std::string>& key_paths, std::string& passphrase) {
    auto pqc_paths = key_paths;
    pqc_paths["public-key"] = key_paths.at("public-mlkem-key");
    pqc_paths["private-key"] = key_paths.at("private-mlkem-key");
    auto res1 = pqc_strategy_->generateEncryptionKeyPair(pqc_paths, passphrase);
    if (!res1) return res1;

    auto ecc_paths = key_paths;
    ecc_paths["public-key"] = key_paths.at("public-ecdh-key");
    ecc_paths["private-key"] = key_paths.at("private-ecdh-key");
    return ecc_strategy_->generateEncryptionKeyPair(ecc_paths, passphrase);
}

std::expected<void, CryptoError> HybridStrategy::generateSigningKeyPair(const std::map<std::string, std::string>& key_paths, std::string& passphrase) {
    // 署名はハイブリッドではなくPQC単体を使用
    return pqc_strategy_->generateSigningKeyPair(key_paths, passphrase);
}

std::expected<void, CryptoError> HybridStrategy::prepareEncryption(const std::map<std::string, std::string>& key_paths) {
    std::map<std::string, std::string> pqc_paths = {{"recipient-pubkey", key_paths.at("recipient-mlkem-pubkey")}};
    auto res1 = pqc_strategy_->prepareEncryption(pqc_paths);
    if (!res1) return res1;

    std::map<std::string, std::string> ecc_paths = {{"recipient-pubkey", key_paths.at("recipient-ecdh-pubkey")}};
    auto res2 = ecc_strategy_->prepareEncryption(ecc_paths);
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

std::expected<void, CryptoError> HybridStrategy::prepareDecryption(const std::map<std::string, std::string>& key_paths, std::string& passphrase) {
    // パスフレーズが各ストラテジ内で消去されないよう、コピーして使用する。
    // (nkCryptoToolBase::loadPrivateKey は参照を受け取るが、Hybrid では複数回呼ぶ必要があるため)
    std::string pass_copy = passphrase; 

    std::map<std::string, std::string> pqc_paths = {{"user-privkey", key_paths.at("recipient-mlkem-privkey")}};
    auto res1 = pqc_strategy_->prepareDecryption(pqc_paths, pass_copy);
    if (!res1) return res1;

    std::map<std::string, std::string> ecc_paths = {{"user-privkey", key_paths.at("recipient-ecdh-privkey")}};
    auto res2 = ecc_strategy_->prepareDecryption(ecc_paths, pass_copy);
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
    
    if (!cipher_ctx_ || EVP_DecryptInit_ex(cipher_ctx_.get(), EVP_aes_256_gcm(), nullptr, encryption_key_.data(), iv_.data()) <= 0) {
        return std::unexpected(CryptoError::OpenSSLError);
    }
    
    decrypt_buffer_.clear();
    return {};
}


std::vector<char> HybridStrategy::encryptTransform(const std::vector<char>& data) {
    if (data.empty()) return {};
    std::vector<unsigned char> out(data.size() + 16);
    int out_len = 0;
    if (EVP_EncryptUpdate(cipher_ctx_.get(), out.data(), &out_len, (const unsigned char*)data.data(), (int)data.size()) <= 0) {
        throw std::runtime_error("Encryption update failed");
    }
    out.resize(out_len);
    return std::vector<char>(out.begin(), out.end());
}

std::vector<char> HybridStrategy::decryptTransform(const std::vector<char>& data) {
    if (data.empty()) return {};
    std::vector<unsigned char> out(data.size() + 16);
    int out_len = 0;
    if (EVP_DecryptUpdate(cipher_ctx_.get(), out.data(), &out_len, (const unsigned char*)data.data(), (int)data.size()) <= 0) {
        throw std::runtime_error("Decryption update failed");
    }
    out.resize(out_len);
    return std::vector<char>(out.begin(), out.end());
}

std::expected<void, CryptoError> HybridStrategy::finalizeEncryption(std::vector<char>& out_final) {
    std::vector<unsigned char> final_block(16);
    int final_len = 0;
    if (EVP_EncryptFinal_ex(cipher_ctx_.get(), final_block.data(), &final_len) <= 0) {
        return std::unexpected(CryptoError::OpenSSLError);
    }
    std::vector<unsigned char> tag(16);
    if (EVP_CIPHER_CTX_ctrl(cipher_ctx_.get(), EVP_CTRL_GCM_GET_TAG, 16, tag.data()) <= 0) {
        return std::unexpected(CryptoError::OpenSSLError);
    }
    out_final.assign(final_block.begin(), final_block.begin() + final_len);
    out_final.insert(out_final.end(), tag.begin(), tag.end());
    return {};
}

std::expected<void, CryptoError> HybridStrategy::finalizeDecryption(const std::vector<char>& tag) {
    if (EVP_CIPHER_CTX_ctrl(cipher_ctx_.get(), EVP_CTRL_GCM_SET_TAG, 16, (void*)tag.data()) <= 0) {
        return std::unexpected(CryptoError::OpenSSLError);
    }
    std::vector<unsigned char> final_block(16);
    int final_len = 0;
    if (EVP_DecryptFinal_ex(cipher_ctx_.get(), final_block.data(), &final_len) <= 0) {
        return std::unexpected(CryptoError::SignatureVerificationError);
    }
    return {};
}

std::expected<void, CryptoError> HybridStrategy::prepareSigning(const std::filesystem::path& p, std::string& pass, const std::string& d) { return pqc_strategy_->prepareSigning(p, pass, d); }
std::expected<void, CryptoError> HybridStrategy::prepareVerification(const std::filesystem::path& p, const std::string& d) { return pqc_strategy_->prepareVerification(p, d); }
void HybridStrategy::updateHash(const std::vector<char>& d) { pqc_strategy_->updateHash(d); }
std::expected<std::vector<char>, CryptoError> HybridStrategy::signHash() { return pqc_strategy_->signHash(); }
std::expected<bool, CryptoError> HybridStrategy::verifyHash(const std::vector<char>& s) { return pqc_strategy_->verifyHash(s); }

std::map<std::string, std::string> HybridStrategy::getMetadata(const std::string& magic) const {
    auto m1 = pqc_strategy_->getMetadata(magic);
    auto m2 = ecc_strategy_->getMetadata(magic);
    std::map<std::string, std::string> res;
    res["Strategy"] = "Hybrid (PQC + ECC)";
    for (auto const& [k, v] : m1) { if (k != "Strategy") res["PQC-" + k] = v; }
    for (auto const& [k, v] : m2) { if (k != "Strategy") res["ECC-" + k] = v; }
    return res;
}

size_t HybridStrategy::getHeaderSize() const { 
    return 4 + 2 + 1 + pqc_strategy_->getHeaderSize() + ecc_strategy_->getHeaderSize(); 
}
size_t HybridStrategy::getTagSize() const { return pqc_strategy_->getTagSize(); }

std::vector<char> HybridStrategy::serializeHeader() const {
    std::vector<char> header;
    // Magic "NKCT"
    header.insert(header.end(), {'N', 'K', 'C', 'T'});
    // Version 1
    uint16_t version = 1;
    header.insert(header.end(), (char*)&version, (char*)&version + 2);
    // Strategy Hybrid = 3
    header.push_back((char)getStrategyType());

    auto h1 = pqc_strategy_->serializeHeader();
    auto h2 = ecc_strategy_->serializeHeader();
    header.insert(header.end(), h1.begin(), h1.end());
    header.insert(header.end(), h2.begin(), h2.end());
    return header;
}

std::expected<void, CryptoError> HybridStrategy::deserializeHeader(const std::vector<char>& data) {
    size_t pos = 0;
    if (data.size() < 7) return std::unexpected(CryptoError::FileReadError);
    if (std::string(data.data(), 4) != "NKCT") return std::unexpected(CryptoError::FileReadError);
    pos += 4;
    uint16_t version; memcpy(&version, &data[pos], 2); pos += 2;
    if (version != 1) return std::unexpected(CryptoError::FileReadError);
    uint8_t type = (uint8_t)data[pos++];
    if (type != (uint8_t)getStrategyType()) return std::unexpected(CryptoError::FileReadError);

    std::vector<char> pqc_data(data.begin() + pos, data.end());
    auto res1 = pqc_strategy_->deserializeHeader(pqc_data);
    if (!res1) return res1;
    pos += pqc_strategy_->getHeaderSize();

    if (pos >= data.size()) return std::unexpected(CryptoError::FileReadError);
    std::vector<char> ecc_data(data.begin() + pos, data.end());
    auto res2 = ecc_strategy_->deserializeHeader(ecc_data);
    if (!res2) return res2;
    
    salt_ = pqc_strategy_->getSalt();
    iv_ = pqc_strategy_->getIV();
    return {};
}

std::vector<char> HybridStrategy::serializeSignatureHeader() const {
    std::vector<char> header;
    header.insert(header.end(), {'N', 'K', 'C', 'S'});
    uint16_t version = 1;
    header.insert(header.end(), (char*)&version, (char*)&version + 2);
    header.push_back((char)getStrategyType());
    
    auto h = pqc_strategy_->serializeSignatureHeader();
    header.insert(header.end(), h.begin(), h.end());
    return header;
}

std::expected<size_t, CryptoError> HybridStrategy::deserializeSignatureHeader(const std::vector<char>& data) {
    size_t pos = 0;
    if (data.size() < 7) return std::unexpected(CryptoError::FileReadError);
    if (std::string(data.data(), 4) != "NKCS") return std::unexpected(CryptoError::FileReadError);
    pos += 4;
    uint16_t version; memcpy(&version, data.data() + pos, 2); pos += 2;
    if (version != 1) return std::unexpected(CryptoError::FileReadError);
    uint8_t type = (uint8_t)data[pos++];
    if (type != (uint8_t)getStrategyType()) return std::unexpected(CryptoError::FileReadError);
    
    std::vector<char> pqc_data(data.begin() + pos, data.end());
    auto res = pqc_strategy_->deserializeSignatureHeader(pqc_data);
    if (!res) return std::unexpected(res.error());
    return pos + *res;
}
