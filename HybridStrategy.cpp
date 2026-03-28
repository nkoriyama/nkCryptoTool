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

HybridStrategy::~HybridStrategy() {}

std::expected<void, CryptoError> HybridStrategy::generateEncryptionKeyPair(const std::map<std::string, std::string>& key_paths, std::string& passphrase) {
    std::map<std::string, std::string> pqc_paths = {{"public-key", key_paths.at("public-mlkem-key")}, {"private-key", key_paths.at("private-mlkem-key")}};
    auto res1 = pqc_strategy_->generateEncryptionKeyPair(pqc_paths, passphrase);
    if (!res1) return res1;

    std::map<std::string, std::string> ecc_paths = {{"public-key", key_paths.at("public-ecdh-key")}, {"private-key", key_paths.at("private-ecdh-key")}};
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

    // ハイブリッド暗号化ではPQC側の暗号化コンテキストを主に使用
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

    return {};
}


std::vector<char> HybridStrategy::encryptTransform(const std::vector<char>& data) {
    return pqc_strategy_->encryptTransform(data);
}

std::vector<char> HybridStrategy::decryptTransform(const std::vector<char>& data) {
    return pqc_strategy_->decryptTransform(data);
}

std::expected<void, CryptoError> HybridStrategy::finalizeEncryption(std::vector<char>& out_final) {
    return pqc_strategy_->finalizeEncryption(out_final);
}

std::expected<void, CryptoError> HybridStrategy::finalizeDecryption(const std::vector<char>& tag) {
    return pqc_strategy_->finalizeDecryption(tag);
}

std::expected<void, CryptoError> HybridStrategy::prepareSigning(const std::filesystem::path& p, std::string& pass, const std::string& d) { return pqc_strategy_->prepareSigning(p, pass, d); }
std::expected<void, CryptoError> HybridStrategy::prepareVerification(const std::filesystem::path& p, const std::string& d) { return pqc_strategy_->prepareVerification(p, d); }
void HybridStrategy::updateHash(const std::vector<char>& d) { pqc_strategy_->updateHash(d); }
std::expected<std::vector<char>, CryptoError> HybridStrategy::signHash() { return pqc_strategy_->signHash(); }
std::expected<bool, CryptoError> HybridStrategy::verifyHash(const std::vector<char>& s) { return pqc_strategy_->verifyHash(s); }

size_t HybridStrategy::getHeaderSize() const { 
    // PQCヘッダーサイズは動的なので、ここでは固定値を返さず、常にPQCに依存させる
    return pqc_strategy_->getHeaderSize() + ecc_strategy_->getHeaderSize(); 
}
size_t HybridStrategy::getTagSize() const { return pqc_strategy_->getTagSize(); }

std::vector<char> HybridStrategy::serializeHeader() const {
    auto h1 = pqc_strategy_->serializeHeader();
    auto h2 = ecc_strategy_->serializeHeader();
    h1.insert(h1.end(), h2.begin(), h2.end());
    return h1;
}

std::expected<void, CryptoError> HybridStrategy::deserializeHeader(const std::vector<char>& data) {
    // 1. PQCにまず読ませる。PQCは自分のサイズを知っているので、正確に消費する。
    auto res1 = pqc_strategy_->deserializeHeader(data);
    if (!res1) return res1;

    // 2. PQCが消費した後の残りをECCに読ませる。
    size_t pqc_consumed = pqc_strategy_->getHeaderSize();
    if (data.size() < pqc_consumed) return std::unexpected(CryptoError::FileReadError);
    
    std::vector<char> remaining(data.begin() + pqc_consumed, data.end());
    return ecc_strategy_->deserializeHeader(remaining);
}
