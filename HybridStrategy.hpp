#ifndef HYBRID_STRATEGY_HPP
#define HYBRID_STRATEGY_HPP

#include "ICryptoStrategy.hpp"
#include "PQCStrategy.hpp"
#include "ECCStrategy.hpp"
#include <memory>
#include <vector>
#include <string>
#include <map>
#include <expected>
#include <filesystem>

class HybridStrategy : public ICryptoStrategy {
public:
    HybridStrategy();
    ~HybridStrategy() override;

    // ストラテジーの種類
    StrategyType getStrategyType() const override { return StrategyType::Hybrid; }

    // 鍵生成 (ML-KEM + ECDH)
    std::expected<void, CryptoError> generateEncryptionKeyPair(const std::map<std::string, std::string>& key_paths, std::string& passphrase) override;
    std::expected<void, CryptoError> generateSigningKeyPair(const std::map<std::string, std::string>& key_paths, std::string& passphrase) override;

    // パイプライン・トランスフォーマー
    std::expected<void, CryptoError> prepareEncryption(const std::map<std::string, std::string>& key_paths) override;
    std::expected<void, CryptoError> prepareDecryption(const std::map<std::string, std::string>& key_paths, std::string& passphrase) override;
    std::vector<char> encryptTransform(const std::vector<char>& data) override;
    std::vector<char> decryptTransform(const std::vector<char>& data) override;
    std::expected<void, CryptoError> finalizeEncryption(std::vector<char>& out_final) override;
    std::expected<void, CryptoError> finalizeDecryption(const std::vector<char>& tag) override;

    // 署名・検証 (現在は PQC を使用)
    std::expected<void, CryptoError> prepareSigning(const std::filesystem::path& priv_key_path, std::string& passphrase, const std::string& digest_algo) override;
    std::expected<void, CryptoError> prepareVerification(const std::filesystem::path& pub_key_path, const std::string& digest_algo) override;
    void updateHash(const std::vector<char>& data) override;
    std::expected<std::vector<char>, CryptoError> signHash() override;
    std::expected<bool, CryptoError> verifyHash(const std::vector<char>& signature) override;

    // 署名ヘッダー情報
    std::vector<char> serializeSignatureHeader() const override;
    std::expected<size_t, CryptoError> deserializeSignatureHeader(const std::vector<char>& data) override;

    // ヘッダー情報
    std::map<std::string, std::string> getMetadata() const override;
    size_t getHeaderSize() const override;
    std::vector<char> serializeHeader() const override;
    std::expected<void, CryptoError> deserializeHeader(const std::vector<char>& data) override;
    size_t getTagSize() const override;

private:
    std::unique_ptr<PQCStrategy> pqc_strategy_;
    std::unique_ptr<ECCStrategy> ecc_strategy_;
    
    // ハイブリッド固有の鍵導出用
    std::vector<unsigned char> encryption_key_;
    std::vector<unsigned char> iv_;
    std::vector<unsigned char> salt_;
    std::unique_ptr<EVP_CIPHER_CTX, EVP_CIPHER_CTX_Deleter> cipher_ctx_;
    std::vector<unsigned char> decrypt_buffer_;
};

#endif // HYBRID_STRATEGY_HPP
