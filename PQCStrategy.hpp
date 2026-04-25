#ifndef PQC_STRATEGY_HPP
#define PQC_STRATEGY_HPP

#include "ICryptoStrategy.hpp"
#include "SecureMemory.hpp"
#include "backend/IBackend.hpp"
#include <memory>
#include <vector>
#include <string>
#include <map>
#include <expected>
#include <filesystem>

#include "KeyProvider.hpp"

class PQCStrategy : public ICryptoStrategy {
public:
    PQCStrategy();
    ~PQCStrategy() override;

    // ストラテジーの種類
    StrategyType getStrategyType() const override { return StrategyType::PQC; }

    // 鍵プロバイダーの設定
    void setKeyProvider(std::shared_ptr<nk::IKeyProvider> provider) override {
        key_provider_.set(provider);
    }

    // 鍵生成 ---
    std::expected<void, CryptoError> generateEncryptionKeyPair(const std::map<std::string, std::string>& key_paths, SecureString& passphrase) override;
    std::expected<void, CryptoError> generateSigningKeyPair(const std::map<std::string, std::string>& key_paths, SecureString& passphrase) override;
    std::expected<void, CryptoError> regeneratePublicKey(const std::filesystem::path& priv_path, const std::filesystem::path& pub_path, SecureString& passphrase) override;

    // パイプライン・トランスフォーマー
    std::expected<void, CryptoError> prepareEncryption(const std::map<std::string, std::string>& key_paths) override;
    std::expected<void, CryptoError> prepareDecryption(const std::map<std::string, std::string>& key_paths, SecureString& passphrase) override;
    std::vector<char> encryptTransform(const std::vector<char>& data) override;
    std::vector<char> decryptTransform(const std::vector<char>& data) override;
    std::expected<void, CryptoError> finalizeEncryption(std::vector<char>& out_final) override;
    std::expected<void, CryptoError> finalizeDecryption(const std::vector<char>& tag) override;

    // 署名・検証
    std::expected<void, CryptoError> prepareSigning(const std::filesystem::path& priv_key_path, SecureString& passphrase, const std::string& digest_algo) override;
    std::expected<void, CryptoError> prepareVerification(const std::filesystem::path& pub_key_path, const std::string& digest_algo) override;
    void updateHash(const std::vector<char>& data) override;
    std::expected<std::vector<char>, CryptoError> signHash() override;
    std::expected<bool, CryptoError> verifyHash(const std::vector<char>& signature) override;

    // 署名ヘッダー情報
    std::vector<char> serializeSignatureHeader() const override;
    std::expected<size_t, CryptoError> deserializeSignatureHeader(const std::vector<char>& data) override;

    // ヘッダー情報
    std::map<std::string, std::string> getMetadata(const std::string& magic = "") const override;
    size_t getHeaderSize() const override;
    std::vector<char> serializeHeader() const override;
    std::expected<size_t, CryptoError> deserializeHeader(const std::vector<char>& data) override;
    size_t getTagSize() const override;

    void setKemAlgo(const std::string& algo) { kem_algo_ = algo; }
    void setDsaAlgo(const std::string& algo) { dsa_algo_ = algo; }

    // ハイブリッド連携用
    std::vector<unsigned char> getEncapsulatedKey() const { return kem_ct_; }
    void setEncapsulatedKey(const std::vector<unsigned char>& key) { kem_ct_ = key; }
    std::vector<unsigned char> getSalt() const { return salt_; }
    void setSalt(const std::vector<unsigned char>& s) { salt_ = s; }
    std::vector<unsigned char> getIV() const { return iv_; }
    void setIV(const std::vector<unsigned char>& i) { iv_ = i; }
    std::vector<unsigned char> getSharedSecret() const { return shared_secret_; }

private:
    std::unique_ptr<nk::backend::IAeadBackend> aead_ctx_;
    std::unique_ptr<nk::backend::IHashBackend> hash_ctx_;
    std::vector<uint8_t> sign_key_der_;
    std::vector<uint8_t> verify_key_der_;

    std::string kem_algo_ = "ML-KEM-1024";
    std::string dsa_algo_ = "ML-DSA-87";
    std::string digest_algo_ = "SHA3-512";
    std::vector<unsigned char> encryption_key_;
    std::vector<unsigned char> iv_;
    std::vector<unsigned char> salt_;
    std::vector<unsigned char> kem_ct_;
    std::vector<unsigned char> shared_secret_;
    nk::KeyProvider key_provider_;
};

#endif // PQC_STRATEGY_HPP
